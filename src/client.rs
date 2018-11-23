use std::net::SocketAddr;
use std::io;
use std::collections::HashMap;
use std::time::{Instant, Duration};

use tokio_tcp::{TcpStream, TcpListener};
use tokio_timer::{Timeout, Delay};
use futures::{Sink, Stream, Future, Poll, Async, AsyncSink, StartSend};
use futures::sync::mpsc::{self, Sender};

use chunfen_sec::ClientSession;
use chunfen_socks::SocksConnection;

use crate::framed::Framed;
use crate::utils::{Id, tunnel_broken};
use crate::tunnel_port::{ToPort, TunnelPort};
use crate::protocol::{Msg, HEARTBEAT_INTERVAL_MS, ALIVE_TIMEOUT_TIME_MS};
use crate::tls;
use crate::checked_key::CheckedKey;

pub struct Client; 

impl Client {
    pub fn new(listen_addr: &SocketAddr, server_addr: &SocketAddr, key: CheckedKey) {
        let listening = TcpListener::bind(listen_addr).unwrap();
        let client = run_tunnel(server_addr, key).and_then(|ports| {
            listening.incoming().zip(ports).for_each(|(stream, port)| {
                let proxy = SocksConnection::serve(stream, port);
                tokio::spawn(drop_res!(proxy));
                Ok(())
            })
        }).map_err(|e| {
            error!("{}", e)
        });
        
        tokio::run(client)
    }
}

type Tls = tls::Tls<ClientSession, TcpStream>;

fn run_tunnel(server: &SocketAddr, key: CheckedKey)
    -> impl Future<Item=Ports, Error=io::Error> + Send
{
    TcpStream::connect(server).and_then(|stream| {
        let session = ClientSession::new(key.into());
        tls::connect(session, stream)
    }).map(|tls| {
        // The sender will send messages from ports.
        let (sender, receiver) = mpsc::channel(1000);
        // This sender sends new port notifies to the port map.
        let (new_port_notifier, new_ports) = mpsc::channel(10);

        let timeout = Duration::from_millis(ALIVE_TIMEOUT_TIME_MS);
        let server: Framed<Msg, Msg, Tls> = Framed::new(tls);
        let heartbeats = HeartBeats::new(HEARTBEAT_INTERVAL_MS as u64);
        let ports = PortMap::new();

        let (sink, stream) = server.split();
        let receiver = receiver.map_err(|_| unreachable!());
        let new_ports = new_ports.map_err(|_| unreachable!());

        let read_server = Timeout::new(stream, timeout)
            .map_err(|e| tunnel_broken(format!("{}", e)))
            .map(to_cmd)
            .select(new_ports)
            .forward(ports);
        let write_server = receiver.select(heartbeats).forward(sink);

        tokio::spawn(read_server.join(write_server).map(|_| {
            info!("finished")
        }).map_err(|e| {
            error!("server error: {}", e)
        }));

        Ports { sender, new_port_notifier, count: 1 }
    })
}

fn to_cmd(msg: Msg) -> MapCmd {
    use self::MapCmd::*;
    trace!("got {}", msg);
    match msg {
        Msg::HeartBeatRsp => Skip,
        Msg::ClosePort(id) => Close(id),
        Msg::Success(id, addr) => Forward { id, msg: ToPort::Connected(addr) },
        Msg::Fail(id) => Forward { id, msg: ToPort::Failed },
        Msg::Data(id, buf) => Forward { id, msg: ToPort::Data(buf) },
        Msg::ShutdownWrite(id) => Forward { id, msg: ToPort::ShutdownWrite },
        _ => unreachable!(),
    }
}

struct Ports {
    // This sender rarely sends messages itself, but is used to be cloned to
    // produce tunnel ports.
    sender: Sender<Msg>,

    // This sender sends new port notifies to the port map.
    // It only sends ToPort::PortOpen.
    new_port_notifier: Sender<MapCmd>,
    count: u32,
}

impl Stream for Ports {
    type Item = TunnelPort;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, io::Error> {
        let id = self.count;
        //trace!("new port {}!", id);
        // The sender is used to send messages to the port,
        // and will be send to the port map.
        let (sender, port) = TunnelPort::new(id, self.sender.clone());

        // Use poll_ready to determine if the receiver has been dropped.
        match self.new_port_notifier.poll_ready() {
            Ok(Async::Ready(_)) => {
                self.new_port_notifier.try_send(MapCmd::Open(id, sender)).unwrap();
                self.count += 1;
                Ok(Async::Ready(Some(port)))
            },
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(_) => Ok(Async::Ready(None)),
        }
   }
}

enum MapCmd {
    Skip,
    Open(Id, Sender<ToPort>),
    Close(Id),
    Forward { id: Id, msg: ToPort }
}

struct PortMap {
    ports: HashMap<Id, Sender<ToPort>>,
}

impl PortMap {
    fn new() -> PortMap {
        PortMap { ports: HashMap::new() }
    }

    fn insert(&mut self, id: Id, sender: Sender<ToPort>) {
        let _ = self.ports.insert(id, sender);
    }

    fn remove(&mut self, id: Id) {
        let _ = self.ports.remove(&id);
    }
}

impl Sink for PortMap {
    type SinkItem = MapCmd;
    type SinkError = io::Error;

    fn start_send(&mut self, cmd: MapCmd) -> StartSend<MapCmd, io::Error> {
        use self::MapCmd::*;

        match cmd {
            Skip => {},
            Open(id, sender) => self.insert(id, sender),
            // A port get a message only when it is at read, write or connect
            // operation, at which time it knows if all senders are dropped.
            // But it has only one sender, the one in this map.
            // So it's safe to just remove the sender without sending a Close
            // message.
            Close(id) => self.remove(id),
            Forward { id, msg } => {
                if let Some(sender) = self.ports.get_mut(&id) {
                    match sender.poll_ready() {
                        Ok(Async::Ready(_)) => sender.try_send(msg).unwrap(),
                        Ok(Async::NotReady) =>
                            return Ok(AsyncSink::NotReady(Forward { id, msg })),
                        Err(_) => self.remove(id),
                    }
                } else {
                    debug!("sending to an nonexist port {}", id);
                }
            },
        }
        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Poll<(), io::Error> { Ok(().into()) }
}

pub struct HeartBeats {
    timeout: Delay,
    duration: Duration,
}

impl HeartBeats {
    pub fn new(t: u64) -> HeartBeats {
        let t = Duration::from_millis(t);
        let timeout = Delay::new(Instant::now() + t);
        HeartBeats{ timeout, duration: t }
    }
}

impl Stream for HeartBeats {
    type Item = Msg;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
        match self.timeout.poll() {
            Ok(Async::Ready(_)) => {
                let next = Instant::now() + self.duration;
                self.timeout.reset(next);
                Ok(Some(Msg::HeartBeat).into())
            },
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(_) => Ok(None.into()),
        }
    }
}
