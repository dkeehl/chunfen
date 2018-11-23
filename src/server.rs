use std::net::SocketAddr;
use std::io;
use std::collections::HashMap;
use std::time::Duration;

use tokio_tcp::{TcpListener, TcpStream};
use tokio_timer::Timeout;
use futures::{Sink, Stream, Future, Poll, Async, AsyncSink, StartSend};
use futures::sync::mpsc::{self, Sender};

use chunfen_sec::ServerSession;
use chunfen_socks::connector::SocksAddr;

use crate::utils::{*, Id}; 
use crate::protocol::{Msg, ALIVE_TIMEOUT_TIME_MS};
use crate::framed::Framed;
use crate::tunnel_port::{TunnelPort, ToPort};
use crate::tls;
use crate::checked_key::CheckedKey;

pub struct Server;

impl Server {
    pub fn bind(addr: &SocketAddr, key: CheckedKey) {
        let listening = TcpListener::bind(addr).unwrap();
        let server = listening.incoming().map_err(|e| {
            error!("accepting error {}", e)
        }).for_each(move |stream| {
            tokio::spawn(new_tunnel(stream, key.clone()));
            Ok(())
        });

        tokio::run(server)
    }
}

type Tls = tls::Tls<ServerSession, TcpStream>;

fn new_tunnel(stream: TcpStream, key: CheckedKey) -> impl Future<Item=(), Error=()> {
    info!("Request from {}, creat new tunnel.", stream.peer_addr().unwrap());

    let session = ServerSession::new(key.into());
    let (sender, receiver) = mpsc::channel(1000);

    tls::connect(session, stream).map_err(|e| {
        warn!("tls connect error: {}", e)
    }).and_then(|tls| {
        let timeout = Duration::from_millis(ALIVE_TIMEOUT_TIME_MS);
        let client: Framed<Msg, Msg, Tls> = Framed::new(tls);
        let ports = PortMap::new(sender);
        let connections = receiver.map_err(|_| unreachable!());

        let (sink, stream) = client.split();
        let read_client = Timeout::new(stream, timeout)
            .map_err(|e| tunnel_broken(format!("{}", e)))
            .map(to_cmd)
            .forward(ports);
        let write_client = connections.forward(sink);
        
        read_client.join(write_client).map(|_| {
            info!("finished")
        }).map_err(|e| {
            info!("error: {}", e)
        })
    })
}

fn to_cmd(msg: Msg) -> MapCmd {
    use self::Msg::*;
    trace!("got {}", msg);
    match msg {
        HeartBeat         => MapCmd::HeartBeat,
        ClosePort(id)     => MapCmd::Close(id),
        Connect(id, addr) => MapCmd::Connect(id, addr),
        Data(id, buf)     => MapCmd::Forward { id, msg: ToPort::Data(buf) },
        ShutdownWrite(id) => MapCmd::Forward { id, msg: ToPort::ShutdownWrite },
        _                 => unreachable!(),
    }
}

struct PortMap {
    // a port is created after it connected.
    ports: HashMap<Id, Sender<ToPort>>,
    // For making new ports.
    sender: Sender<Msg>,
}

impl PortMap {
    fn new(sender: Sender<Msg>) -> PortMap {
        PortMap {
            ports: HashMap::new(),
            sender,
        }
    }
    
    fn remove(&mut self, id: Id) {
        let _ = self.ports.remove(&id);
    }

    fn connect(&mut self, id: Id, addr: SocksAddr)  {
        let (sender, port) = TunnelPort::new(id, self.sender.clone());
        if self.ports.insert(id, sender).is_some() {
            warn!("overiding an existing port");
        }
        // Spawn a new task to connect, to avoid the connect action blocking the
        // main thread.
        tokio::spawn(port.connect_and_proxy(addr));
    }

    fn send_to_port(&mut self, id: Id, msg: ToPort)
        -> StartSend<MapCmd, io::Error>
    {
        if let Some(sender) = self.ports.get_mut(&id) {
            match sender.poll_ready() {
                Ok(Async::Ready(_)) => sender.try_send(msg).unwrap(),
                Ok(Async::NotReady) => 
                    return Ok(AsyncSink::NotReady(MapCmd::Forward { id, msg })),
                Err(_) => self.remove(id),
            }
        } else {
            debug!("sending to an nonexist port {}", id);
        }
        Ok(AsyncSink::Ready)
    }

    fn port0_send(&mut self, msg: Msg) {
        // FIXME; Messages may lost.
        let _ = self.sender.try_send(msg);
    }
}

enum MapCmd {
    HeartBeat,
    Close(Id),
    Connect(Id, SocksAddr),
    Forward { id: Id, msg: ToPort }
}

impl Sink for PortMap {
    type SinkItem = MapCmd;
    type SinkError = io::Error;

    fn start_send(&mut self, cmd: MapCmd) -> StartSend<MapCmd, io::Error> {
        use self::MapCmd::*;
        match cmd {
            HeartBeat => self.port0_send(Msg::HeartBeatRsp),
            Close(id) => self.remove(id),
            Connect(id, addr) => self.connect(id, addr),
            Forward { id, msg } => return self.send_to_port(id, msg),
        }
        Ok(AsyncSink::Ready)
   }

    fn poll_complete(&mut self) -> Poll<(), io::Error> { Ok(().into()) }
}
