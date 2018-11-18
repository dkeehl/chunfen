use std::net::SocketAddr;
use std::io;
use std::collections::HashMap;
use std::time::Duration;

use tokio_tcp::{TcpListener, TcpStream};
use tokio_timer::Timeout;
use futures::{Sink, Stream, Future, Poll, Async, AsyncSink, StartSend};
use futures::sync::mpsc::{self, Sender};
use bytes::Bytes;

use chunfen_sec::ServerSession;

use crate::utils::{*, Id, DomainName, Port}; 
use crate::protocol::{ServerMsg, ClientMsg, ALIVE_TIMEOUT_TIME_MS};
use crate::framed::Framed;
use crate::tunnel_port::{TunnelPort, FromPort, ToPort};
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
        let client: Framed<ClientMsg, ServerMsg, Tls> = Framed::new(tls);
        let ports = PortMap::new(sender);
        let connections = receiver.map_err(|_| unreachable!());

        let (sink, stream) = client.split();
        let read_client = Timeout::new(stream, timeout)
            .map_err(|e| tunnel_broken(format!("{}", e)))
            .map(t_to_p)
            .forward(ports);
        let write_client = connections.map(p_to_t).forward(sink);
        
        read_client.join(write_client).map(|_| {
            info!("finished")
        }).map_err(|e| {
            info!("error: {}", e)
        })
    })
}

fn p_to_t(msg: FromPort<ServerMsg>) -> ServerMsg {
    let ret = match msg {
        FromPort::Data(id, buf) => ServerMsg::Data(id, buf),
        FromPort::ShutdownWrite(id) => ServerMsg::ShutdownWrite(id),
        // A port send Close only when it is dropped.
        FromPort::Close(id) => ServerMsg::ClosePort(id),
        FromPort::Payload(x @ ServerMsg::ConnectOK(..)) |
        FromPort::Payload(x @ ServerMsg::HeartBeatRsp) => x,
        _ => unreachable!(),
    };
    trace!("sending {}", ret);
    ret
}

fn t_to_p(msg: ClientMsg) -> MapCmd {
    use self::ClientMsg::*;
    trace!("got {}", msg);
    match msg {
        HeartBeat               => MapCmd::HeartBeat,
        OpenPort(id)            => MapCmd::Open(id),
        ClosePort(id)           => MapCmd::Close(id),
        Connect(id, buf)        => MapCmd::Connect(id, buf),
        ConnectDN(id, dn, port) => MapCmd::ConnectDN(id, dn, port),
        Data(id, buf)           => MapCmd::Forward { id, msg: ToPort::Data(buf) },
        ShutdownWrite(id)       => MapCmd::Forward { id, msg: ToPort::ShutdownWrite },
    }
}

struct PortMap {
    // a port is created after it connected.
    ports: HashMap<Id, Option<Sender<ToPort>>>,
    // For making new ports.
    sender: Sender<FromPort<ServerMsg>>,
}

impl PortMap {
    fn new(sender: Sender<FromPort<ServerMsg>>) -> PortMap {
        PortMap {
            ports: HashMap::new(),
            sender,
        }
    }
    
    fn add(&mut self, id: Id) {
        let _ = self.ports.insert(id, None);
    }

    fn remove(&mut self, id: Id) {
        let _ = self.ports.remove(&id);
    }

    fn connect(&mut self, id: Id, addr: SocketAddr)  {
        let (sender, port) = TunnelPort::new(id, self.sender.clone());
        let _ = self.ports.insert(id, Some(sender));

        // Spawn a new task to connect, to avoid the connect action blocking the
        // main thread.
        tokio::spawn(port.connect_and_proxy(id, &addr));
    }

    fn connect_dn(&mut self, id: Id, dn: DomainName, port: Port) {
        if let Some(addr) = parse_domain_name_with_port(dn, port) {
            self.connect(id, addr);
        } else {
            let send = self.sender.clone()
                .send(FromPort::Payload(connection_fail(id)));
            tokio::spawn(drop_res!(send));
        }
    }

    fn send_to_port(&mut self, id: Id, msg: ToPort)
        -> StartSend<MapCmd, io::Error>
    {
        if let Some(Some(sender)) = self.ports.get_mut(&id) {
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

    fn port0_send(&mut self, msg: ServerMsg) {
        // FIXME; Messages may lost.
        let _ = self.sender.try_send(FromPort::Payload(msg));
    }
}

fn connection_fail(id: Id) -> ServerMsg {
    ServerMsg::ConnectOK(id, Bytes::new())
}

enum MapCmd {
    HeartBeat,
    Open(Id),
    Close(Id),
    Connect(Id, Bytes),
    ConnectDN(Id, Bytes, Port),
    Forward { id: Id, msg: ToPort }
}

impl Sink for PortMap {
    type SinkItem = MapCmd;
    type SinkError = io::Error;

    fn start_send(&mut self, cmd: MapCmd) -> StartSend<MapCmd, io::Error> {
        use self::MapCmd::*;
        match cmd {
            HeartBeat => self.port0_send(ServerMsg::HeartBeatRsp),
            Open(id) => self.add(id),
            Close(id) => self.remove(id),
            Connect(id, buf) => {
                if let Some(addr) = parse_domain_name(buf) {
                    self.connect(id, addr)
                } else {
                    self.port0_send(connection_fail(id));
                }
            },
            ConnectDN(id, dn, port) => self.connect_dn(id, dn, port),
            Forward { id, msg } => return self.send_to_port(id, msg),
        }
        Ok(AsyncSink::Ready)
   }

    fn poll_complete(&mut self) -> Poll<(), io::Error> { Ok(().into()) }
}
