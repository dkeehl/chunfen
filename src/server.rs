use std::net::SocketAddr;
use std::io;
use std::collections::HashMap;

use time::{Timespec, get_time};
use tokio_tcp::{TcpListener, TcpStream};
use futures::future;
use futures::{Sink, Stream, Future, Poll, Async};
use futures::sync::mpsc::{self, Receiver, Sender};
use bytes::Bytes;

use chunfen_sec::server::ServerSession;
use chunfen_socks::pipe;

use crate::utils::{*, Id, DomainName, Port}; 
use crate::protocol::{ServerMsg, ClientMsg, ALIVE_TIMEOUT_TIME_MS};
use crate::framed::Framed;
use crate::tunnel_port::{TunnelPort, FromPort, ToPort};
use crate::tls;

pub struct Server;

impl Server {
    pub fn bind(addr: &SocketAddr, key: Vec<u8>) {
        let listening = TcpListener::bind(addr).unwrap();
        let server = listening.incoming().for_each(move |stream| {
            tokio::spawn(Tunnel::new(stream, &key));
            Ok(())
        }).map_err(|_| ());
        tokio::run(server)
    }
}

type Tls = tls::Tls<ServerSession, TcpStream>;

struct Tunnel {
    client: Framed<ClientMsg, ServerMsg, Tls>,
    alive_time: Timespec,
    ports: PortMap,
    connections: Receiver<FromPort<ServerMsg>>,
    not_processed: Option<(Id, ToPort)>,
    closing: bool,
}

impl Tunnel {
    fn new(stream: TcpStream, key: &[u8]) -> impl Future<Item=(), Error=()> {
        println!("Request from {}, creat new tunnel.",
                 stream.peer_addr().unwrap());

        let session = ServerSession::new(key);
        let (sender, receiver) = mpsc::channel(1000);

        tls::connect(session, stream).and_then(|stream| {
            Tunnel {
                client: Framed::new(stream),
                alive_time: get_time(),
                ports: PortMap::new(sender),
                connections: receiver,
                not_processed: None,
                closing: false,
            }
        }).then(|res| {
            match res {
                Ok(_) => println!("peer at eof, quit"),
                Err(e) => println!("an error occured: {}, tunnel broken", e),
            }
            future::ok::<(), ()>(())
        })
    }
}

impl Future for Tunnel {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(), io::Error> {
        // Do we really need to flush? Or just return an error?
        if self.closing {
            return self.client.poll_flush()
        }

        let dur = get_time() - self.alive_time;
        if dur.num_milliseconds() > ALIVE_TIMEOUT_TIME_MS {
            println!("Client timeout.");
            return self.close()
        }

        loop {
            match self.connections.poll().unwrap() {
                Async::Ready(Some(msg)) => self.process_port_msg(msg),
                // We always have a sender in the tunnel.
                Async::Ready(None) => unreachable!(),
                Async::NotReady => break,
            }
        }
        let _ = self.client.poll_flush()?;
        loop {
            if let Some(msg) = self.not_processed.take() {
                if !self.process_client_msg(msg).is_ready() { break }
            }

            match self.client.poll()? {
                Async::Ready(Some(c_msg)) => {
                    self.alive_time = get_time();
                    if !self.process_client_msg(toport(c_msg)).is_ready() {
                        // A port is blocked
                        break
                    }
                },
                // Client EOF
                Async::Ready(None) => return self.close(),
                Async::NotReady => break,
            }
        }
        let _ = self.client.poll_flush()?;
        Ok(Async::NotReady)
    }
}

impl Tunnel {
    fn process_client_msg(&mut self, msg: (Id, ToPort)) -> Async<()> {
        debug_assert!(self.not_processed.is_none());
        if let Err(msg) = self.ports.process(msg) {
            self.not_processed = Some(msg);
            Async::NotReady
        } else {
            ().into()
        }
    }

    fn process_port_msg(&mut self, msg: FromPort<ServerMsg>) {
        let s_msg = match msg {
            FromPort::Data(id, buf) => ServerMsg::Data(id, buf),
            FromPort::ShutdownWrite(id) => ServerMsg::ShutdownWrite(id),
            // A port send Close only when it is dropped.
            FromPort::Close(id) => ServerMsg::ClosePort(id),
            FromPort::Payload(x @ ServerMsg::ConnectOK(..)) |
            FromPort::Payload(x @ ServerMsg::HeartBeatRsp) => x,
            _ => unreachable!(),
        };
        //println!("sending: {}", s_msg);
        self.client.buffer_msg(s_msg)
    }

    fn close(&mut self) -> Poll<(), io::Error> {
        // TODO: close all ports
        self.closing = true;
        self.client.poll_flush()
    }
}

fn toport(msg: ClientMsg) -> (Id, ToPort) {
    use self::ClientMsg::*;
    match msg {
        HeartBeat               => (0,  ToPort::HeartBeat),
        OpenPort(id)            => (id, ToPort::Open),
        Connect(id, buf)        => (id, ToPort::Connect(buf)),
        ConnectDN(id, dn, port) => (id, ToPort::ConnectDN(dn, port)),
        Data(id, buf)           => (id, ToPort::Data(buf)),
        ShutdownWrite(id)       => (id, ToPort::ShutdownWrite),
        ClosePort(id)           => (id, ToPort::Close),
    }
}

fn connection_fail(id: Id) -> ServerMsg {
    ServerMsg::ConnectOK(id, Bytes::new())
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
        let connect = TcpStream::connect(&addr);
        let proxing = connect.then(move |res| {
            match res {
                Ok(stream) => {
                    let bind_addr = format!("{}", stream.local_addr().unwrap());
                    //println!("{}", bind_addr);
                    let buf = Bytes::from(bind_addr.as_bytes());
                    let fut = port.send_raw(ServerMsg::ConnectOK(id, buf)).map(|_| {
                        pipe(stream, port)
                    });
                    Box::new(drop_res!(fut)) as Box<Future<Item=(), Error=()> + Send>
                },
                Err(_) => {
                    let fut = port.send_raw(connection_fail(id));
                    Box::new(drop_res!(fut)) as Box<Future<Item=(), Error=()> + Send>
                },
            }
        });
        //println!("connecting port {}", id);
        tokio::spawn(proxing);
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

    fn send_to_port(&mut self, id: Id, msg: ToPort) -> Result<(), (Id, ToPort)> {
        if let Some(Some(sender)) = self.ports.get_mut(&id) {
            match sender.poll_ready() {
                Ok(Async::Ready(_)) => Ok(sender.try_send(msg).unwrap()),
                Ok(Async::NotReady) => Err((id, msg)),
                Err(_) => { self.remove(id); Ok(()) }
            }
        } else {
            debug!("sending to an nonexist port {}", id);
            Ok(())
        }
    }

    fn send_data(&mut self, id: Id, data: Bytes) -> Result<(), (Id, ToPort)> {
         self.send_to_port(id, ToPort::Data(data))
    }

    fn shutdown_write(&mut self, id: Id) -> Result<(), (Id, ToPort)> {
         self.send_to_port(id, ToPort::ShutdownWrite)
    }

    fn port0_send(&mut self, msg: ServerMsg) {
        // FIXME; Messages may lost.
        let _ = self.sender.try_send(FromPort::Payload(msg));
    }

    fn process(&mut self, msg: (Id, ToPort)) -> Result<(), (Id, ToPort)> {
        use self::ToPort::*;
        match msg {
            (0, HeartBeat) => self.port0_send(ServerMsg::HeartBeatRsp),
            (id, Open) => self.add(id),
            (id, Connect(buf)) => {
                if let Some(addr) = parse_domain_name(buf) {
                    self.connect(id, addr)
                } else {
                    self.port0_send(connection_fail(id));
                }
            },
            (id, ConnectDN(dn, port)) => self.connect_dn(id, dn, port),
            (id, Data(buf)) => return self.send_data(id, buf),
            (id, ShutdownWrite) => return self.shutdown_write(id),
            (id, Close) => self.remove(id),

            (_, ConnectOK(_)) | (_, HeartBeat) => unreachable!(),
        }
        Ok(())
    }
}
