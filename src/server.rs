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
    not_processed: Option<ClientMsg>,
    closing: bool,
    client_ready: bool,
    ports_ready: bool,
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
                client_ready: false,
                ports_ready: false,
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

        self.client_ready = true;
        self.ports_ready = true;

        while self.client_ready || self.ports_ready {
            if self.ports_ready {
                match self.connections.poll().unwrap() {
                    Async::Ready(Some(msg)) => self.process_port_msg(msg),
                    // We always have a sender in the tunnel.
                    Async::Ready(None) => unreachable!(),
                    Async::NotReady => self.ports_ready = false,
                }
            }
            if self.client_ready {
                if let Some(msg) = self.not_processed.take() {
                    if !self.process_client_msg(msg).is_ready() {
                        self.client_ready = false;
                        let _ = self.client.poll_flush()?;
                        continue
                    }
                }
                match self.client.poll()? {
                    Async::Ready(Some(c_msg)) => {
                        self.alive_time = get_time();
                        if !self.process_client_msg(c_msg).is_ready() {
                            // A port is blocked
                            self.client_ready = false
                        }
                    },
                    // Client EOF
                    Async::Ready(None) => return self.close(),
                    Async::NotReady => self.client_ready = false,
                }
            }
            let _ = self.client.poll_flush()?;
        }
        Ok(Async::NotReady)
    }
}

impl Tunnel {
    fn process_client_msg(&mut self, c_msg: ClientMsg) -> Async<()> {
        debug_assert!(self.not_processed.is_none());
        if let Err(msg) = self.process_client_msg_prim(c_msg) {
            self.not_processed = Some(msg);
            Async::NotReady
        } else {
            ().into()
        }
    }

    fn process_client_msg_prim(&mut self, c_msg: ClientMsg) -> Result<(), ClientMsg> {
        match c_msg {
            ClientMsg::HeartBeat => {
                //println!("sending: heartbeat");
                self.client.buffer_msg(ServerMsg::HeartBeatRsp);
            },
            ClientMsg::OpenPort(id) => self.ports.add(id),
            ClientMsg::Connect(id, buf) => {
                if let Some(addr) = parse_domain_name(buf) {
                    self.ports.connect(id, addr)
                } else {
                    //println!("sending: port {} connections fail", id);
                    self.client.buffer_msg(connection_fail(id));
                }
            },
            ClientMsg::ConnectDN(id, dn, port) => {
                self.ports.connect_dn(id, dn, port);
            },
            ClientMsg::Data(id, buf) => {
                return self.ports.send_data(id, buf)
            },
            ClientMsg::ShutdownWrite(id) => {
                return self.ports.shutdown_write(id)
            },
            ClientMsg::ClosePort(id) => self.ports.remove(id),
        }
        Ok(())
    }

    fn process_port_msg(&mut self, msg: FromPort<ServerMsg>) {
        let s_msg = match msg {
            FromPort::Data(id, buf) => ServerMsg::Data(id, buf),
            FromPort::ShutdownWrite(id) => ServerMsg::ShutdownWrite(id),
            FromPort::Close(id) => {
                self.ports.remove(id);
                ServerMsg::ClosePort(id)
            },
            FromPort::Payload(x @ ServerMsg::ConnectOK(..)) => x,
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
                    let fut = port.send_raw(ServerMsg::ConnectOK(id, buf)).and_then(|_| {
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

    fn send_to_port(&mut self, id: Id, msg: ToPort) -> Result<(), ToPort> {
        if let Some(Some(sender)) = self.ports.get_mut(&id) {
            match sender.poll_ready() {
                Ok(Async::Ready(_)) => Ok(sender.try_send(msg).unwrap()),
                Ok(Async::NotReady) => Err(msg),
                Err(_) => { self.remove(id); Ok(()) }
            }
        } else {
            debug!("sending to an nonexist port {}", id);
            Ok(())
        }
    }

    fn send_data(&mut self, id: Id, data: Bytes) -> Result<(), ClientMsg> {
         self.send_to_port(id, ToPort::Data(data)).map_err(|e| {
             match e {
                 ToPort::Data(data) => ClientMsg::Data(id, data),
                 _ => unreachable!()
             }
         })
    }

    fn shutdown_write(&mut self, id: Id) -> Result<(), ClientMsg> {
         self.send_to_port(id, ToPort::ShutdownWrite).map_err(|_| {
             ClientMsg::ShutdownWrite(id)
         })
    }
}
