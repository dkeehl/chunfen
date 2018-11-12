use std::net::SocketAddr;
use std::io;
use std::collections::HashMap;

use time::{Timespec, get_time};
use tokio_tcp::{TcpStream, TcpListener};
use futures::{Stream, Future, Poll, Async};
use futures::sync::mpsc::{self, Sender, Receiver};

use chunfen_sec::client::ClientSession;
use chunfen_socks::SocksConnection;

use crate::framed::Framed;
use crate::utils::{Timer, Id};
use crate::tunnel_port::{ToPort, FromPort, TunnelPort};
use crate::protocol::{ServerMsg, ClientMsg, HEARTBEAT_INTERVAL_MS, ALIVE_TIMEOUT_TIME_MS};
use crate::tls;

pub struct Client; 

impl Client {
    pub fn new(listen_addr: &str, server_addr: &str, key: Vec<u8>) {
        let listen_addr = listen_addr.parse().unwrap();
        let server_addr = server_addr.parse().unwrap();
        let listening = TcpListener::bind(&listen_addr).unwrap();
        let client = Tunnel::new(&server_addr, key).and_then(|tunnel| {
            listening.incoming().zip(tunnel).for_each(|(stream, port)| {
                let proxy = SocksConnection::serve(stream, port);
                tokio::spawn(drop_res!(proxy));
                Ok(())
            })
        }).map_err(|e| {
            eprintln!("{}", e)
        });
        
        tokio::run(client)
    }
}

type Tls = tls::Tls<ClientSession, TcpStream>;

struct Tunnel {
    // This sender rarely sends messages itself, but is used to be cloned to
    // produce tunnel ports.
    // If this sender get an error when sending messages, we know that the
    // tunnel is broken.
    sender: Sender<FromPort<ClientMsg>>,
    count: u32,
}

impl Tunnel {
    fn new(server: &SocketAddr, key: Vec<u8>)
        -> impl Future<Item=Tunnel, Error=io::Error> + Send
    {
        let (sender, receiver) = mpsc::channel(1000);
        TcpStream::connect(server).map(|stream| {
            tokio::spawn(run_tunnel(stream, key, receiver));
            Tunnel { sender, count: 1 }
        })
    }

    fn new_port(&mut self) -> Poll<TunnelPort<ClientMsg>, io::Error> {
        let id = self.count;
        trace!("new port {}!", id);
        // Open a channel between the port and the tunnel. The sender is send 
        // to the tunnel, for sending data later to the corresponing port. 
        let (sender, port) = TunnelPort::new(id, self.sender.clone());

        // Use poll_ready to determine if the receiver has been dropped.
        match self.sender.poll_ready() {
            Ok(Async::Ready(_)) => {
                self.sender.try_send(FromPort::NewPort(id, sender)).unwrap();
                self.count += 1;
                Ok(Async::Ready(port))
            },
            Ok(Async::NotReady) => Ok(Async::NotReady),
            Err(_) => Err(tunnel_broken()),
        }
    }
}

impl Stream for Tunnel {
    type Item = TunnelPort<ClientMsg>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<Self::Item>, io::Error> {
        let port = try_ready!(self.new_port());
        Ok(Async::Ready(Some(port)))
    }
}

fn run_tunnel(stream: TcpStream,
              key: Vec<u8>,
              receiver: Receiver<FromPort<ClientMsg>>)
    -> impl Future<Item=(), Error=()> + Send
{
    let session = ClientSession::new(&key);

    tls::connect(session, stream).and_then(|tls| {
        RunTunnel {
            server: Framed::new(tls),
            timer: Timer::new(HEARTBEAT_INTERVAL_MS as u64),
            client: receiver,
            ports: PortMap::new(),
            alive_time: get_time(),
            not_processed: None,
        }
    }).map_err(|e| println!("{}", e))
}

struct RunTunnel {
    server: Framed<ServerMsg, ClientMsg, Tls>,
    timer: Timer,
    client: Receiver<FromPort<ClientMsg>>,
    ports: PortMap,
    alive_time: Timespec,
    not_processed: Option<(Id, ToPort)>,
}

impl RunTunnel {
    fn process_server_msg(&mut self, s_msg: (Id, ToPort)) -> Async<()> {
        debug_assert!(self.not_processed.is_none());
        if let Err(msg) = self.ports.process(s_msg) {
            self.not_processed = Some(msg);
            Async::NotReady
        } else {
            ().into()
        }
    }


    fn process_port_msg(&mut self, msg: FromPort<ClientMsg>) {
        let c_msg = match msg {
            FromPort::NewPort(id, sender) => {
                self.ports.insert(id, sender);
                ClientMsg::OpenPort(id)
            },
            FromPort::Data(id, buf) => ClientMsg::Data(id, buf),
            FromPort::ShutdownWrite(id) => ClientMsg::ShutdownWrite(id),
            FromPort::Close(id) => {
                self.ports.remove(id);
                ClientMsg::ClosePort(id)
            },
            FromPort::Payload(m @ ClientMsg::Connect(..)) => m, 
            FromPort::Payload(m @ ClientMsg::Data(..)) => m,
            FromPort::Payload(_) => unreachable!(),
        };
        trace!("sending {}", c_msg);
        self.server.buffer_msg(c_msg);
    }
}

impl Future for RunTunnel {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(), io::Error> {
        if let Async::Ready(_) = self.timer.poll().unwrap() {
            let dur = get_time() - self.alive_time;
            if dur.num_milliseconds() > ALIVE_TIMEOUT_TIME_MS {
                // Server timeout.
                return Err(tunnel_broken())
            } else {
                trace!("sending hearbeat");
                self.server.buffer_msg(ClientMsg::HeartBeat);
            }
        }

        // Timer is not ready.
        loop {
            match self.client.poll().unwrap() {
                Async::Ready(Some(msg)) => self.process_port_msg(msg),
                // At least one sender should in the socks part.
                // If `None` is returned, the socks part should be down, and
                // no ports left. No further work to do.
                Async::Ready(None) => {
                    let _ = self.server.poll_flush()?;
                    return Ok(().into())
                },
                Async::NotReady => break,
            }
        }
        let _ = self.server.poll_flush()?;
        //let mut count: u16 = 0;
        //println!("looping...");
        loop {
            if let Some(msg) = self.not_processed.take() {
                if !self.process_server_msg(msg).is_ready() { break }
            }
            match self.server.poll()? {
                Async::Ready(Some(s_msg)) => {
                    //count += 1;
                    //println!("get server message {}", s_msg);
                    self.alive_time = get_time();
                    if !self.process_server_msg(toport(s_msg)).is_ready() {
                        break
                    }
                },
                // Disconnected from server.
                Async::Ready(None) => {
                    //println!("looped {} messages", count);
                    return Err(tunnel_broken())
                },
                Async::NotReady => {
                    break
                },
            }
            let _ = self.server.poll_flush()?;
        }
        //println!("looped {} messages", count);
        Ok(Async::NotReady)
    }
}

struct PortMap {
    ports: HashMap<Id, Sender<ToPort>>,
}

impl PortMap {
    fn new() -> PortMap {
        PortMap {
            ports: HashMap::new(),
        }
    }

    fn insert(&mut self, id: Id, sender: Sender<ToPort>) {
        let _ = self.ports.insert(id, sender);
    }

    fn remove(&mut self, id: Id) {
        let _ = self.ports.remove(&id);
    }

    fn process(&mut self, msg: (Id, ToPort)) -> Result<(), (Id, ToPort)> {
        match msg {
            (0, ToPort::HeartBeat) => Ok(()),
            (id, msg) => {
                if let Some(sender) = self.ports.get_mut(&id) {
                    match sender.poll_ready() {
                        Ok(Async::Ready(_)) => Ok(sender.try_send(msg).unwrap()),
                        Ok(Async::NotReady) => Err((id, msg)),
                        Err(_) => { self.remove(id); Ok(()) },
                    }
                } else {
                    debug!("sending to an nonexist port {}", id);
                    Ok(())
                }
            },
        }
    }
}

fn toport(msg: ServerMsg) -> (Id, ToPort) {
    match msg {
        ServerMsg::HeartBeatRsp => (0, ToPort::HeartBeat),
        ServerMsg::ConnectOK(id, buf) => (id, ToPort::ConnectOK(buf)),
        ServerMsg::Data(id, buf) => (id, ToPort::Data(buf)),
        ServerMsg::ShutdownWrite(id) => (id, ToPort::ShutdownWrite),
        ServerMsg::ClosePort(id) => (id, ToPort::Close),
    }
}

fn tunnel_broken() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "Tunnel broken")
}

