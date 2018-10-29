use std::net::{self, SocketAddr, SocketAddrV4, Shutdown, ToSocketAddrs};
use std::thread;
//use std::sync::mpsc::{self, Sender, Receiver, TryRecvError};
use std::io::{self, Write, Read};
use std::collections::HashMap;

use time::{Timespec, get_time};
use tokio_core::reactor::{Core, Handle};
use tokio_core::net::{TcpStream, TcpListener};
use tokio_io::{AsyncRead, AsyncWrite};
use futures::future;
use futures::{Sink, Stream, Future, Poll, Async};
use futures::sync::mpsc::{self, Sender, Receiver};
use bytes::{BufMut, BytesMut};

use crate::socks::SocksConnection;
use crate::{DomainName, Port, Id};
use crate::framed::Framed;
use crate::utils::{self, Timer};
use crate::tunnel_port::{ToPort, FromPort, TunnelPort};
use crate::protocol::{ServerMsg, ClientMsg, HEARTBEAT_INTERVAL_MS, ALIVE_TIMEOUT_TIME_MS};

struct PortMap {
    ports: HashMap<Id, Sender<ToPort>>,
    handle: Handle
}

impl PortMap {
    fn new(handle: &Handle) -> PortMap {
        PortMap {
            ports: HashMap::new(),
            handle: handle.clone(),
        }
    }

    fn insert(&mut self, id: Id, sender: Sender<ToPort>) {
        let _ = self.ports.insert(id, sender);
    }

    fn remove(&mut self, id: Id) {
        let _ = self.ports.remove(&id);
    }

    fn send(&self, id: Id, msg: ToPort) {
        let _ = self.ports.get(&id).map(|v| {
            let send = v.clone().send(msg);
            self.handle.spawn(drop_res!(send))
        });
    }
}

struct Tunnel {
    // This sender rarely sends messages itself, but is used to be cloned to
    // produce tunnel ports.
    // If this sender get an error when sending messages, we know that the
    // tunnel is broken.
    sender: Sender<FromPort<ClientMsg>>,
    count: u32,
}

impl Tunnel {
    pub fn new(server: &str) -> Tunnel {
        //let addr: SocketAddr = server.parse().unwrap();
        let stream = net::TcpStream::connect(server)
            .expect("can't connect to server");
        let (sender, receiver) = mpsc::channel(1000);
        let cloned_sender = sender.clone();
        thread::spawn(move || {
            run_tunnel(stream, cloned_sender, receiver)
        });

        Tunnel { sender, count: 0, }
    }

    pub fn new_port(&mut self, handle: &Handle) -> TunnelPort<ClientMsg> {
        let id = self.count;
        // Open a channel between the port and the tunnel. The sender is send 
        // to the tunnel, for sending data later to the corresponing port. 
        let (sender, port) = TunnelPort::new(id, self.sender.clone(), handle);
        let send = self.sender.clone()
            .send(FromPort::NewPort(id, sender))
            .map(|_| ())
            .map_err(|_| panic!("background tunnel broken"));
        handle.spawn(send);
        self.count += 1;
        port
    }

    fn run(stream: TcpStream,
           sender: Sender<FromPort<ClientMsg>>,
           receiver: Receiver<FromPort<ClientMsg>>,
           handle: Handle) -> RunTunnel
    {
        let server: Framed<ServerMsg, ClientMsg> = Framed::new(stream);
        let timer = Timer::new(HEARTBEAT_INTERVAL_MS as u64, &handle);
        let ports = PortMap::new(&handle);
        let alive_time = get_time();
        RunTunnel {
            server,
            timer,
            client: receiver,
            ports,
            alive_time,
        }
    }
}

fn run_tunnel(stream: net::TcpStream,
              sender: Sender<FromPort<ClientMsg>>,
              receiver: Receiver<FromPort<ClientMsg>>)
{
    let mut lp = Core::new().unwrap();
    let handle = lp.handle();
    let mut stream = TcpStream::from_stream(stream, &handle).unwrap();
    let tunnel = Tunnel::run(stream, sender, receiver, handle);
    if let Err(e) = lp.run(tunnel) {
        println!("an error occured: {}", e);
    }
}

struct RunTunnel {
    server: Framed<ServerMsg, ClientMsg>,
    timer: Timer,
    client: Receiver<FromPort<ClientMsg>>,

    ports: PortMap,
    alive_time: Timespec,
}

impl RunTunnel {
    fn process_server_msg(&mut self, s_msg: ServerMsg) {
        //println!("get server message: {}", s_msg);
        match s_msg {
            ServerMsg::HeartBeatRsp => {},

            ServerMsg::ConnectOK(id, buf) => 
                self.ports.send(id, ToPort::ConnectOK(buf)),

            ServerMsg::Data(id, buf) =>
                self.ports.send(id, ToPort::Data(buf)),

            ServerMsg::ShutdownWrite(id) =>
                self.ports.send(id, ToPort::ShutdownWrite),

            ServerMsg::ClosePort(id) =>
                self.ports.send(id, ToPort::Close),
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
            FromPort::Payload(m) => m,
        };
        println!("sending {}", c_msg);
        self.server.buffer_msg(c_msg);
    }
}

impl Future for RunTunnel {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(), io::Error> {
        if let Async::Ready(_) = self.timer.poll()? {
            let dur = get_time() - self.alive_time;
            if dur.num_milliseconds() > ALIVE_TIMEOUT_TIME_MS {
                // Server timeout.
                return Err(io::Error::new(io::ErrorKind::TimedOut, "timeout"))
            } else {
                self.server.buffer_msg(ClientMsg::HeartBeat);
            }
        }

        // Timer is not ready.
        // Check client messages.
        loop {
            match self.client.poll().unwrap() {
                Async::Ready(Some(msg)) => self.process_port_msg(msg),
                Async::Ready(None) => return self.server.poll_flush(),
                Async::NotReady => break,
            }
        }
        let _ = self.server.poll_flush()?;

        // Check server side messages.
        loop {
            match self.server.poll()? {
                Async::Ready(Some(s_msg)) => {
                    self.process_server_msg(s_msg);
                    self.alive_time = get_time();
                },
                // Disconnected from server.
                Async::Ready(None) =>
                    return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "")),
                Async::NotReady => break,
            }
        }
        Ok(Async::NotReady)
    }
}

pub struct Client; 

impl Client {
    pub fn new(listen_addr: &str, server_addr: &str) {
        let mut lp = Core::new().unwrap();
        let handle = lp.handle();
        let listen_addr = listen_addr.parse().unwrap();

        let listening = TcpListener::bind(&listen_addr, &handle).unwrap();
        let mut tunnel = Tunnel::new(server_addr);

        let client = listening.incoming().for_each(move |(stream, _)| {
            // TODO: Quit if tunnel broken
            let mut port = tunnel.new_port(&handle);
            let proxy = SocksConnection::new(handle.clone()).serve(stream, port);
            handle.spawn(proxy.then(|_| future::ok(())));
            Ok(())
        });
        
        lp.run(client).unwrap()
    }
}
