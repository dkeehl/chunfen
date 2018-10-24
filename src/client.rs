use std::net::{self, SocketAddr, SocketAddrV4, Shutdown, ToSocketAddrs};
use std::thread;
use std::sync::mpsc::{self, Sender, Receiver, TryRecvError};
use std::io::{self, Write, Read};
use std::collections::HashMap;

use time::{Timespec, get_time};
use tokio_core::reactor::{Core, Handle};
use tokio_core::net::{TcpStream, TcpListener};
use tokio_io::{AsyncRead, AsyncWrite};
use futures::future;
use futures::{Stream, Future, Poll, Async};
use futures::sync::mpsc::UnboundedSender;
use bytes::{BufMut, BytesMut};
use nom::Err::Incomplete;

use {Encode, DomainName, Port, Id};
use socks::SocksConnection;
use utils::{self, Timer};
use tunnel_port::{ToPort, FromPort, TunnelPort};
use protocol::{parse_client_msg, parse_server_msg, ServerMsg, ClientMsg,
               HEARTBEAT_INTERVAL_MS, ALIVE_TIMEOUT_TIME_MS};

struct PortMap(HashMap<Id, UnboundedSender<ToPort>>);

impl PortMap {
    fn new() -> PortMap {
        PortMap(HashMap::new())
    }

    fn insert(&mut self, id: Id, sender: UnboundedSender<ToPort>) {
        self.0.insert(id, sender);
    }

    fn remove(&mut self, id: Id) {
        self.0.remove(&id);
    }

    fn send(&mut self, id: Id, msg: ToPort) {
        self.0.get(&id).map(|v| {
            v.unbounded_send(msg).expect("port has been dropped")
        });
    }
}

struct Tunnel {
    // This sender rarely sends messages itself, but is used to be cloned to
    // produce tunnel ports.
    // If this sender get an error when sending messages, we know that the
    // tunnel is broken.
    sender: Sender<FromPort>,
    count: u32,
}

impl Tunnel {
    pub fn new(server: &str) -> Tunnel {
        //let addr: SocketAddr = server.parse().unwrap();
        let stream = net::TcpStream::connect(server).unwrap();
        let (sender, receiver) = mpsc::channel();
        let cloned_sender = sender.clone();
        thread::spawn(move || {
            run_tunnel(stream, cloned_sender, receiver)
        });

        Tunnel { sender, count: 0, }
    }

    pub fn connect(&mut self) -> TunnelPort {
        let id = self.count;
        // Open a channel between the port and the tunnel. The sender is send 
        // to the tunnel, for sending data later to the corresponing port. 
        let (sender, port) = TunnelPort::new(id, self.sender.clone());
        self.sender.send(FromPort::NewPort(id, sender));
        self.count += 1;
        port
    }

    fn run(stream: TcpStream,
           sender: Sender<FromPort>,
           receiver: Receiver<FromPort>,
           handle: Handle) -> RunTunnel
    {
        let server = Server::new(stream);
        let timer = Timer::new(HEARTBEAT_INTERVAL_MS as u64, &handle);
        let ports = PortMap::new();
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

fn run_tunnel(stream: net::TcpStream, sender: Sender<FromPort>, receiver: Receiver<FromPort>) {
    let mut lp = Core::new().unwrap();
    let handle = lp.handle();
    let mut stream = TcpStream::from_stream(stream, &handle).unwrap();
    let tunnel = Tunnel::run(stream, sender, receiver, handle);
    lp.run(tunnel).unwrap()
}

struct RunTunnel {
    server: Server,
    timer: Timer,
    client: Receiver<FromPort>,

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
        self.alive_time = get_time();
    }

    fn process_client_msg(&mut self, c_msg: ClientMsg) {
        //println!("get client message {:?}", c_msg);
        match c_msg {
            ClientMsg::OpenPort(_) => unreachable!(),

            ClientMsg::ClosePort(id) => self.ports.remove(id),
            
            _ => {},
        }
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
            match self.client.try_recv() {
                Ok(FromPort::NewPort(id, sender)) => {
                    self.ports.insert(id, sender);
                    self.server.buffer_msg(ClientMsg::OpenPort(id));
                },
                Ok(FromPort::Client(c_msg)) => self.process_client_msg(c_msg),
                Err(TryRecvError::Empty) => break,
                // All senders have lost. No more client messages will arrive.
                Err(TryRecvError::Disconnected) =>
                    return Ok(().into()),
            }
        }
        let _ = self.server.poll_flush()?;

        // Continue no matter previous flush ready or not ready.
        // Check server side messages.
        loop {
            match try_ready!(self.server.poll()) {
                Some(s_msg) => self.process_server_msg(s_msg),
                // Disconnected from server.
                None =>
                    return Err(io::Error::new(io::ErrorKind::ConnectionAborted, "")),
            }
        }
    }
}

struct Server {
    stream: TcpStream,
    r_buffer: BytesMut,
    w_buffer: BytesMut,
}

impl Server {
    fn new(stream: TcpStream) -> Server {
        Server {
            stream,
            r_buffer: BytesMut::new(),
            w_buffer: BytesMut::new(),
        }
    }

    fn fill_buffer(&mut self) -> Poll<(), io::Error> {
        loop {
            self.r_buffer.reserve(1024);
            let n = try_ready!(self.stream.read_buf(&mut self.r_buffer));
            if n == 0 {
                return Ok(Async::Ready(()))
            }
        }
    }

    fn buffer_msg(&mut self, msg: ClientMsg) {
        if self.w_buffer.remaining_mut() < 10 {
            self.w_buffer.reserve(32);
        }
        msg.encode(&mut self.w_buffer);
    }

    fn poll_flush(&mut self) -> Poll<(), io::Error> {
        while !self.w_buffer.is_empty() {
            let len = try_nb!(self.stream.write(&self.w_buffer));
            assert!(len > 0);
            self.w_buffer.advance(len);
        }
        Ok(Async::Ready(()))
    }
}

enum ParseResult {
    Ok { msg: ServerMsg, consumed: usize },
    Incomplete,
    Err,
}

impl Stream for Server {
    type Item = ServerMsg;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<ServerMsg>, io::Error> {
        let eof = self.fill_buffer()?.is_ready();

        let res = {
            match parse_server_msg(&self.r_buffer) {
                Ok((remain, msg)) => {
                    let remain = remain.len();
                    let len = self.r_buffer.len();
                    ParseResult::Ok{ msg, consumed: len - remain }
                },
                Err(Incomplete(_)) => ParseResult::Incomplete,
                Err(e) => {
                    println!("parse error: {}", e);
                    ParseResult::Err
                },
            }
        };

        match res {
            ParseResult::Ok { msg, consumed } => {
                self.r_buffer.advance(consumed);
                //println!("consumed {}, msg: {}", consumed, msg);
                return Ok(Async::Ready(Some(msg)))
            },
            ParseResult::Incomplete => {
                //println!("incomplete, now buffer has {}", self.r_buffer.len());
            },
            ParseResult::Err => 
                return Err(io::Error::new(io::ErrorKind::InvalidData, "ServerMsg")),
        }

        if eof {
            Ok(Async::Ready(None))
        } else {
            Ok(Async::NotReady)
        }
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
            let mut port = tunnel.connect();
            let proxy = SocksConnection::new(handle.clone()).serve(stream, port);
            handle.spawn(proxy.then(|_| future::ok(())));
            Ok(())
        });
        
        lp.run(client).unwrap()
    }
}
