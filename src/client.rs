use std::net::{self, SocketAddr, SocketAddrV4, Shutdown, ToSocketAddrs};
use std::thread;
use std::io::{self, Write, Read};
use std::collections::HashMap;

use time::{Timespec, get_time};
use tokio_current_thread::{self as ct, CurrentThread, Handle};
use tokio_tcp::{TcpStream, TcpListener};
use tokio_io::{AsyncRead, AsyncWrite};
use tokio_reactor::Handle as ReactorHandle;
use tokio_executor::park::ParkThread;
use tokio_timer::timer::{Handle as TimerHandle, Timer as TokioTimer};
use futures::future;
use futures::{Sink, Stream, Future, Poll, Async};
use futures::sync::mpsc::{self, Sender, Receiver};
use bytes::{BufMut, BytesMut};

use chunfen_sec::client::ClientSession;
use chunfen_socks::SocksConnection;

use crate::framed::Framed;
use crate::utils::{self, Timer, DomainName, Port, Id};
use crate::tunnel_port::{ToPort, FromPort, TunnelPort};
use crate::protocol::{ServerMsg, ClientMsg, HEARTBEAT_INTERVAL_MS, ALIVE_TIMEOUT_TIME_MS};
use crate::tls;

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

    fn send(&self, id: Id, msg: ToPort) {
        match self.ports.get(&id) {
            Some(v) => {
                let send = v.clone().send(msg);
                ct::spawn(drop_res!(send))
            },
            None => info!("sending to an nonexist port {}", id),
        }
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
    fn new(server: &str, key: Vec<u8>) -> Tunnel {
        let stream = net::TcpStream::connect(server)
            .expect("can't connect to server");
        let (sender, receiver) = mpsc::channel(1000);
        let cloned_sender = sender.clone();
        thread::spawn(|| {
            run_tunnel(stream, key, cloned_sender, receiver)
        });

        Tunnel { sender, count: 0, }
    }

    fn new_port(&mut self, handle: &Handle) -> TunnelPort<ClientMsg> {
        let id = self.count;
        //println!("new port {}!", id);
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

    fn run(stream: Tls,
           sender: Sender<FromPort<ClientMsg>>,
           receiver: Receiver<FromPort<ClientMsg>>,
           handle: TimerHandle) -> RunTunnel
    {
        let server: Framed<ServerMsg, ClientMsg, Tls> = Framed::new(stream);
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

fn run_tunnel(stream: net::TcpStream,
              key: Vec<u8>,
              sender: Sender<FromPort<ClientMsg>>,
              receiver: Receiver<FromPort<ClientMsg>>)
{
    let timer = TokioTimer::new(ParkThread::new());
    let handle = timer.handle();
    let mut lp = CurrentThread::new_with_park(timer);

    let tcp = TcpStream::from_std(stream, &ReactorHandle::default()).unwrap();
    let session = ClientSession::new(&key);

    let tunnel = tls::connect(session, tcp).and_then(|stream| {
        Tunnel::run(stream, sender, receiver, handle)
    }).map_err(|e| {
        println!("An error occured: {:#?}", e);
        ()
    });

    lp.spawn(tunnel);
    lp.run().unwrap()
}

struct RunTunnel {
    server: Framed<ServerMsg, ClientMsg, Tls>,
    timer: Timer,
    client: Receiver<FromPort<ClientMsg>>,

    ports: PortMap,
    alive_time: Timespec,
}

impl RunTunnel {
    fn process_server_msg(&mut self, s_msg: ServerMsg) {
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
            FromPort::Payload(m @ ClientMsg::Connect(..)) => {
                //println!("will send message {}", m);
                m
            },
            FromPort::Payload(m @ ClientMsg::Data(..)) => m,
            FromPort::Payload(_) => unreachable!(),
        };
        //println!("sending {}", c_msg);
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
                return Err(io::Error::new(io::ErrorKind::TimedOut, "timeout"))
            } else {
                //println!("hearbeat");
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
                    //println!("get server message {}", s_msg);
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
    pub fn new(listen_addr: &str, server_addr: &str, key: Vec<u8>) {
        let mut lp = CurrentThread::new();
        let handle = lp.handle();
        let listen_addr = listen_addr.parse().unwrap();

        let listening = TcpListener::bind(&listen_addr).unwrap();
        let mut tunnel = Tunnel::new(server_addr, key);

        let client = listening.incoming().for_each(move |stream| {
            // TODO: Quit if tunnel broken
            let mut port = tunnel.new_port(&handle);
            let proxy = SocksConnection::serve(stream, port);
            ct::spawn(drop_res!(proxy));
            Ok(())
        });
        
        lp.spawn(drop_res!(client));
        lp.run().unwrap()
    }
}
