use std::net::{TcpStream, TcpListener, SocketAddrV4};
use std::thread;
use std::sync::mpsc::{Sender, Receiver, channel, sync_channel, SyncSender,
                    TryRecvError, };
//use std::marker::Send;
use std::time::Duration;
use std::io::Write;
use std::collections::HashMap;
use time::{Timespec, get_time};

use {DomainName, Port, Id, TcpConnection, Result, WriteTcp, Error, ServerMsg,
    ClientMsg, };
use socks::SocksConnection;
use protocol::*;

#[derive(Debug)]
enum SocksMsg {
    ConnectOK(Vec<u8>),
    Data(Vec<u8>),
    ShutdownWrite,
    Close,
}

enum Msg {
    NewPort(Id, SyncSender<SocksMsg>),
    Server(ServerMsg),
    Client(ClientMsg),
}

struct PortMap(HashMap<Id, SyncSender<SocksMsg>>);

impl PortMap {
    fn new() -> PortMap {
        PortMap { HashMap::new() }
    }

    fn insert(id: Id, sender: SyncSender<SocksMsg>) {
        self.0.insert(id, sender);
    }

    fn remove(id: Id) {
        self.0.remove(&id);
    }

    fn send(id: Id, msg: SocksMsg) {
        self.0.get(&id).map(|v| v.send(msg));
    }
}

struct Tunnel {
    // This sender rarely sends messages itself, but is used to be cloned to
    // produce tunnel ports.
    sender: Sender<Msg>,
    count: u32,
}

struct TunnelPort {
    id: Id,
    sender: Sender<Msg>,
    receiver: Receiver<SocksMsg>,
}

impl Tunnel {
    pub fn new(server: &str) -> Tunnel {
        // Crash if connection failed
        let stream = TcpStream::connect(server).unwrap();

        let tcp = TcpConnection(stream.try_clone().unwrap());
        let alive_time = get_time();
        let (sender, receiver) = channel();

        // A tunnel has two threads. One is `monitor`, which maintains the
        // the connection with the tunnel server, reads from the server and
        // sends to the handler. The other is `handler`, which receives and
        // handles messages from the monitor and all the ports.
        let cloned_sender = sender.clone();
        thread::spawn(move || {
            monitor(TcpConnection(stream), cloned_sender, alive_time);
        });

        thread::spawn(move || {
            handler(tcp, receiver);
        });

        Tunnel { sender, count: 0, }
    }

    pub fn connect(&mut self) -> Result<TunnelPort> {
        let id = self.count;
        // Open a channel between the port and the tunnel. The sender is left,
        // while the receiver is put in the port.
        let (sender, receiver) = sync_channel(10000);
        self.sender.send(Msg::NewPort(id, sender)?;
        self.count += 1;
        Ok(TunnelPort { id, sender: self.sender.clone(), receiver, })
    }
}

pub struct Timer;

impl Timer {
    pub fn new() -> Receiver<()> {
        let (sender, receiver) = channel();
        thread::spawn(move || {
            let t = Duration::from_millis(HEARTBEAT_INTERVAL_MS as u64);
            loop {
                thread::sleep(t);
                if let Err(_) = sender.send(()) {
                    break;
                }
            }
        });
        receiver
    }
}

fn monitor(mut tcp: TcpConnection, handler: Sender<Msg>, alive_time: Timespec) {
    let mut alive_time = alive_time;
    let timer = Timer::new();
    loop {
        match timer.try_recv() {
            Ok(_) => {
                let duration = get_time() - alive_time;
                if duration.num_milliseconds() > ALIVE_TIMEOUT_TIME_MS {
                    break;
                } else {
                    let _ = tcp.send(ClientMsg::HeartBeat);
                }
            },

            Err(TryRecvError::Empty) => {},

            _ => break,
        }

        let op = tcp.read_u8().expect("failed to read tunnel");

        if op == sc::HEARTBEAT_RSP {
            alive_time = get_time();
            continue
        }
        
        let id = tcp.read_u32().expect("failed to read tunnel");

        match op {
            sc::CLOSE_PORT =>
                handler.send(Msg::Server(ServerMsg::ClosePort(id))).unwrap(),

            sc::SHUTDOWN_WRITE =>
                handler.send(Msg::Server(ServerMsg::ShutdownWrite(id))).unwrap(),

            sc::CONNECT_OK => {
                let buf = tcp.read_size(len as usize).expect("failed to read tunnel");
                handler.send(Msg::Server(ServerMsg::ConnectOK(id, buf))).unwrap();
            },

            sc::DATA => {
                let len = tcp.read_u32().expect("failed to read tunnel");
                let buf = tcp.read_size(len as usize).expect("failed to read tunnel");
                handler.send(Msg::Server(ServerMsg::Data(id, buf))).unwrap();
            },

            _ => break,
        }
        alive_time = get_time();
    }
}

fn handler(tcp: TcpConnection, receiver: Receiver<Msg>) {
    let mut ports = PortMap::new();
    loop {
        if let Ok(msg) = receiver.recv() {
            match msg {
                Msg::NewPort(id, sender) => {
                    ports.insert(id, sender);
                    tcp.send(ClientMsg::OpenPort(id));
                }
                             
                Msg::Server(s_msg) => {
                    match s_msg {
                        ServerMsg::HeartBeatRsp => unreachable!(),

                        ServerMsg::ConnectOK(id, buf) => 
                            ports.send(id, SocksMsg::ConnectOK(buf)),

                        ServerMsg::Data(id, buf) =>
                            ports.send(id, SocksMsg::Data(buf),

                        ServerMsg::ShutdownWrite(id) =>
                            ports.send(id, SocksMsg::ShutdownWrite,

                        ServerMsg::ClosePort(id) =>
                            ports.send(id, SocksMsg::Close),
                    }
                },
                Msg::Client(c_msg) => {
                    match c_msg => {
                        ClientMsg::HeartBeat |
                        ClientMsg::OpenPort(_) => unreachable!(),

                        ClientMsg::ClosePort(id) => ports.remove(id),
                        
                        _ => {},
                    }
                    tcp.send(c_msg)
                },
        } else {
            break
        }
    }
}

impl WriteTcp<ClientMsg> for TcpConnection {
    fn send(&mut self, msg: ClientMsg) -> Result<()> {
        match msg {
            ClientMsg::HeartBeat => self.write_u8(cs::HEARTBEAT),

            ClientMsg::OpenPort(id) => {
                self.write_u8(cs::OPEN_PORT)
                    .and(self.write_u32(id))
            },

            ClientMsg::Connect(id, addr) => {
                let mut buf = Vec::new();
                let _ = write!(&mut buf, "{}", addr);
                self.write_u8(cs::CONNECT)
                    .and(self.write_u32(id))
                    .and(self.write_u32(buf.len() as u32))
                    .and(self.write(&buf[..]))
            },

            ClientMsg::ConnectDN(id, dn, port) => {
                self.write_u8(cs::CONNECT_DOMAIN_NAME)
                    .and(self.write_u32(id))
                    .and(self.write_u32(dn.len() as u32))
                    .and(self.write(&dn[..]))
                    .and(self.write_u16(port))
            },

            ClientMsg::Data(id, buf) => {
                self.write_u8(cs::DATA)
                    .and(self.write_u32(id))
                    .and(self.write_u32(buf.len() as u32))
                    .and(self.write(&buf[..]))
            },

            ClientMsg::ShutdownWrite(id) => {
                self.write_u8(cs::SHUTDOWN_WRITE)
                    .and(self.write_u32(id))
            },

            ClientMsg::ClosePort(id) => {
                self.write_u8(cs::CLOSE_PORT)
                    .and(self.write_u32(id))
            },
        }
    }
}

pub struct Client; 

impl Client {
    pub fn new(listen_addr: &str, server_addr: &str) {
        let listening = TcpListener::bind(listen_addr).unwrap();
        let mut tunnel = Tunnel::new(server_addr);

        for s in listening.incoming() {
            if let (Ok(stream), Ok(connector)) = (s, tunnel.connect) { 
                SocksConnection::new(stream, connector);
            }
        }
    }
}

