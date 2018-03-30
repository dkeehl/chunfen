use std::net::{TcpStream, TcpListener, SocketAddrV4};
use std::thread;
use std::sync::mpsc::{Sender, Receiver, channel, TryRecvError};
//use std::marker::Send;
use std::time::Duration;
use std::io::Write;
use time::{Timespec, get_time};

use {DomainName, Port, Id, Talker, communicate, TcpConnection, Result,};
use client::socks::SocksConnection;
use protocol::*;

pub mod socks;

enum ClientMsg {
    HeartBeat,
    OpenPort(Id),
    Connect(Id, SocketAddrV4),
    ConnectDN(Id, DomainName, Port),
    Data(Id, Vec<u8>),
    ShutdownWrite(Id),

    ClosePort(Id),
}

enum ServerMsg {
    HeartBeatRsp,
    ConnectOK(Id, Vec<u8>),
    Data(Id, Vec<u8>),
    ShutdownWrite(Id),

    ClosePort(Id),
}

enum SocksMsg {
    ConnectOK(Vec<u8>),
    Data(Vec<u8>),
    ShutdownWrite,
    Close,
}

struct Tunnel {
    tcp: TcpConnection,  
    monitor: Receiver<ServerMsg>,

    port: Option<Id>,
}

impl Tunnel {
    pub fn new(server: &str) -> Tunnel {
        //crash if connection failed
        let stream = TcpStream::connect(server).unwrap();
        let tcp = TcpConnection(stream.try_clone().unwrap());
        let alive_time = get_time();
        let (sender, receiver) = channel();

        thread::spawn(move || {
            monitor(TcpConnection(stream), sender, alive_time);
        });
        Tunnel { tcp, monitor: receiver, port: None, }
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

fn monitor(mut tcp: TcpConnection, handler: Sender<ServerMsg>, alive_time: Timespec) {
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
            sc::CLOSE_PORT => handler.send(ServerMsg::ClosePort(id)).unwrap(),

            sc::SHUTDOWN_WRITE =>
                handler.send(ServerMsg::ShutdownWrite(id)).unwrap(),

            sc::CONNECT_OK => {
                let len = tcp.read_u32().expect("failed to read tunnel");
                let buf = tcp.read_size(len as usize).expect("failed to read tunnel");
                handler.send(ServerMsg::ConnectOK(id, buf)).unwrap();
            },

            sc::DATA => {
                let len = tcp.read_u32().unwrap();
                let buf = tcp.read_size(len as usize).expect("failed to read tunnel");
                handler.send(ServerMsg::Data(id, buf)).unwrap();
            },

            _ => break,
        }
        alive_time = get_time();
    }
}

trait WriteTcp<T> {
    fn send(&mut self, msg: T) -> Result<()>;
}

impl WriteTcp<ClientMsg> for TcpConnection {
    fn send(&mut self, msg: ClientMsg) -> Result<()> {
        match msg {
            ClientMsg::HeartBeat => self.write_u8(cs::HEARTBEAT),

            ClientMsg::OpenPort(id) => {
                self.write_u8(cs::OPEN_PORT)
                    .and_then(|_| self.write_u32(id))
            },

            ClientMsg::Connect(id, addr) => {
                let mut buf = Vec::new();
                let _ = write!(&mut buf, "{}", addr);
                self.write_u8(cs::CONNECT)
                    .and_then(|_| self.write_u32(id))
                    .and_then(|_| self.write_u32(buf.len() as u32))
                    .and_then(|_| self.write(&buf[..]))
            },

            ClientMsg::ConnectDN(id, dn, port) => {
                self.write_u8(cs::CONNECT_DOMAIN_NAME)
                    .and_then(|_| self.write_u32(id))
                    .and_then(|_| self.write_u32(dn.len() as u32))
                    .and_then(|_| self.write(&dn[..]))
                    .and_then(|_| self.write_u16(port))
            },

            ClientMsg::Data(id, buf) => {
                self.write_u8(cs::DATA)
                    .and_then(|_| self.write_u32(id))
                    .and_then(|_| self.write_u32(buf.len() as u32))
                    .and_then(|_| self.write(&buf[..]))
            },

            ClientMsg::ShutdownWrite(id) => {
                self.write_u8(cs::SHUTDOWN_WRITE)
                    .and_then(|_| self.write_u32(id))
            },

            ClientMsg::ClosePort(id) => {
                self.write_u8(cs::CLOSE_PORT)
                    .and_then(|_| self.write_u32(id))
            },
        }
    }
}

impl Talker<SocksMsg, ClientMsg> for Tunnel {
    fn tell<T, W>(&mut self, socks: &mut T) where T: Talker<W, SocksMsg> {
        loop {
            match self.monitor.recv() {
                Err(_) => break,

                Ok(ServerMsg::HeartBeatRsp) => unreachable!(),

                Ok(ServerMsg::ConnectOK(id, buf)) => {
                    self.port.map(|p| {
                        if id == p {
                            let _ = socks.told(SocksMsg::ConnectOK(buf));
                        }
                    });
                },

                Ok(ServerMsg::Data(id, buf)) => {
                    self.port.map(|p| {
                        if id == p {
                            let _ = socks.told(SocksMsg::Data(buf));
                        }
                    });
                },

                Ok(ServerMsg::ShutdownWrite(id)) => {
                    self.port.map(|p| {
                        if id == p {
                            let _ = socks.told(SocksMsg::ShutdownWrite);
                        }
                    });
                },

                Ok(ServerMsg::ClosePort(id)) => {
                    if let Some(p) = self.port {
                        if id == p {
                            let _ = socks.told(SocksMsg::Close);
                            self.port = None;
                            break;
                        }
                    }
                },
            }
        }
    }

    fn told(&mut self, msg: ClientMsg) -> Result<()> {
        match msg {
            ClientMsg::HeartBeat => unreachable!(),

            ClientMsg::OpenPort(id) => self.port = Some(id),

            _ => {},
        }
        self.tcp.send(msg)
    }
}

pub struct Client; 

impl Client {
    pub fn new(listen_addr: &str, server_addr: &str) {
        let listening = TcpListener::bind(listen_addr).unwrap();
        let mut tunnel = Tunnel::new(server_addr);

        let mut id = 0;
        for s in listening.incoming() {
            if let Ok(stream) = s {     //stream: TcpStream
                let mut socks_connection = SocksConnection::new(id, stream);
                communicate(&mut socks_connection, &mut tunnel);
                id += 1;
            }
        }
    }
}

