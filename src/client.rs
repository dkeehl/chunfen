use std::net::{TcpStream, TcpListener, SocketAddr, SocketAddrV4, Shutdown,
               ToSocketAddrs};
use std::thread;
use std::sync::mpsc;
use std::sync::mpsc::{Sender, Receiver,  SyncSender, TryRecvError, };
use std::io::{copy, Write};
use std::collections::HashMap;
use std::str::from_utf8;

use time::get_time;

use {DomainName, Port, Id, TcpWrapper, Result, WriteTcp, Error, ServerMsg,
    ClientMsg, };
use socks::{SocksConnection, Connector, CopyTcp};
use utils::Timer;
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
        PortMap(HashMap::new())
    }

    fn insert(&mut self, id: Id, sender: SyncSender<SocksMsg>) {
        self.0.insert(id, sender);
    }

    fn remove(&mut self, id: Id) {
        self.0.remove(&id);
    }

    fn send(&mut self, id: Id, msg: SocksMsg) {
        self.0.get(&id).map(|v| v.send(msg));
    }
}

struct Tunnel {
    // This sender rarely sends messages itself, but is used to be cloned to
    // produce tunnel ports.
    sender: Sender<Msg>,
    count: u32,
}

// To implement the Write trait, need this wrapper for Sender
#[derive(Clone)]
struct MsgSender(Sender<Msg>, Id);

struct TunnelPort {
    id: Id,
    sender: MsgSender,
    receiver: Receiver<SocksMsg>,
}

impl Tunnel {
    pub fn new(server: &str) -> Tunnel {
        // Crash if connection failed
        let stream = TcpStream::connect(server).unwrap();

        let tcp = TcpWrapper(stream.try_clone().unwrap());
        let (sender, receiver) = mpsc::channel();

        // A tunnel has two threads. One is `monitor`, which maintains the
        // the connection with the tunnel server, reads from the server and
        // sends to the handler. The other is `handler`, which receives and
        // handles messages from the monitor and all the ports.
        let cloned_sender = sender.clone();
        thread::spawn(move || {
            monitor(TcpWrapper(stream), cloned_sender);
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
        let (sender, receiver) = mpsc::sync_channel(10000);
        self.sender.send(Msg::NewPort(id, sender));
        self.count += 1;
        Ok(TunnelPort { id, sender: MsgSender(self.sender.clone(), id), receiver, })
    }
}


fn monitor(mut tcp: TcpWrapper, handler: Sender<Msg>) {
    let mut alive_time = get_time();
    let timer = Timer::new(HEARTBEAT_INTERVAL_MS as u64);
    loop {
        match timer.try_recv() {
            Ok(_) => {
                let duration = get_time() - alive_time;
                if duration.num_milliseconds() > ALIVE_TIMEOUT_TIME_MS {
                    break;
                } else {
                    let _ = handler.send(Msg::Client(ClientMsg::HeartBeat));
                }
            },

            Err(TryRecvError::Empty) => {},

            _ => break,
        }

        let op = tcp.read_u8().expect("failed to read op");

        if op == sc::HEARTBEAT_RSP {
            alive_time = get_time();
            continue
        }
        
        let id = tcp.read_u32().expect("failed to read id");

        match op {
            sc::CLOSE_PORT =>
                handler.send(Msg::Server(ServerMsg::ClosePort(id))).unwrap(),

            sc::SHUTDOWN_WRITE =>
                handler.send(Msg::Server(ServerMsg::ShutdownWrite(id))).unwrap(),

            sc::CONNECT_OK => {
                let len = tcp.read_u32().expect("failed to read data length at connect_ok");
                let buf = tcp.read_size(len as usize).expect("failed to read data of length ..");
                handler.send(Msg::Server(ServerMsg::ConnectOK(id, buf))).unwrap();
            },

            sc::DATA => {
                let len = tcp.read_u32().expect("failed to read data length at data");
                let buf = tcp.read_size(len as usize).expect("failed to read data of length ..");
                handler.send(Msg::Server(ServerMsg::Data(id, buf))).unwrap();
            },

            _ => break,
        }
        alive_time = get_time();
    }
}

fn handler(tcp: TcpWrapper, receiver: Receiver<Msg>) {
    let mut tcp = tcp;
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
                            ports.send(id, SocksMsg::Data(buf)),

                        ServerMsg::ShutdownWrite(id) =>
                            ports.send(id, SocksMsg::ShutdownWrite),

                        ServerMsg::ClosePort(id) =>
                            ports.send(id, SocksMsg::Close),
                    }
                },
                Msg::Client(c_msg) => {
                    match c_msg {
                        ClientMsg::OpenPort(_) => unreachable!(),

                        ClientMsg::ClosePort(id) => ports.remove(id),
                        
                        _ => {},
                    }
                    tcp.send(c_msg);
                },
            }
        } else {
            break
        }
    }
}

impl WriteTcp<ClientMsg> for TcpWrapper {
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

impl Connector for TunnelPort {
    fn connect(&mut self, addr: SocketAddrV4) -> Option<SocketAddr> {
        self.sender.0.send(Msg::Client(ClientMsg::Connect(self.id, addr)));
        if let Ok(SocksMsg::ConnectOK(buf)) = self.receiver.recv() {
            try_parse_domain_name(buf)
        } else {
            None
        }
    }

    fn connect_dn(&mut self, dn: DomainName, port: Port) -> Option<SocketAddr> {
        self.sender.0.send(Msg::Client(ClientMsg::ConnectDN(self.id, dn, port)));
        if let Ok(SocksMsg::ConnectOK(buf)) = self.receiver.recv() {
            try_parse_domain_name(buf)
        } else {
            None
        }
    }
}

fn try_parse_domain_name(buf: Vec<u8>) -> Option<SocketAddr> {
    let string = from_utf8(&buf[..]).unwrap_or("");
    debug!("remote address is {}", &string);
    if let Ok(mut addr_iter) = string.to_socket_addrs() {
        addr_iter.nth(0)
    } else {
        None
    }
}

impl Write for MsgSender {
    fn write(&mut self, buf: &[u8]) -> ::std::io::Result<usize> {
        let size: usize = 1024;
        let mut to: Vec<u8> = Vec::with_capacity(size);
        let len = buf.len();
        let res = if len > size {
            to.write(&buf[..size])?
        } else {
            to.write(buf)?
        };
        self.0.send(Msg::Client(ClientMsg::Data(self.1, to)));
        Ok(res)
    }

    fn flush(&mut self) -> ::std::io::Result<()> { Ok(()) }
}

impl CopyTcp for TunnelPort {
    fn copy_tcp(&mut self, stream: TcpStream) -> Result<()> {
        let mut stream_read = stream.try_clone().unwrap();
        let mut tun_write = self.sender.clone();
        thread::spawn(move || {
            copy(&mut stream_read, &mut tun_write);
            stream_read.shutdown(Shutdown::Read).unwrap();
            tun_write.0.send(Msg::Client(ClientMsg::ShutdownWrite(tun_write.1)));
        });

        let mut stream_write = stream;
        loop {
            match self.receiver.recv() {
                Ok(SocksMsg::ConnectOK(_)) => unreachable!(),

                Ok(SocksMsg::Data(buf)) => {
                    if stream_write.write(&buf[..]).is_err() {
                        stream_write.shutdown(Shutdown::Both);
                        return Err(Error::TcpIo)
                    }
                },

                Ok(SocksMsg::ShutdownWrite) => {
                    stream_write.shutdown(Shutdown::Write);
                    return Ok(())
                },

                _ => {
                    stream_write.shutdown(Shutdown::Both);
                    return Err(Error::ServerClosedConnection)
                },
            }
        }
    }
}

pub struct Client; 

impl Client {
    pub fn new(listen_addr: &str, server_addr: &str) {
        let listening = TcpListener::bind(listen_addr).unwrap();
        let mut tunnel = Tunnel::new(server_addr);

        for s in listening.incoming() {
            if let (Ok(stream), Ok(connector)) = (s, tunnel.connect()) { 
                SocksConnection::new(stream, connector);
            }
        }
    }
}

