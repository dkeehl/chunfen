use std::net::{TcpStream, TcpListener, SocketAddr, SocketAddrV4, Shutdown,
               ToSocketAddrs};
use std::thread;
use std::sync::mpsc;
use std::sync::mpsc::{Sender, Receiver,  SyncSender, TryRecvError, };
use std::io::{copy, Write};
use std::collections::HashMap;
use std::str::from_utf8;

use time::get_time;

use {DomainName, Port, Id, TcpWrapper, Result, 
    WriteSize, ReadSize, WriteStream, Error, ParseStream};
use socks::{SocksConnection, Connector, CopyTcp};
use utils::Timer;
use protocol::*;
use protocol::{ServerMsg, ClientMsg};

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
    Shutdown,
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
struct MsgSender(Id, Sender<Msg>);

struct TunnelPort {
    id: Id,
    sender: Sender<Msg>,
    receiver: Receiver<SocksMsg>,
    //alive_time: Timespec, // For profiling 
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
        let (sender, receiver) = mpsc::sync_channel(1000);
        self.sender.send(Msg::NewPort(id, sender));
        self.count += 1;
        Ok(TunnelPort { id, sender: self.sender.clone() , receiver })
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
                    handler.send(Msg::Client(ClientMsg::HeartBeat));
                }
            },

            Err(TryRecvError::Empty) => {},

            _ => break,
        }

        match tcp.parse_stream() {
            Some(msg) => {
                handler.send(Msg::Server(msg));
                alive_time = get_time();
            },

            None => {
                println!("Lost connection to server");
                break
            },
        }
    }
    let _ = tcp.shutdown_read();
    let _ = handler.send(Msg::Shutdown);
}

fn handler(tcp: TcpWrapper, receiver: Receiver<Msg>) {
    let mut tcp = tcp;
    let mut ports = PortMap::new();
    loop {
        if let Ok(msg) = receiver.recv() {
            match msg {
                Msg::NewPort(id, sender) => {
                    ports.insert(id, sender);
                    tcp.write_stream(ClientMsg::OpenPort(id));
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
                    tcp.write_stream(c_msg);
                },

                Msg::Shutdown => break,
            }
        } else {
            break
        }
    }
    let _ = tcp.shutdown_write();
}

impl Connector for TunnelPort {
    fn connect(&mut self, addr: SocketAddrV4) -> Option<SocketAddr> {
        debug!("task {}: connecting to {}", self.id, addr);
        let mut buf = Vec::new();
        let _ = write!(&mut buf, "{}", addr);
        self.sender.send(Msg::Client(ClientMsg::Connect(self.id, buf)));
        if let Ok(SocksMsg::ConnectOK(buf)) = self.receiver.recv() {
            try_parse_domain_name(buf)
        } else {
            None
        }
    }

    fn connect_dn(&mut self, dn: DomainName, port: Port) -> Option<SocketAddr> {
        self.sender.send(Msg::Client(ClientMsg::ConnectDN(self.id, dn, port)));
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
    string.to_socket_addrs().ok()
        .and_then(|mut addr_iter| addr_iter.nth(0))
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
        self.1.send(Msg::Client(ClientMsg::Data(self.0, to)));
        Ok(res)
    }

    fn flush(&mut self) -> ::std::io::Result<()> { Ok(()) }
}

impl CopyTcp for TunnelPort {
    fn copy_tcp(&mut self, stream: TcpStream) -> Result<()> {
        let mut stream_read = stream.try_clone().unwrap();
        let mut tun_write = MsgSender(self.id, self.sender.clone());
        thread::spawn(move || {
            copy(&mut stream_read, &mut tun_write);
            stream_read.shutdown(Shutdown::Read).unwrap();
            tun_write.1.send(Msg::Client(ClientMsg::ShutdownWrite(tun_write.0)));
        });

        let mut stream_write = stream;
        loop {
            match self.receiver.recv() {
                Ok(SocksMsg::ConnectOK(_)) => unreachable!(),

                Ok(SocksMsg::Data(buf)) => {
                    if stream_write.write(&buf[..]).is_err() {
                        stream_write.shutdown(Shutdown::Both);
                        return Err(Error::Io)
                    }
                },

                Ok(SocksMsg::ShutdownWrite) => {
                    stream_write.shutdown(Shutdown::Write);
                    //let total_time = (get_time() - self.alive_time).num_seconds();
                    //println!("task {}: finished in {}seconds.", self.id, total_time);
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

        listening.incoming().for_each(|s| {
            if let (Ok(stream), Ok(connector)) = (s, tunnel.connect()) { 
                thread::spawn(move || {
                    SocksConnection::new(stream, connector);
                });
            }
        });
    }
}

