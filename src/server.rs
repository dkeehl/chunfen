use std::net::{TcpListener, TcpStream, SocketAddr, SocketAddrV4, Shutdown};
use std::sync::mpsc;
use std::sync::mpsc::{Sender, Receiver, SyncSender};
use std::thread;
use std::io;
use std::io::Write;
use std::collections::HashMap;

use time::get_time;

use {TcpWrapper, WriteTcp, Id, DomainName, Port, Result};
use protocol::*;
use protocol::{ServerMsg, ClientMsg};
use utils::*;

pub struct Server;

impl Server {
    pub fn bind(addr: &str) {
        let listening = TcpListener::bind(addr).unwrap();

        for s in listening.incoming() {
            if let Ok(stream) = s {
                Tunnel::new(stream)
            }
        }
    }
}

struct Tunnel;

impl Tunnel {
    fn new(stream: TcpStream) {
        println!("Request from {}, creat new tunnel.",
                 stream.peer_addr().unwrap());

        let mut tcp = TcpWrapper(stream.try_clone().unwrap());
        let (sender, receiver) = mpsc::channel();

        let cloned_sender = sender.clone();
        thread::spawn(move || {
            monitor(TcpWrapper(stream), cloned_sender);
        });

        thread::spawn(move || {
            handler(tcp, receiver, sender);
        });
    }
}

trait ParseStream<T> {
    fn parse_stream(&mut self) -> Option<T>;
}

impl ParseStream<ClientMsg> for TcpWrapper {
    fn parse_stream(&mut self) -> Option<ClientMsg> {
        match self.read_u8() {
            Ok(cs::HEARTBEAT) => Some(ClientMsg::HeartBeat),

            Ok(op) => {
                let id = self.read_u32().unwrap();
                match op {
                    cs::OPEN_PORT => Some(ClientMsg::OpenPort(id)),

                    cs::CONNECT => {
                        let buf = self.read_u32()
                            .and_then(|size| self.read_size(size as usize))
                            .unwrap();
                        Some(ClientMsg::Connect(id, buf))
                    },

                    cs::CONNECT_DOMAIN_NAME => {
                        let buf = self.read_u32()
                            .and_then(|size| self.read_size(size as usize))
                            .unwrap();
                        let port = self.read_u16().unwrap();
                        Some(ClientMsg::ConnectDN(id, buf, port))
                    },

                    cs::DATA => {
                        let buf = self.read_u32()
                            .and_then(|size| self.read_size(size as usize))
                            .unwrap();
                        Some(ClientMsg::Data(id, buf))
                    },

                    cs::SHUTDOWN_WRITE => Some(ClientMsg::ShutdownWrite(id)),
                    
                    _ => None,
                }
            },

            Err(_) => None,
        }
    }
}

enum Msg {
    Server(ServerMsg),
    Client(ClientMsg),
    Shutdown,
}

fn monitor(mut tcp: TcpWrapper, handler: Sender<Msg>) {
    let mut alive_time = get_time();
    loop {
        let duration = get_time() - alive_time;
        if duration.num_milliseconds() > ALIVE_TIMEOUT_TIME_MS {
            println!("tunnel timeout");
            break
        }
        match tcp.parse_stream() {
            Some(msg) => {
                // TODO: decrypt data here
                handler.send(Msg::Client(msg));
                alive_time = get_time();
            },

            None => {
                println!("client error");
                break
            },
        }
    }
    let _ = handler.send(Msg::Shutdown);
    let _ = tcp.shutdown_read();
}

fn handler(mut tcp: TcpWrapper, receiver: Receiver<Msg>, sender: Sender<Msg>) {
    let mut ports = PortMap::new();
    loop {
        match receiver.recv() {
            Ok(Msg::Client(c_msg)) => {
                match c_msg {
                    ClientMsg::HeartBeat => {
                        let _ = tcp.send(ServerMsg::HeartBeatRsp);
                    },

                    ClientMsg::OpenPort(id) => {
                        let _ = ports.add(id);
                    },

                    // TODO: If a port action failed, drop the port.
                    ClientMsg::Connect(id, buf) => {
                        // FIXME: This is ugly. If parsing failed, it doesn't
                        // response correctly.
                        // Maybe I can merge Connect and ConnectDN.
                        if let Some(SocketAddr::V4(addr)) = parse_domain_name(buf) {
                            ports.connect(id, addr, sender.clone());
                        }
                    },

                    ClientMsg::ConnectDN(id, dn, port) => {
                        ports.connect_dn(id, dn, port, sender.clone());
                    },

                    ClientMsg::Data(id, buf) => {
                        ports.send_data(id, buf);
                    },

                    ClientMsg::ShutdownWrite(id) => {
                        let _ = ports.shutdown_write(id);
                    },

                    ClientMsg::ClosePort(id) => {
                        let _ = ports.remove(id);
                    },
                }
            },

            Ok(Msg::Server(s_msg)) => {
                // TODO: crypt data here
                tcp.send(s_msg);
            },

            Ok(Msg::Shutdown) => {
                println!("shutting down");
                break
            },

            Err(_) => break,
        }
    }
    let _ = tcp.shutdown_write();
}

enum PortMsg {
    Data(Vec<u8>),
    ShutdownWrite,
}

struct PortMap(HashMap<Id, TunnelPort>);

struct TunnelPort(Option<SyncSender<PortMsg>>);

impl TunnelPort {
    fn send_data(&self, buf: Vec<u8>) {
        if let Some(ref sender) = self.0 {
            sender.send(PortMsg::Data(buf));
        }
    }

    fn shutdown_write(&self) {
        if let Some(ref sender) = self.0 {
            sender.send(PortMsg::ShutdownWrite);
        }
    }

    fn set_sender(&mut self, sender: SyncSender<PortMsg>) {
        self.0 = Some(sender);
    }

}

impl PortMap {
    fn new() -> PortMap {
        PortMap(HashMap::new())
    }

    fn add(&mut self, id: Id) {
        let port = TunnelPort(None);
        self.0.insert(id, port);
    }

    fn remove(&mut self, id: Id) {
        self.0.remove(&id);
    }

    fn get(&self, id: Id) -> Option<&TunnelPort> {
        self.0.get(&id)
    }

    fn get_mut(&mut self, id: Id) -> Option<&mut TunnelPort> {
        self.0.get_mut(&id)
    }

    fn connect(&mut self, id: Id, addr: SocketAddrV4, handler: Sender<Msg>) {
        let mut buf: Vec<u8> = Vec::new();
        if let Some(port) = self.get_mut(id) {
            let (sender, receiver) = mpsc::sync_channel(1000);
            port.set_sender(sender);

            // Connect in a new thread, to avoid the connect action blocking the
            // main thread.
            thread::spawn(move || {
                if let Ok(stream) = TcpStream::connect(addr) {
                    write!(buf, "{}", stream.local_addr().unwrap());
                    // Send before copy, to avoid blocking
                    handler.send(Msg::Server(ServerMsg::ConnectOK(id, buf)));
                    copy_stream(id, stream, receiver, handler);
                } else {
                    // Connect failed.
                    handler.send(Msg::Server(ServerMsg::ConnectOK(id, buf)));
                }
            });
        } else { // can't find a port with the very id.
            handler.send(Msg::Server(ServerMsg::ConnectOK(id, buf)));
        }
    }

    fn connect_dn(&mut self, id: Id, dn: DomainName, port: Port,
                  handler: Sender<Msg>) {
        if let Some(SocketAddr::V4(addr)) = parse_domain_name_with_port(dn, port) {
            self.connect(id, addr, handler);
        } else {
            let buf = Vec::new();
            handler.send(Msg::Server(ServerMsg::ConnectOK(id, buf)));
        }
    }

    fn send_data(&mut self, id: Id, data: Vec<u8>) {
        if let Some(port) = self.get(id) {
            port.send_data(data);
        }
    }

    fn shutdown_write(&mut self, id: Id) {
        if let Some(port) = self.get(id) {
            port.shutdown_write();
        }
    }

}

struct MsgSender(Id, Sender<Msg>);

impl SenderWithId<Msg> for MsgSender {
    fn get_id(&self) -> Id { self.0 }

    fn get_sender(&self) -> &Sender<Msg> { &self.1 }
}

impl Write for MsgSender {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        write_id_data(self, buf, |id, data|
                      Msg::Server(ServerMsg::Data(id, data)))
    }

    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

fn copy_stream(id: Id, stream: TcpStream, receiver: Receiver<PortMsg>,
               handler: Sender<Msg>) {
    let mut stream_read = stream.try_clone().unwrap();
    let mut handler = MsgSender(id, handler);
    thread::spawn(move || {
        io::copy(&mut stream_read, &mut handler);
        stream_read.shutdown(Shutdown::Read).unwrap();
        handler.get_sender().send(Msg::Server(ServerMsg::ShutdownWrite(id)));
    });

    let mut stream_write = stream;
    loop {
        match receiver.recv() {
            Ok(PortMsg::Data(buf)) => {
                if stream_write.write(&buf[..]).is_err() {
                    stream_write.shutdown(Shutdown::Both);
                    break
                }
            },

            Ok(PortMsg::ShutdownWrite) => {
                stream_write.shutdown(Shutdown::Write);
                break
            },

            Err(_) => {
                stream_write.shutdown(Shutdown::Both);
                break
            },
        }
    }
}

impl WriteTcp<ServerMsg> for TcpWrapper {
    fn send(&mut self, msg: ServerMsg) -> Result<()> {
        match msg {
            ServerMsg::HeartBeatRsp => self.write_u8(sc::HEARTBEAT_RSP),

            ServerMsg::ConnectOK(id, buf) => {
                self.write_u8(sc::CONNECT_OK)
                    .and(self.write_u32(id))
                    .and(self.write_u32(buf.len() as u32))
                    .and(self.write(&buf))
            },

            ServerMsg::Data(id, buf) => {
                self.write_u8(sc::DATA)
                    .and(self.write_u32(id))
                    .and(self.write_u32(buf.len() as u32))
                    .and(self.write(&buf))
            },

            ServerMsg::ShutdownWrite(id) => {
                self.write_u8(sc::SHUTDOWN_WRITE)
                    .and(self.write_u32(id))
            },

            ServerMsg::ClosePort(id) => {
                self.write_u8(sc::CLOSE_PORT)
                    .and(self.write_u32(id))
            },
        }
    }
}
