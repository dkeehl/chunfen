use std::net::{self, TcpListener, SocketAddr, SocketAddrV4, Shutdown};
use std::sync::mpsc::{self, Sender, Receiver, SyncSender, TryRecvError};
use std::thread;
use std::io;
use std::io::Write;
use std::collections::HashMap;

use time::{Timespec, get_time};
use tokio_core::reactor::{Core, Handle};
use tokio_core::net::TcpStream;
use tokio_io::{AsyncRead, AsyncWrite};
use futures::future;
use futures::{Stream, Future, Poll, Async};
use futures::sync::mpsc::UnboundedSender;
use bytes::{BufMut, BytesMut, Bytes};
use nom::Err::Incomplete;

use {Id, DomainName, Port}; 
use socks::pipe;
use protocol::{ServerMsg, ClientMsg, ALIVE_TIMEOUT_TIME_MS};
use utils::*;
use framed::Framed;
use tunnel_port::{TunnelPort, FromPort, ToPort};

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

struct Tunnel {
    client: Framed<ClientMsg, ServerMsg>,
    alive_time: Timespec,
    ports: PortMap,
    connections: Receiver<FromPort<ServerMsg>>,
}

impl Tunnel {
    fn new(stream: net::TcpStream) {
        println!("Request from {}, creat new tunnel.",
                 stream.peer_addr().unwrap());

        let mut lp = Core::new().unwrap();
        let handle = lp.handle();

        let mut stream = TcpStream::from_stream(stream, &handle).unwrap();
        let (sender, receiver) = mpsc::channel();

        let tunnel = Tunnel {
            client: Framed::new(stream),
            alive_time: get_time(),
            ports: PortMap::new(sender, handle),
            connections: receiver,
        };

        match lp.run(tunnel) {
            Ok(_) => println!("peer at eof, quit"),
            Err(e) => println!("an error occured: {}, tunnel broken", e),
        }
    }
}

impl Future for Tunnel {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(), io::Error> {
        let dur = get_time() - self.alive_time;
        if dur.num_milliseconds() > ALIVE_TIMEOUT_TIME_MS {
            //println!("Client timeout.");
            return self.client.poll_flush()
        }

        let mut read_ready = true;
        let mut msg_ready = true;
        while read_ready | msg_ready {
            if read_ready {
                match self.client.poll()? {
                    Async::Ready(Some(c_msg)) => {
                        //println!("get client message {}", c_msg);
                        self.process_client_msg(c_msg);
                        self.alive_time = get_time();
                    },
                    // Client EOF
                    Async::Ready(None) => return self.client.poll_flush(),
                    Async::NotReady => read_ready = false,
                }
            }

            if msg_ready {
                match self.connections.try_recv() {
                    Ok(msg) => self.process_port_msg(msg),
                    Err(TryRecvError::Empty) => msg_ready = false,
                    // We always have a sender in the tunnel.
                    Err(TryRecvError::Disconnected) => unreachable!(),
                }
            }

            self.client.poll_flush();
        }
        // here ready = false
        Ok(Async::NotReady)
    }
}

impl Tunnel {
    fn process_client_msg(&mut self, c_msg: ClientMsg) {
        match c_msg {
            ClientMsg::HeartBeat => {
                self.client.buffer_msg(ServerMsg::HeartBeatRsp);
            },
            ClientMsg::OpenPort(id) => self.ports.add(id),
            // TODO: If a port action failed, drop the port.
            ClientMsg::Connect(id, buf) => {
                // FIXME: This is ugly. If parsing failed, it doesn't
                // response correctly.
                // Maybe I can merge Connect and ConnectDN.
                if let Some(addr) = parse_domain_name(buf) {
                    self.ports.connect(id, addr);
                }
            },
            ClientMsg::ConnectDN(id, dn, port) => {
                self.ports.connect_dn(id, dn, port);
            },
            ClientMsg::Data(id, buf) => self.ports.send_data(id, buf),
            ClientMsg::ShutdownWrite(id) => {
                self.ports.shutdown_write(id);
            },
            ClientMsg::ClosePort(id) => self.ports.remove(id),
        }
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
        //println!("sending {}", s_msg);
        self.client.buffer_msg(s_msg)
    }
}

struct PortMap {
    // a port is created after it connected.
    ports: HashMap<Id, Option<UnboundedSender<ToPort>>>,
    // For making new ports.
    sender: Sender<FromPort<ServerMsg>>,
    handle: Handle
}

impl PortMap {
    fn new(sender: Sender<FromPort<ServerMsg>>, handle: Handle) -> PortMap {
        PortMap {
            ports: HashMap::new(),
            sender,
            handle
        }
    }
    
    fn add(&mut self, id: Id) {
        let _ = self.ports.insert(id, None);
    }

    fn remove(&mut self, id: Id) {
        let _ = self.ports.remove(&id);
    }

    fn len(&self) -> usize {
        self.ports.len()
    }

    fn connect(&mut self, id: Id, addr: SocketAddr)  {
        let (sender, port) = TunnelPort::new(id, self.sender.clone());
        let _ = self.ports.insert(id, Some(sender));

        // Connect in a new thread, to avoid the connect action blocking the
        // main thread.
        let connect = TcpStream::connect(&addr, &self.handle);
        let proxing = connect.and_then(move |stream| {
            let bind_addr = format!("{}", stream.local_addr().unwrap());
            //println!("{}", bind_addr);
            let buf = Bytes::from(bind_addr.as_bytes());
            port.send(ServerMsg::ConnectOK(id, buf));

            pipe(stream, port)
        }).map(|_| ()).map_err(|_| ());

        self.handle.spawn(proxing);
    }

    fn connect_dn(&mut self, id: Id, dn: DomainName, port: Port) {
        if let Some(addr) = parse_domain_name_with_port(dn, port) {
            self.connect(id, addr);
        } else {
            let buf = Bytes::new();
            self.sender.send(FromPort::Payload(ServerMsg::ConnectOK(id, buf)));
        }
    }

    fn send_data(&mut self, id: Id, data: Bytes) {
        if let Some(Some(port)) = self.ports.get(&id) {
            // Ports send close messages when dropped.
            // So it's safe to drop the send result.
            let _ = port.unbounded_send(ToPort::Data(data));
        }
    }

    fn shutdown_write(&mut self, id: Id) {
        if let Some(Some(port)) = self.ports.get(&id) {
            let _ = port.unbounded_send(ToPort::ShutdownWrite);
        }
    }
}
