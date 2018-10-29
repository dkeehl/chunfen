use std::net::{self, TcpListener, SocketAddr, SocketAddrV4};
use std::io::{self, Write};
use std::collections::HashMap;

use time::{Timespec, get_time};
use tokio_core::reactor::{Core, Handle};
use tokio_core::net::TcpStream;
use tokio_io::{AsyncRead, AsyncWrite};
use futures::future;
use futures::{Sink, Stream, Future, Poll, Async};
use futures::sync::mpsc::{self, Receiver, Sender};
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
            // Block. One tunnel at a time.
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
        let (sender, receiver) = mpsc::channel(1000);

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

        loop {
            match self.client.poll()? {
                Async::Ready(Some(c_msg)) => {
                    //println!("get client message {}", c_msg);
                    self.process_client_msg(c_msg);
                    self.alive_time = get_time();
                },
                // Client EOF
                Async::Ready(None) => return self.client.poll_flush(),
                Async::NotReady => break,
            }
        }

        loop {
            match self.connections.poll().unwrap() {
                Async::Ready(Some(msg)) => self.process_port_msg(msg),
                // We always have a sender in the tunnel.
                Async::Ready(None) => unreachable!(),
                Async::NotReady => break,
            }
        }
        let _ = self.client.poll_flush()?;
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
            ClientMsg::Connect(id, buf) => {
                if let Some(addr) = parse_domain_name(buf) {
                    self.ports.connect(id, addr);
                } else {
                    self.client.buffer_msg(connection_fail(id));
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

fn connection_fail(id: Id) -> ServerMsg {
    ServerMsg::ConnectOK(id, Bytes::new())
}

struct PortMap {
    // a port is created after it connected.
    ports: HashMap<Id, Option<Sender<ToPort>>>,
    // For making new ports.
    sender: Sender<FromPort<ServerMsg>>,
    handle: Handle
}

impl PortMap {
    // TODO: If a port action failed, drop the port.
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

    fn connect(&mut self, id: Id, addr: SocketAddr)  {
        let handle = self.handle.clone();
        let (sender, port) = TunnelPort::new(id, self.sender.clone(), &handle);
        let _ = self.ports.insert(id, Some(sender));

        // Spawn a new task to connect, to avoid the connect action blocking the
        // main thread.
        let connect = TcpStream::connect(&addr, &handle);
        let proxing = connect.then(move |res| {
            match res {
                Ok(stream) => {
                    let bind_addr = format!("{}", stream.local_addr().unwrap());
                    //println!("{}", bind_addr);
                    let buf = Bytes::from(bind_addr.as_bytes());
                    port.send_raw(ServerMsg::ConnectOK(id, buf));

                    Box::new(drop_res!(pipe(stream, port, handle)))
                        as Box<Future<Item=(), Error=()>>
                },
                Err(_) => {
                    port.send_raw(connection_fail(id));
                    Box::new(future::ok(())) as Box<Future<Item=(), Error=()>>
                },
            }
        });
        self.handle.spawn(proxing);
    }

    fn connect_dn(&mut self, id: Id, dn: DomainName, port: Port) {
        if let Some(addr) = parse_domain_name_with_port(dn, port) {
            self.connect(id, addr);
        } else {
            let send = self.sender.clone()
                .send(FromPort::Payload(connection_fail(id)));
            self.handle.spawn(drop_res!(send))
        }
    }

    fn send_to_port(&self, id: Id, msg: ToPort) {
        if let Some(Some(port)) = self.ports.get(&id) {
            let send = port.clone().send(msg);
            self.handle.spawn(drop_res!(send))
        }
    }

    fn send_data(&mut self, id: Id, data: Bytes) {
         self.send_to_port(id, ToPort::Data(data))
    }

    fn shutdown_write(&mut self, id: Id) {
         self.send_to_port(id, ToPort::ShutdownWrite)
    }
}
