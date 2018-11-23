// Tunnel Port
use std::io::{self, Write, Read};

use tokio_io::AsyncRead;
use tokio_tcp::TcpStream;
use futures::{Sink, Stream, Future, Poll, Async};
use futures::sync::mpsc::{self, Sender, Receiver};
use bytes::Bytes;

use chunfen_socks::{ShutdownWrite, pipe};
use chunfen_socks::connector::{Connector, SocksAddr, to_socket_addr_with,
system_dns_lookup};

use crate::utils::{Id, tunnel_broken};
use crate::protocol::Msg;

#[derive(Debug)]
pub enum ToPort {
    Connected(SocksAddr),
    Failed,
    Data(Bytes),
    ShutdownWrite,
}

pub struct TunnelPort {
    id: Id,
    sender: Sender<Msg>,
    receiver: Receiver<ToPort>,
    buffer: Option<Bytes>,
    eof: bool,
}

impl TunnelPort {
    pub fn new(id: Id, sender: Sender<Msg>) -> (Sender<ToPort>, TunnelPort) {
        let (tx, rx) = mpsc::channel(10);
        let port = TunnelPort {
            id,
            sender,
            receiver: rx,
            buffer: None,
            eof: false,
        };
        (tx, port)
    }

    pub fn connect_and_proxy(self, addr: SocksAddr)
        -> impl Future<Item=(), Error=()> + Send
    {
        let sender = self.sender.clone();
        let id = self.id;
        to_socket_addr_with(addr, system_dns_lookup).and_then(|addr| {
            TcpStream::connect(&addr)
        }).then(move |res| {
            match res {
                Ok(stream) => {
                    let addr = SocksAddr::from_socket_addr(stream.local_addr().unwrap());
                    let fut = sender.send(Msg::Success(id, addr)).map(|_| {
                        pipe(stream, self)
                    }).map_err(|_| ());
                    Box::new(fut) as Box<Future<Item=(), Error=()> + Send>
                },
                Err(e) => {
                    trace!("Error when connecting port {}: {}", id, e);
                    let fut = sender.send(Msg::Fail(id)); 
                    Box::new(drop_res!(fut)) as Box<Future<Item=(), Error=()> + Send>
                },
            }
        })
    }

    fn to_connect_future(self) -> PortConnectFuture {
        PortConnectFuture(Some(self))
    }

    // Send a message to the tunnel core.
    pub fn send(&self, msg: Msg)
        -> impl Future<Item=(), Error=io::Error> + Send
    {
        self.sender.clone()
            .send(msg)
            .map(|_| ())
            .map_err(|_| tunnel_broken(""))
    }
}

struct PortConnectFuture(Option<TunnelPort>);

impl Future for PortConnectFuture {
    type Item = (TunnelPort, SocksAddr);
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, io::Error> {
        let addr = match self.0 {
            Some(ref mut port) => {
                match port.receiver.poll().unwrap() {
                    Async::Ready(Some(ToPort::Connected(addr))) => addr,
                    Async::NotReady => return Ok(Async::NotReady),
                    _ => return Err(connection_fail()),
                }
            },
            _ => unreachable!("polling a dummy tunnel port future"),
        };
        let port = self.0.take().unwrap();
        Ok((port, addr).into())
    }
}

impl Connector for TunnelPort {
    type Remote = Self;

    fn connect(self, addr: SocksAddr)
        -> Box<Future<Item=(Self, SocksAddr), Error=io::Error> + Send>
    {
        let fut = self.send(Msg::Connect(self.id, addr)).and_then(|_| {
            self.to_connect_future()
        });
        Box::new(fut)
    }
}

macro_rules! ready_sender_mut {
    ($sender: expr) => {
        match $sender.poll_ready() {
            Ok(Async::Ready(_)) => &mut $sender,
            Ok(Async::NotReady) => return Err(would_block()),
            Err(_) => return Err(tunnel_broken("")),
        }
    }
}

impl Write for TunnelPort {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let sender = ready_sender_mut!(self.sender);
        let len = buf.len();
        let data = Bytes::from(buf);
        sender.try_send(Msg::Data(self.id, data)).unwrap();
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

impl Read for TunnelPort {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while !self.eof && self.buffer.is_none() {
            // Polling a receiver never gets an error.
            match self.receiver.poll().unwrap() {
                Async::Ready(Some(msg)) => {
                    match msg {
                        ToPort::Data(buf) => self.buffer = Some(buf),
                        ToPort::ShutdownWrite => {
                            self.receiver.close();
                            self.eof = true
                        },
                        _ => {},
                    }
                },
                Async::Ready(None) => self.eof = true,
                Async::NotReady => break,
            }
        }
        match (self.buffer.take(), self.eof) {
            (Some(mut data), _) => {
                let len = data.len().min(buf.len());
                assert!(len > 0);
                buf[..len].copy_from_slice(&data.split_to(len));
                if !data.is_empty() {
                    self.buffer = Some(data)
                }
                Ok(len)
            },
            (None, false) => Err(would_block()),
            (None, true) => Ok(0),
        }
    }
}

impl AsyncRead for TunnelPort {}

impl ShutdownWrite for TunnelPort {
    fn shutdown_write(&mut self) -> io::Result<()> {
        let sender = ready_sender_mut!(self.sender);
        sender.try_send(Msg::ShutdownWrite(self.id)).unwrap();
        Ok(())
    }
}

impl Drop for TunnelPort {
    fn drop(&mut self) {
        // TODO: handle TrySendError
        let _ = self.sender.try_send(Msg::ClosePort(self.id));
    }
}

fn would_block() -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, "")
}

fn connection_fail() -> io::Error {
    io::Error::new(io::ErrorKind::Other, "can't connect")
}

