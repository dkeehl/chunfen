// Tunnel Port
use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::io::{self, Write, Read};
use std::str::from_utf8;
use std::fmt::Debug;

use tokio_io::AsyncRead;
use futures::{Sink, Stream, Future, Poll, Async};
use futures::sync::mpsc::{self, Sender, Receiver};
use bytes::Bytes;

use chunfen_socks::{ShutdownWrite, Connector};

use crate::utils::{DomainName, Port, Id};
use crate::protocol::ClientMsg;

#[derive(Debug)]
pub enum FromPort<T: Debug + Send + 'static> {
    Data(Id, Bytes),
    ShutdownWrite(Id),
    Close(Id),

    Payload(T),
}

#[derive(Debug)]
pub enum ToPort {
    HeartBeat,
    Open,
    Connect(Bytes),
    ConnectDN(DomainName, Port),
    ConnectOK(Bytes),
    Data(Bytes),
    ShutdownWrite,
    Close,
}

pub struct TunnelPort<T: Debug + Send + 'static> {
    id: Id,
    sender: Sender<FromPort<T>>,
    receiver: Receiver<ToPort>,
    buffer: Option<Bytes>,
    eof: bool,
}

impl<T: Debug + Send + 'static> TunnelPort<T> {
    pub fn new(id: Id, sender: Sender<FromPort<T>>)
        -> (Sender<ToPort>, TunnelPort<T>)
    {
        let (tx, rx) = mpsc::channel(10);
        let port = TunnelPort {
            id,
            sender,
            receiver:  rx,
            buffer: None,
            eof: false,
        };
        (tx, port)
    }

    fn to_connect_future(self) -> PortConnectFuture<T> {
        PortConnectFuture(Some(self))
    }

    pub fn send_raw(&self, msg: T)
        -> impl Future<Item=(), Error=io::Error> + Send
    {
        self.sender.clone()
            .send(FromPort::Payload(msg))
            .map(|_| ())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, ""))
    }
}

struct PortConnectFuture<T: Debug + Send + 'static>(Option<TunnelPort<T>>);

impl<T: Debug + Send + 'static> Future for PortConnectFuture<T> {
    type Item = Option<(TunnelPort<T>, SocketAddr)>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, io::Error> {
        let res = match self.0 {
            Some(ref mut port) => {
                match port.receiver.poll().unwrap() {
                    Async::Ready(Some(ToPort::ConnectOK(buf))) =>
                        try_get_binded_addr(&buf),
                    Async::NotReady => return Ok(Async::NotReady),
                    _ => None,
                }
            },
            _ => unreachable!("polling a dummy tunnel port future"),
        };
        Ok(Async::Ready(res.map(|addr| {
            let port = self.0.take().unwrap();
            (port, addr)
        })))
    }
}

impl Connector for TunnelPort<ClientMsg> {
    type Remote = Self;

    fn connect(self, addr: &SocketAddrV4)
        -> Box<Future<Item=Option<(Self, SocketAddr)>, Error=io::Error> + Send>
    {
        let addr = format!("{}", addr);
        let buf = Bytes::from(addr.as_bytes());
        let fut = self.send_raw(ClientMsg::Connect(self.id, buf)).and_then(|_| {
            self.to_connect_future()
        });
        Box::new(fut)
    }

    fn connect_dn(self, dn: DomainName, port: Port)
        -> Box<Future<Item=Option<(Self, SocketAddr)>, Error=io::Error> + Send>
    {
        let fut = self.send_raw(ClientMsg::ConnectDN(self.id, dn, port)).and_then(|_| {
            self.to_connect_future()
        });
        Box::new(fut)
    }
}

fn try_get_binded_addr(buf: &[u8]) -> Option<SocketAddr> {
    let string = from_utf8(buf).unwrap_or("");
    string.to_socket_addrs().ok()
        .and_then(|mut addr_iter| addr_iter.nth(0))
}

macro_rules! ready_sender_mut {
    ($sender: expr) => {
        match $sender.poll_ready() {
            Ok(Async::Ready(_)) => &mut $sender,
            Ok(Async::NotReady) => return Err(would_block()),
            Err(_) => return Err(io::Error::new(io::ErrorKind::BrokenPipe, "")),
        }
    }
}

impl<T: Debug + Send + 'static> Write for TunnelPort<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let sender = ready_sender_mut!(self.sender);
        let len = buf.len();
        let data = Bytes::from(buf);
        sender.try_send(FromPort::Data(self.id, data)).unwrap();
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

impl<T: Debug + Send + 'static> Read for TunnelPort<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while !self.eof && self.buffer.is_none() {
            // Polling a receiver never gets an error.
            match self.receiver.poll().unwrap() {
                Async::Ready(Some(msg)) => {
                    match msg {
                        ToPort::Data(buf) => self.buffer = Some(buf),
                        ToPort::ShutdownWrite => self.eof = true,
                        ToPort::Close     => unreachable!(),
                        _ => {},
                    }
                },
                Async::Ready(None) => self.eof = true,
                Async::NotReady => break,
            }
        }
        match (self.buffer.is_some(), self.eof) {
            (true, _) => {
                let mut data = self.buffer.take().unwrap();
                let len = data.len().min(buf.len());
                assert!(len > 0);
                buf[..len].copy_from_slice(&data.split_to(len));
                if !data.is_empty() {
                    self.buffer = Some(data)
                }
                Ok(len)
            },
            (false, false) => Err(would_block()),
            (false, true) => Ok(0),
        }
    }
}

impl<T: Debug + Send + 'static> AsyncRead for TunnelPort<T> {}

impl<T: Debug + Send + 'static> ShutdownWrite for TunnelPort<T> {
    fn shutdown_write(&mut self) -> io::Result<()> {
        let sender = ready_sender_mut!(self.sender);
        sender.try_send(FromPort::ShutdownWrite(self.id)).unwrap();
        Ok(())
    }
}

impl<T: Debug + Send + 'static> Drop for TunnelPort<T> {
    fn drop(&mut self) {
        // TODO: handle TrySendError
        let _ = self.sender.try_send(FromPort::Close(self.id));
    }
}

fn would_block() -> io::Error {
    io::Error::new(io::ErrorKind::WouldBlock, "")
}
