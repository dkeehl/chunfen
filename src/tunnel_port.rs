//
// Tunnel Port
use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::io::{self, Write, Read};
use std::str::from_utf8;
use std::fmt::Debug;

use tokio_current_thread::Handle;
use tokio_io::{AsyncRead, AsyncWrite};
use futures::future;
use futures::{Sink, Stream, Future, Poll, Async};
use futures::sync::mpsc::{self, Sender, Receiver};
use bytes::{Bytes, BufMut, BytesMut};

use chunfen_socks::{ShutdownWrite, Connector};

use crate::utils::{DomainName, Port, Id};
use crate::protocol::ClientMsg;

#[derive(Debug)]
pub enum FromPort<T: Debug + Send + 'static> {
    NewPort(Id, Sender<ToPort>),
    Data(Id, Bytes),
    ShutdownWrite(Id),
    Close(Id),

    Payload(T),
}

#[derive(Debug)]
pub enum ToPort {
    ConnectOK(Bytes),
    Data(Bytes),
    ShutdownWrite,
    Close,
}

pub struct TunnelPort<T: Debug + Send + 'static> {
    id: Id,
    handle: Handle,
    sender: Sender<FromPort<T>>,
    receiver: Receiver<ToPort>,
    buffer: BytesMut,
    eof: bool
}

impl<T: Debug + Send + 'static> TunnelPort<T> {
    pub fn new(id: Id, sender: Sender<FromPort<T>>, handle: &Handle)
        -> (Sender<ToPort>, TunnelPort<T>)
    {
        let (tx, rx) = mpsc::channel(10);
        let port = TunnelPort {
            id,
            handle: handle.clone(),
            sender,
            receiver:  rx,
            buffer: BytesMut::new(),
            eof: false,
        };
        (tx, port)
    }

    fn to_connect_future(self) -> PortConnectFuture<T> {
        PortConnectFuture(Some(self))
    }

    pub fn send_raw(&self, msg: T) {
        self.send(FromPort::Payload(msg))
    }

    fn send(&self, msg: FromPort<T>) {
        let send = self.sender.clone().send(msg)
            .map(|_| ())
            .map_err(|e| println!("port failed to send {:?}", e.into_inner()));
        let _ = self.handle.spawn(send);
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
        -> Box<Future<Item = Option<(Self, SocketAddr)>, Error = io::Error>>
    {
        let addr = format!("{}", addr);
        let buf = Bytes::from(addr.as_bytes());
        //println!("port {} will connect", self.id);
        self.send_raw(ClientMsg::Connect(self.id, buf));

        Box::new(self.to_connect_future())
    }

    fn connect_dn(self, dn: DomainName, port: Port)
        -> Box<Future<Item = Option<(Self, SocketAddr)>, Error = io::Error>>
    {
        self.send_raw(ClientMsg::ConnectDN(self.id, dn, port));
        Box::new(self.to_connect_future())
    }
}

fn try_get_binded_addr(buf: &[u8]) -> Option<SocketAddr> {
    let string = from_utf8(buf).unwrap_or("");
    string.to_socket_addrs().ok()
        .and_then(|mut addr_iter| addr_iter.nth(0))
}

impl<T: Debug + Send + 'static> Write for TunnelPort<T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = buf.len();
        let data = Bytes::from(buf);
        // println!("client data size {}", data.len());
        self.send(FromPort::Data(self.id, data));
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

impl<T: Debug + Send + 'static> Read for TunnelPort<T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        while !self.eof {
            match self.receiver.poll().unwrap() {
                Async::Ready(Some(msg)) => {
                    match msg {
                        ToPort::Data(buf) => self.buffer.extend_from_slice(&buf),
                        ToPort::ShutdownWrite |
                        ToPort::Close     => self.eof = true,
                        _ => {},
                    }
                },
                // TODO: Unexpected EOF
                Async::Ready(None) => self.eof = true,
                Async::NotReady => break,
            }
        }
        match (self.buffer.is_empty(), self.eof) {
            (false, _) => {
                let len = self.buffer.len().min(buf.len());
                buf[..len].copy_from_slice(&self.buffer[..len]);
                self.buffer.advance(len);
                Ok(len)
            },
            (true, false) =>
                Err(io::Error::new(io::ErrorKind::WouldBlock, "blocked")),
            (true, true) => Ok(0),
        }
    }
}

impl<T: Debug + Send + 'static> AsyncRead for TunnelPort<T> {}

impl<T: Debug + Send + 'static> ShutdownWrite for TunnelPort<T> {
    fn shutdown_write(&mut self) -> io::Result<()> {
        self.send(FromPort::ShutdownWrite(self.id));
        Ok(())
    }
}

impl<T: Debug + Send + 'static> Drop for TunnelPort<T> {
    fn drop(&mut self) {
        self.send(FromPort::Close(self.id));
    }
}

