//
// Tunnel Port
use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::mem;
use std::sync::mpsc::Sender;
use std::io::{self, Write, Read};
use std::str::from_utf8;

use tokio_core::reactor::Handle;
use tokio_io::{AsyncRead, AsyncWrite};
use futures::future;
use futures::{Stream, Future, Poll, Async};
use futures::sync::mpsc::{unbounded, UnboundedSender, UnboundedReceiver};
use bytes::{Bytes, BufMut, BytesMut};

use {DomainName, Port, Id};
use socks::Connector;
use protocol::ClientMsg;

#[derive(Debug)]
pub enum FromPort {
    NewPort(Id, UnboundedSender<ToPort>),
    Client(ClientMsg),
}

#[derive(Debug)]
pub enum ToPort {
    ConnectOK(Bytes),
    Data(Bytes),
    ShutdownWrite,
    Close,
}

pub struct TunnelPort {
    id: Id,
    sender: Sender<FromPort>,
    receiver: UnboundedReceiver<ToPort>,
    buffer: BytesMut,
    eof: bool
}

impl TunnelPort {
    pub fn new(id: Id, sender: Sender<FromPort>)
        -> (UnboundedSender<ToPort>, TunnelPort)
    {
        let (tx, rx) = unbounded();
        let port = TunnelPort {
            id,
            sender,
            receiver:  rx,
            buffer: BytesMut::new(),
            eof: false,
        };
        (tx, port)
    }

    fn to_connect_future(self) -> PortConnectFuture {
        PortConnectFuture(Some(self))
    }
}

struct PortConnectFuture(Option<TunnelPort>);

impl Future for PortConnectFuture {
    type Item = Option<(TunnelPort, SocketAddr)>;
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
            let port = mem::replace(&mut self.0, None).unwrap();
            (port, addr)
        })))
    }
}

impl Connector for TunnelPort {
    fn connect(self, addr: &SocketAddrV4, _: &Handle)
        -> Box<Future<Item = Option<(Self, SocketAddr)>, Error = io::Error>>
    {
        let addr = format!("{}", addr);
        let buf = Bytes::from(&addr.into_bytes()[..]);
        self.sender.send(FromPort::Client(ClientMsg::Connect(self.id, buf)));

        Box::new(self.to_connect_future())
    }

    fn connect_dn(self, dn: DomainName, port: Port, _: &Handle)
        -> Box<Future<Item = Option<(Self, SocketAddr)>, Error = io::Error>>
    {
        self.sender.send(FromPort::Client(ClientMsg::ConnectDN(self.id, dn, port)));
        Box::new(self.to_connect_future())
    }
}

fn try_get_binded_addr(buf: &[u8]) -> Option<SocketAddr> {
    let string = from_utf8(buf).unwrap_or("");
    string.to_socket_addrs().ok()
        .and_then(|mut addr_iter| addr_iter.nth(0))
}

impl Write for TunnelPort {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = buf.len();
        let data = Bytes::from(buf);
        // println!("client data size {}", data.len());
        self.sender.send(FromPort::Client(ClientMsg::Data(self.id, data)));
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}

impl Read for TunnelPort {
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

impl AsyncRead for TunnelPort {}

impl AsyncWrite for TunnelPort {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        self.sender.send(FromPort::Client(ClientMsg::ShutdownWrite(self.id)));
        self.sender.send(FromPort::Client(ClientMsg::ClosePort(self.id)));
        Ok(Async::Ready(()))
    }
}
