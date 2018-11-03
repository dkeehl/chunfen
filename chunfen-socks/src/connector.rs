use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::io::{self, Read, Write};
use std::str::from_utf8;

use futures::future;
use futures::{Future, Poll};
use tokio_core::net::TcpStream;
use tokio_core::reactor::Handle;
use tokio_io::{AsyncRead, AsyncWrite};

use crate::{DomainName, Port};
use crate::utils::*;

// Open a tcp connection to out bound
pub trait Connector: AsyncRead + AsyncWrite + 'static + Sized {
    fn connect(self, addr: &SocketAddrV4, handle: &Handle)
        -> Box<Future<Item = Option<(Self, SocketAddr)>, Error = io::Error>>;

    fn connect_dn(self, dn: DomainName, port: Port, handle: &Handle)
        -> Box<Future<Item = Option<(Self, SocketAddr)>, Error = io::Error>>
    {
        match try_parse_domain_name(dn, port) {
            Some(SocketAddr::V4(addr)) => Box::new(self.connect(&addr, handle)),
            Some(_) => unimplemented!(),
            None => Box::new(future::err(
                    io::Error::new(io::ErrorKind::InvalidData, "invalid domain name")))
        }
    }
}

fn try_parse_domain_name(buf: DomainName, port: Port) -> Option<SocketAddr> {
    let string = from_utf8(&buf[..]).unwrap_or("");
    let mut addr = (string, port).to_socket_addrs().unwrap();
    addr.nth(0)
}

pub struct SimpleConnector(pub Option<TcpStream>);

impl Read for SimpleConnector {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self.0 {
            Some(ref mut rd) => rd.read(buf),
            None => Err(not_connected()),
        }
    }
}

impl AsyncRead for SimpleConnector {}

impl Write for SimpleConnector {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self.0 {
            Some(ref mut wt) => wt.write(buf),
            None => Err(not_connected()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self.0 {
            Some(ref mut wt) => wt.flush(),
            None => Err(not_connected()),
        }
    }
}

impl AsyncWrite for SimpleConnector {
    fn shutdown(&mut self) -> Poll<(), io::Error> {
        match self.0 {
            Some(ref mut wt) => AsyncWrite::shutdown(wt),
            None => Err(not_connected()),
        }
    }
}

impl Connector for SimpleConnector {

    fn connect(self, addr: &SocketAddrV4, handle: &Handle)
        -> Box<Future<Item = Option<(Self, SocketAddr)>, Error = io::Error>>
    {
        let stream = TcpStream::connect(&SocketAddr::V4(*addr), handle)
            .map(|tcp| {
                let addr = tcp.local_addr().unwrap();
                Some((SimpleConnector(Some(tcp)), addr))
            }).or_else(|_| {
                future::ok(None)
            });
        boxup(stream)
    }
}

