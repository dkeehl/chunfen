use std::net::{SocketAddr, SocketAddrV4, ToSocketAddrs};
use std::io;
use std::str::from_utf8;

use futures::future;
use futures::Future;
use tokio_tcp::TcpStream;
use tokio_io::AsyncRead;

use crate::{DomainName, Port};
use crate::transfer::ShutdownWrite;
use crate::utils::*;

// Open a tcp connection to out bound
pub trait Connector: Sized {
    type Remote: AsyncRead + io::Write + ShutdownWrite + 'static;

    fn connect(self, addr: &SocketAddrV4)
        -> Box<Future<Item = Option<(Self::Remote, SocketAddr)>, Error = io::Error>>;

    fn connect_dn(self, dn: DomainName, port: Port)
        -> Box<Future<Item = Option<(Self::Remote, SocketAddr)>, Error = io::Error>>
    {
        match try_parse_domain_name(dn, port) {
            Some(SocketAddr::V4(addr)) => self.connect(&addr),
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

pub struct SimpleConnector;

impl Connector for SimpleConnector {
    type Remote = TcpStream;

    fn connect(self, addr: &SocketAddrV4)
        -> Box<Future<Item = Option<(TcpStream, SocketAddr)>, Error = io::Error>>
    {
        let stream = TcpStream::connect(&SocketAddr::V4(*addr))
            .map(|tcp| {
                let addr = tcp.local_addr().unwrap();
                Some((tcp, addr))
            }).or_else(|_| {
                future::ok(None)
            });
        boxup(stream)
    }
}

