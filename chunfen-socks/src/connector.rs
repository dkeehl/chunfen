use std::net::{SocketAddr, ToSocketAddrs, IpAddr, Ipv4Addr, Ipv6Addr};
use std::io::{self, Write};
use std::str::from_utf8;

use futures::future::{self, IntoFuture};
use futures::Future;
use tokio_tcp::TcpStream;
use tokio_io::AsyncRead;
use bytes::{BufMut, BytesMut};

use crate::transfer::ShutdownWrite;
use crate::utils::{boxup, invalid};

pub const ATYP_IP_V4: u8 = 1;
pub const ATYP_DOMAINNAME: u8 = 3;
pub const ATYP_IP_V6: u8 = 4;

#[derive(Debug, PartialEq, Eq)]
pub struct SocksAddr {
    pub(crate) addr: AddrKind,
    pub(crate) port: u16,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum AddrKind {
    Ipv4([u8; 4]),
    Ipv6([u8; 16]),
    DomainName(Vec<u8>),
}

impl SocksAddr {
    pub fn from_socket_addr(addr: SocketAddr) -> Self {
        match addr {
            SocketAddr::V4(addr_v4) => {
                SocksAddr {
                    addr: AddrKind::Ipv4(addr_v4.ip().octets()),
                    port: addr_v4.port(),
                }
            }
            SocketAddr::V6(addr_v6) => {
                SocksAddr {
                    addr: AddrKind::Ipv6(addr_v6.ip().octets()),
                    port: addr_v6.port(),
                }
            }
        }
    }

    pub fn encode(&self, buf: &mut BytesMut) {
        let SocksAddr { ref addr, port } = *self;
        match addr {
            AddrKind::Ipv4(l) => {
                buf.put_u8(ATYP_IP_V4);
                buf.put_slice(&l[..]);
                buf.put_u16_be(port);
            }
            AddrKind::Ipv6(l) => {
                buf.put_u8(ATYP_IP_V6);
                buf.put_slice(&l[..]);
                buf.put_u16_be(port);
            }
            AddrKind::DomainName(bytes) => {
                buf.put_u8(ATYP_DOMAINNAME);
                buf.put_u8(bytes.len() as u8);
                buf.extend_from_slice(&bytes[..]);
                buf.put_u16_be(port);
            }
        }
    }
}

// Open a tcp connection to out bound
pub trait Connector: Send + Sized {
    type Remote: AsyncRead + Write + ShutdownWrite + Send + 'static;

    fn connect(self, addr: SocksAddr)
        -> Box<Future<Item=(Self::Remote, SocksAddr), Error=io::Error> + Send>;
}

pub fn system_dns_lookup(dn: &str, port: u16) -> Result<SocketAddr, io::Error> {
    (dn, port).to_socket_addrs().and_then(|mut addr| {
        addr.nth(0).ok_or_else(|| {
            invalid("invalid domain name")
        })
    })
}

fn resolve_dn_with<F, T>(raw: &[u8], port: u16, dns: F)
    -> Box<Future<Item=SocketAddr, Error=io::Error> + Send>
    where F: FnOnce(&str, u16) -> T,
          T: IntoFuture<Item=SocketAddr, Error=io::Error>,
          <T as IntoFuture>::Future: Send + 'static
{
    let addr_str = match from_utf8(raw) {
        Ok(s) => s,
        Err(_) => {
            let fut = future::err(invalid("address is not utf8"));
            return boxup(fut)
        }
    };
    // just an ip
    if let Ok(ip) = addr_str.parse() {
        let fut = future::ok(SocketAddr::new(ip, port));
        return boxup(fut)
    }
    boxup(dns(&addr_str, port).into_future())
}

pub fn to_socket_addr_with<F, T>(addr: SocksAddr, dns: F)
    -> Box<Future<Item=SocketAddr, Error=io::Error> + Send>
    where F: FnOnce(&str, u16) -> T,
          T: IntoFuture<Item=SocketAddr, Error=io::Error>,
          <T as IntoFuture>::Future: Send + 'static
{
    let SocksAddr { addr, port } = addr;
    match addr {
        AddrKind::Ipv4(l) => {
            let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(l)), port);
            boxup(future::ok(socket))
        }
        AddrKind::Ipv6(l) => {
            let socket = SocketAddr::new(IpAddr::V6(Ipv6Addr::from(l)), port);
            boxup(future::ok(socket))
        }
        AddrKind::DomainName(bytes) => resolve_dn_with(&bytes[..], port, dns),
    }
}

pub struct SimpleConnector;

impl SimpleConnector {
    fn connect_socket(self, addr: &SocketAddr)
        -> impl Future<Item = (TcpStream, SocksAddr), Error = io::Error> + Send
    {
        TcpStream::connect(addr).map(|tcp| {
            let addr = tcp.local_addr().unwrap();
            (tcp, SocksAddr::from_socket_addr(addr))
        })
    }
}

impl Connector for SimpleConnector {
    type Remote = TcpStream;

    fn connect(self, addr: SocksAddr)
        -> Box<Future<Item=(Self::Remote, SocksAddr), Error=io::Error> + Send>
    {
        let fut = to_socket_addr_with(addr, system_dns_lookup).and_then(|socket| {
            self.connect_socket(&socket)
        });
        boxup(fut)
    }
}
