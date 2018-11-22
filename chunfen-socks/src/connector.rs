use std::net::{SocketAddr, ToSocketAddrs, IpAddr, Ipv4Addr, Ipv6Addr};
use std::io::{self, Write};
use std::str::from_utf8;

use futures::future;
use futures::Future;
use tokio_tcp::TcpStream;
use tokio_io::AsyncRead;

use crate::transfer::ShutdownWrite;
use crate::utils::{boxup, invalid};

pub const ATYP_IP_V4: u8 = 1;
pub const ATYP_DOMAINNAME: u8 = 3;
pub const ATYP_IP_V6: u8 = 4;

pub struct SocksAddr {
    pub addr: AddrKind,
    pub port: u16,
}

pub enum AddrKind {
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

    pub fn new(addr: AddrKind, port: u16) -> Self {
        SocksAddr { addr, port }
    }
}

// Open a tcp connection to out bound
pub trait Connector: Send + Sized {
    type Remote: AsyncRead + Write + ShutdownWrite + Send + 'static;

    fn connect(self, addr: SocksAddr)
        -> Box<Future<Item=(Self::Remote, SocksAddr), Error=io::Error> + Send>;
}

pub fn system_dns_lookup(dn: &str, port: u16)
    -> Box<Future<Item=SocketAddr, Error=io::Error> + Send>
{
    let res = (dn, port).to_socket_addrs().and_then(|mut addr| {
        addr.nth(0).ok_or_else(|| {
            invalid("invalid domain name")
        })
    });
    boxup(future::result(res))
}

pub fn resolve_dn_with<F>(raw: &[u8], port: u16, dns: F)
    -> Box<Future<Item=SocketAddr, Error=io::Error> + Send>
    where F: FnOnce(&str, u16) -> Box<Future<Item=SocketAddr, Error=io::Error> + Send>
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
    dns(&addr_str, port)
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
        let SocksAddr { addr, port } = addr;
        match addr {
            AddrKind::Ipv4(l) => {
                let socket = SocketAddr::new(IpAddr::V4(Ipv4Addr::from(l)), port);
                boxup(self.connect_socket(&socket))
            }
            AddrKind::Ipv6(l) => {
                let socket = SocketAddr::new(IpAddr::V6(Ipv6Addr::from(l)), port);
                boxup(self.connect_socket(&socket))
            }
            AddrKind::DomainName(bytes) => {
                let fut = resolve_dn_with(&bytes[..], port, system_dns_lookup)
                    .and_then(|socket| {
                        self.connect_socket(&socket)
                    });
                boxup(fut)
            }
        }
    }
}

