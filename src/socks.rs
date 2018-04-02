use std::net::{TcpStream, SocketAddr, SocketAddrV4, Ipv4Addr, ToSocketAddrs,
                Shutdown, TcpListener, };
use std::vec::Vec;
use std::convert::From;
use std::io::copy;
use std::marker::Send;
use std::thread;
use std::str::from_utf8;

use {TcpWrapper, Result, Error, DomainName, Port, WriteTcp, };

const SOCKS_V4:u8 = 4;
const SOCKS_V5:u8 = 5;
const RSV: u8 = 0;
const ATYP_IP_V4: u8 = 1;
const ATYP_DOMAINNAME: u8 = 3;
const CMD_CONNECT: u8 = 1;
const METHOD_NO_AUTH: u8 = 0;
const METHOD_GSSAPI: u8 = 1;
const METHOD_USER_PASSWORD: u8 = 2;
const METHOD_NO_ACCP: u8 = 0xFF;

#[derive(Debug)]
enum Ver { V4, V5 }

impl From<Ver> for u8 {
    fn from(ver: Ver) -> u8 {
        match ver {
            Ver::V4 => SOCKS_V4,
            Ver::V5 => SOCKS_V5,
        }
    }
}

#[derive(Debug, PartialEq, Clone, Copy)]
enum Method {
    NoAuth,
    GSSAPI,
    UserPassword,
    Other(u8),
    NoAccp,
}

impl From<Method> for u8 {
    fn from(m: Method) -> u8 {
        match m {
            Method::NoAuth => METHOD_NO_AUTH,
            Method::GSSAPI => METHOD_GSSAPI,
            Method::UserPassword => METHOD_USER_PASSWORD,
            Method::Other(n) => n,
            Method::NoAccp => METHOD_NO_ACCP,
        }
    }
}

enum Command {
    Connect,
    //Bind,
    //UdpAssociate,
}

enum Addr {
    Ipv4(SocketAddrV4),
    DN(DomainName, Port),
}

enum Req {
    Methods(Ver, Vec<Method>),
    Cmd(Ver, Command, Addr),
}

enum Resp {
    Select(Ver, Method),
    Success(SocketAddr),
    Fail,
}

pub struct SocksConnection;

pub trait Connector {
    fn connect(&mut self, addr: SocketAddrV4) -> Option<SocketAddr>;

    fn connect_dn(&mut self, dn: DomainName, port: Port) -> Option<SocketAddr> {
        if let Some(SocketAddr::V4(addr)) = try_parse_domain_name(dn, port) {
            self.connect(addr)
        } else {
            None
        }
    }
}

pub trait CopyTcp {
    fn copy_tcp(&mut self, stream: TcpStream) -> Result<()>;
}

impl SocksConnection {
    pub fn new<T> (stream: TcpStream, connector: T) -> Result<()>
        where T: Connector + CopyTcp + Send + 'static
    {
        let mut tcp = TcpWrapper(stream.try_clone().unwrap());
        let mut connector = connector;

        debug!("handshaking");
        if let Ok(m) = handshake(&mut tcp) {
            debug!("handshaking ok");
            
            let connect_result = match m {
                Req::Cmd(Ver::V5, Command::Connect, Addr::Ipv4(addr)) => {
                    debug!("target ip is {:?}", addr);
                    connector.connect(addr)
                },

                Req::Cmd(Ver::V5, Command::Connect, Addr::DN(dn, port)) => {
                    debug!("target domain name is {:?}", from_utf8(&dn[..]).unwrap());
                    connector.connect_dn(dn, port)
                },

                _ => unreachable!(),
            };
   
            debug!("connected to outbound? {}", connect_result.is_some());
            match connect_result {
                Some(SocketAddr::V4(addr)) => {
                    tcp.send(Resp::Success(SocketAddr::V4(addr)));
                    thread::spawn(move || {
                        connector.copy_tcp(stream);
                    });
                    Ok(())
                },
                
                _ => tcp.send(Resp::Fail),
            }
        } else {
            debug!("handshake failed");
            tcp.shutdown();
            Err(Error::HandshakeFailed)
        }
    }
}

type SimpleConnector = Option<TcpStream>;

impl CopyTcp for SimpleConnector {
    fn copy_tcp(&mut self, stream: TcpStream) -> Result<()> {
        let outbound = self.take().expect("Not connected!");
        let mut client_reader = stream.try_clone().unwrap();
        let mut outbound_writer = outbound.try_clone().unwrap();
        thread::spawn(move || {
            copy(&mut client_reader, &mut outbound_writer);
            client_reader.shutdown(Shutdown::Read).unwrap();
            outbound_writer.shutdown(Shutdown::Write).unwrap();
        });

        let mut outbound_reader = outbound;
        let mut client_writer = stream;
        copy(&mut outbound_reader, &mut client_writer);
        client_writer.shutdown(Shutdown::Write).unwrap();
        outbound_reader.shutdown(Shutdown::Read).unwrap();
        Ok(())
    }
}

impl Connector for SimpleConnector {
    fn connect(&mut self, addr: SocketAddrV4) -> Option<SocketAddr> {
        if let Ok(stream) = TcpStream::connect(addr) {
            let s = self.get_or_insert(stream);
            s.local_addr().ok()
        } else {
            None
        }
    }
}

fn handshake(tcp: &mut TcpWrapper) -> Result<Req> {
    let req = get_methods(tcp)?;

    match req {
        Req::Methods(Ver::V5, methods) => {
            let method = select_method(&methods);
            let resp = Resp::Select(Ver::V5, method);
            tcp.send(resp)?;

            if method == Method::NoAccp {
                return Err(Error::SocksRequest);
            }
        },

        _ => return Err(Error::SocksRequest),
    }
    get_command(tcp)
}


fn get_methods(tcp: &mut TcpWrapper) -> Result<Req> {
    let version = tcp.read_u8().and_then(|x| parse_version(x))?;
    let nmethods = tcp.read_u8()?;
    let methods = tcp.read_size(nmethods as usize)?;
    let methods = methods.iter().map(|x| parse_method(*x)).collect();
    Ok(Req::Methods(version, methods))
}

fn get_command(tcp: &mut TcpWrapper) -> Result<Req> {
    let mut buf = [0u8; 4];
    tcp.read_to_buf(&mut buf)?;

    match buf {
        [SOCKS_V5, CMD_CONNECT, RSV, atype] => {
            let addr = get_addr(tcp, atype)?;
            Ok(Req::Cmd(Ver::V5, Command::Connect, addr))
        },

        _ => Err(Error::SocksRequest),
    }
}

fn get_addr(tcp: &mut TcpWrapper, atype: u8) -> Result<Addr> {
    match atype {
        ATYP_IP_V4 => {
            let mut buf = [0u8; 4];
            tcp.read_to_buf(&mut buf)?;
            let port = tcp.read_u16()?;
            let [a, b, c, d] = buf;
            Ok(Addr::Ipv4(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port)))
        },

        ATYP_DOMAINNAME => {
            let len = tcp.read_u8()?;
            let domain_name = tcp.read_size(len as usize)?;
            let port = tcp.read_u16()?;
            Ok(Addr::DN(domain_name, port))
        },

        _ => Err(Error::SocksRequest),
    }
}

fn select_method(methods: &Vec<Method>) -> Method {
    let method = Method::NoAuth;

    if methods.contains(&method) {
        method
    } else {
        Method::NoAccp
    }
}

fn parse_version(x: u8) -> Result<Ver> {
    match x {
        SOCKS_V5 => Ok(Ver::V5),
        _        => Err(Error::SocksVersion),
    }
}

fn parse_method(x: u8) -> Method {
    match x {
        METHOD_NO_AUTH       => Method::NoAuth,
        METHOD_GSSAPI        => Method::GSSAPI,
        METHOD_USER_PASSWORD => Method::UserPassword,
        METHOD_NO_ACCP       => Method::NoAccp,
        n                    => Method::Other(n),
    }
}

impl WriteTcp<Resp> for TcpWrapper {
    fn send(&mut self, resp: Resp) -> Result<()> {
        match resp {
            Resp::Select(ver, method) => {
                debug!("select vesion is {:?}, method is {:?}", ver, method);
                self.write(&[u8::from(ver), u8::from(method)])
            },

            Resp::Success(SocketAddr::V4(addr)) => {
                let [a, b, c, d] = addr.ip().octets();
                let port = addr.port();
                debug!("remote address {}.{}.{}.{}, port {}", a, b, c, d, port);
                self.write(&[SOCKS_V5, 0, RSV, ATYP_IP_V4, a, b, c, d])?;
                self.write_u16(port)
            },

            Resp::Fail => {
                debug!("failed");
                self.write(&[SOCKS_V5, 1, RSV, ATYP_IP_V4, 0, 0, 0, 0, 0, 0])
            },

            _ => unreachable!("unexpected Resp message"),
        }
    }
}

fn try_parse_domain_name(buf: DomainName, port: Port) -> Option<SocketAddr> {
    let string = from_utf8(&buf[..]).unwrap_or("");
    let mut addr = (string, port).to_socket_addrs().unwrap();
    addr.nth(0)
}

pub struct Socks5;

impl Socks5 {
    pub fn bind(listen_addr: &str) {
        let listening = TcpListener::bind(listen_addr).unwrap();
        for s in listening.incoming() {
            if let Ok(stream) = s {
                let mut connector: SimpleConnector = None;
                SocksConnection::new(stream, connector);
            }
        }
    }
}
