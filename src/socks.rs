use std::net::{TcpStream, SocketAddr, SocketAddrV4, Ipv4Addr, ToSocketAddrs,
                Shutdown, TcpListener, };
use std::vec::Vec;
use std::convert::From;
use std::io;
use std::io::{copy, Read, Write};
use std::marker::{Send, Sized};
use std::thread;
use std::str::from_utf8;

use {TcpConnection, Result, Error, DomainName, Port, WriteTcp, };

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

pub trait Connector: Read + Write + Send + TryClone + 'static {
    fn connect(&mut self, addr: SocketAddrV4) -> Option<SocketAddr>;

    fn connect_dn(&mut self, dn: DomainName, port: Port) -> Option<SocketAddr>; 

    fn shutdown_read(&mut self) -> Result<()>;

    fn shutdown_write(&mut self) -> Result<()>;

}

impl SocksConnection {
    pub fn new<T: Connector> (stream: TcpStream, connector: T) -> Result<()> {
        let mut tcp = TcpConnection(stream.try_clone().unwrap());
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
                        debug!("start copying data");
                        copy_data(stream, connector);
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

fn copy_data<T: Connector>(stream: TcpStream, connector: T) -> Result<()> {
    let mut client_reader = stream.try_clone().unwrap();
    let mut outbound_writer = connector.try_clone().unwrap();
    thread::spawn(move || {
        copy(&mut client_reader, &mut outbound_writer);
        client_reader.shutdown(Shutdown::Read);
        outbound_writer.shutdown_write();
    });

    let mut outbound_reader = connector;
    let mut client_writer = stream;
    copy(&mut outbound_reader, &mut client_writer);
    client_writer.shutdown(Shutdown::Write);
    outbound_reader.shutdown_read()
}

struct JustTcp {
    tcp_stream: Option<TcpStream>,
}

impl JustTcp {
    fn new() -> JustTcp {
        JustTcp { tcp_stream: None }
    }

    fn stream(&mut self) -> &mut TcpStream {
        if let Some(ref mut stream) = self.tcp_stream {
            stream
        } else {
            panic!("Not connected!")
        }
    }
}

pub trait TryClone: Sized {
    fn try_clone(&self) -> io::Result<Self>;
}

impl TryClone for JustTcp {
    fn try_clone(&self) -> io::Result<JustTcp> {
        if let Some(ref stream) = self.tcp_stream {
            let stream = stream.try_clone()?;
            Ok(JustTcp { tcp_stream: Some(stream) })
        } else {
            Ok(JustTcp { tcp_stream: None })
        }
    }
}
                   
impl Read for JustTcp {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.stream().read(buf)
    }
}

impl Write for JustTcp {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.stream().write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream().flush()
    }
}

impl Connector for JustTcp {
    fn connect(&mut self, addr: SocketAddrV4) -> Option<SocketAddr> {
        if let Ok(stream) = TcpStream::connect(addr) {
            let result = Some(stream.local_addr().unwrap());
            self.tcp_stream = Some(stream);
            result
        } else {
            None
        }
    }

    fn connect_dn(&mut self, dn: DomainName, port: Port) -> Option<SocketAddr> {
        if let Some(SocketAddr::V4(addr)) = try_parse_domain_name(dn, port) {
            self.connect(addr)
        } else {
            None
        }
    }

    fn shutdown_read(&mut self) -> Result<()> {
        if let Some(ref stream) = self.tcp_stream {
            stream.shutdown(Shutdown::Read).map_err(|_| Error::TcpIo)
        } else {
            Ok(())
        }
    }

    fn shutdown_write(&mut self) -> Result<()> {
        if let Some(ref stream) = self.tcp_stream {
            stream.shutdown(Shutdown::Write).map_err(|_| Error::TcpIo)
        } else {
            Ok(())
        }
    }
}

pub struct Socks5;

impl Socks5 {
    pub fn new(listen_addr: &str) {
        let listening = TcpListener::bind(listen_addr).unwrap();
        for s in listening.incoming() {
            if let Ok(stream) = s {
                let mut connector = JustTcp::new();
                SocksConnection::new(stream, connector);
            }
        }
    }
}

fn handshake(tcp: &mut TcpConnection) -> Result<Req> {
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


fn get_methods(tcp: &mut TcpConnection) -> Result<Req> {
    let version = tcp.read_u8().and_then(|x| parse_version(x))?;
    let nmethods = tcp.read_u8()?;
    let methods = tcp.read_size(nmethods as usize)?;
    let methods = methods.iter().map(|x| parse_method(*x)).collect();
    Ok(Req::Methods(version, methods))
}

fn get_command(tcp: &mut TcpConnection) -> Result<Req> {
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

fn get_addr(tcp: &mut TcpConnection, atype: u8) -> Result<Addr> {
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

impl WriteTcp<Resp> for TcpConnection {
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

