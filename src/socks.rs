use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr, ToSocketAddrs, Shutdown,};
use std::vec::Vec;
use std::convert::From;
use std::io::{self, Read, Write};
use std::marker::Send;
use std::str::from_utf8;
use std::rc::Rc;
use std::cell::RefCell;

use futures::future;
use futures::{Future, Poll, Async, Stream};
use tokio_core::net::{TcpStream, TcpListener};
use tokio_core::reactor::{Handle, Core};
use tokio_io::io::{read_exact, write_all};

use {DomainName, Port};

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
pub enum SocksError {
    IO(io::Error),
    InvalidDomainName,
    Unimplemented,
    Done,
}

#[derive(Debug)]
enum Ver { V4, V5 }

impl<'a> From<&'a Ver> for u8 {
    fn from(ver: &Ver) -> u8 {
        match *ver {
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

impl<'a> From<&'a Method> for u8 {
    fn from(m: &Method) -> u8 {
        match *m {
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

pub struct SocksConnection {
    buffer: Rc<RefCell<Vec<u8>>>,
    handle: Handle,
}

// Open a tcp connection to out bound
pub trait Connector {
    fn connect(addr: &SocketAddrV4, handle: &Handle)
        -> Box<Future<Item = TcpStream, Error = SocksError>>;

    fn connect_dn(dn: DomainName, port: Port, handle: &Handle)
        -> Box<Future<Item = TcpStream, Error = SocksError>>
    {
        match try_parse_domain_name(dn, port) {
            Some(SocketAddr::V4(addr)) => Self::connect(&addr, handle),
            Some(_) => boxup(future::err(SocksError::Unimplemented)),
            None => boxup(future::err(SocksError::InvalidDomainName))
        }
    }
}

// Exchange data with a TcpStream. Close the stream when copying finished.
pub trait CopyTcp {
    fn copy_tcp(&mut self, stream: TcpStream) -> io::Result<()>;
}

fn boxup<T: Future + 'static>(x: T) -> Box<Future<Item=T::Item, Error=T::Error>> {
    Box::new(x)
}

impl SocksConnection {
    pub fn serve<T: Connector>(self, stream: TcpStream)
        -> Box<Future<Item = (usize, usize), Error = SocksError>>
    {
        let handshaked = start_handshake(stream);

        let handle = self.handle.clone();
        let connected = handshaked.and_then(move |(stream, req)| {
            match req {
                Req::Cmd(Ver::V5, Command::Connect, Addr::Ipv4(addr)) => {
                    T::connect(&addr, &handle)
                },

                Req::Cmd(Ver::V5, Command::Connect, Addr::DN(dn, port)) => {
                    T::connect_dn(dn, port, &handle)
                },

                _ => unreachable!(),
            }.map(|remote| (stream, remote))
        });

        let buffer = self.buffer.clone();
        let res = connected.and_then(|(stream, remote)| {
            match remote.local_addr() {
                Ok(addr) => {
                    let resp = Resp::Success(addr);
                    boxup(response(stream, &resp).and_then(|stream| {
                        pipe(stream, remote, buffer)
                    }))
                },
                
                Err(_) => {
                    let resp = Resp::Fail;
                    boxup(response(stream, &resp).and_then(|_| {
                        let dummy: (usize, usize) = (0, 0);
                        future::ok(dummy)
                    }))
                },
            }
        });
        boxup(res)
    }
}

fn pipe(a: TcpStream, b: TcpStream, buffer: Rc<RefCell<Vec<u8>>>)
        -> Box<Future<Item = (usize, usize), Error = SocksError>> {
    let a = Rc::new(a);
    let b = Rc::new(b);

    let half1 = Transfer::new(a.clone(), b.clone(), buffer.clone());
    let half2 = Transfer::new(b, a, buffer);
    boxup(half1.join(half2).map_err(SocksError::IO))
}

fn response(stream: TcpStream, resp: &Resp)
    -> Box<Future<Item = TcpStream, Error = SocksError>>
{
    let buf = resp.encode();
    let res = write_all(stream, buf)
        .map(|(s, _)| s)
        .map_err(SocksError::IO);
    boxup(res)
}

trait Encode {
    fn encode(&self) -> Vec<u8>;
}

impl Encode for Resp {
    fn encode(&self) -> Vec<u8> {
        match self {
            Resp::Select(ver, method) => vec![u8::from(ver), u8::from(method)],

            Resp::Success(SocketAddr::V4(addr)) => {
                let [a, b, c, d] = addr.ip().octets();
                let port_high = (addr.port() >> 8) as u8;
                let port_low = addr.port() as u8;
                vec![SOCKS_V5, 0, RSV, ATYP_IP_V4, a, b, c, d, port_high, port_low]
            },

            Resp::Fail => vec![SOCKS_V5, 1, RSV, ATYP_IP_V4, 0, 0, 0, 0, 0, 0],

            _ => unreachable!("unexpected Resp message"),
        }
    }
}

fn start_handshake(stream: TcpStream)
        -> Box<Future<Item=(TcpStream, Req), Error=SocksError>> {
    let got = get_methods(stream);

    let resp = got.and_then(|(stream, req)| {
        match req {
            Req::Methods(Ver::V5, methods) => {
                let method = select_method(&methods);
                let resp = Resp::Select(Ver::V5, method);
                boxup(response(stream, &resp).and_then(move |stream| {
                    if method == Method::NoAccp {
                        Err(SocksError::Done)
                    } else {
                        Ok(stream)
                    }
                }))
            },

            _ => boxup(future::err(SocksError::Unimplemented)),
        }
    });
    boxup(resp.and_then(|stream| get_command(stream)))
}

fn get_methods(stream: TcpStream)
    -> Box<Future<Item=(TcpStream, Req), Error=SocksError>>
{
    let req = read_exact(stream, [0u8]).map_err(SocksError::IO)
        .and_then(|(stream, buf)| {
        match buf[0] {
            SOCKS_V5 => {
                boxup(read_exact(stream, [0u8]).and_then(|(stream, num_methods)| {
                    read_exact(stream, vec![0u8; num_methods[0] as usize])
                }).and_then(|(stream, buf)| {
                    let methods = buf.iter().map(|x| parse_method(*x)).collect();
                    future::ok((stream, Req::Methods(Ver::V5, methods)))
                }).map_err(SocksError::IO))
            },

            _ => boxup(future::err(SocksError::Unimplemented)),
        }
    });
    boxup(req)
}

fn get_command(stream: TcpStream)
    -> Box<Future<Item=(TcpStream, Req), Error=SocksError>>
{
    let req = read_exact(stream, [0u8; 4]).map_err(SocksError::IO)
        .and_then(|(stream, buf)| {
        match buf {
            [SOCKS_V5, CMD_CONNECT, RSV, atype] => {
                boxup(get_addr(stream, atype).and_then(|(stream, addr)| {
                    Ok((stream, Req::Cmd(Ver::V5, Command::Connect, addr)))
                }))
            },

            _ => boxup(future::err(SocksError::Unimplemented)),
        }
    });
    boxup(req)
}

fn get_addr(stream: TcpStream, atype: u8) 
    -> Box<Future<Item=(TcpStream, Addr), Error=SocksError>>
{
    match atype {
        ATYP_IP_V4 => {
            boxup(read_exact(stream, [0u8; 6]).and_then(|(stream, buf)| {
                let addr = Ipv4Addr::new(buf[0], buf[1], buf[2], buf[3]);
                let port = ((buf[4] as u16) << 8) | buf[5] as u16;
                let addr = SocketAddrV4::new(addr, port);
                Ok((stream, Addr::Ipv4(addr)))
            }).map_err(SocksError::IO))
        },

        ATYP_DOMAINNAME => {
            boxup(read_exact(stream, [0u8]).and_then(|(stream, len)| {
                read_exact(stream, vec![0u8; len[0] as usize + 2])
            }).and_then(|(stream, name_port)| {
                let len = name_port.len() - 2;
                let mut domain_name = Vec::new();
                domain_name.extend_from_slice(&name_port[..len]);
                let port = ((name_port[len] as u16) << 8) | name_port[len + 1] as u16;
                Ok((stream, Addr::DN(domain_name, port)))
            }).map_err(SocksError::IO))
        },

        _ => boxup(future::err(SocksError::Unimplemented)),
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

//fn parse_version(x: u8) -> Option<Ver> {
//    match x {
//        SOCKS_V5 => Some(Ver::V5),
//        _        => None,
//    }
//}

fn parse_method(x: u8) -> Method {
    match x {
        METHOD_NO_AUTH       => Method::NoAuth,
        METHOD_GSSAPI        => Method::GSSAPI,
        METHOD_USER_PASSWORD => Method::UserPassword,
        METHOD_NO_ACCP       => Method::NoAccp,
        n                    => Method::Other(n),
    }
}

fn try_parse_domain_name(buf: DomainName, port: Port) -> Option<SocketAddr> {
    let string = from_utf8(&buf[..]).unwrap_or("");
    let mut addr = (string, port).to_socket_addrs().unwrap();
    addr.nth(0)
}

struct Transfer {
    reader: Rc<TcpStream>,
    writer: Rc<TcpStream>,
    buf: Rc<RefCell<Vec<u8>>>,
    amt: usize,
}

impl Transfer {
    fn new(reader: Rc<TcpStream>,
           writer: Rc<TcpStream>,
           buf: Rc<RefCell<Vec<u8>>>) -> Transfer {
        Transfer {
            reader,
            writer,
            buf,
            amt: 0,
        }
    }
}

impl Future for Transfer {
    type Item = usize;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<usize, io::Error> {
        let mut buffer = self.buf.borrow_mut();
        loop {
            let read_ready = self.reader.poll_read().is_ready();
            let write_ready = self.writer.poll_write().is_ready();
            if !read_ready || !write_ready {
                return Ok(Async::NotReady)
            }

            let n = try_nb!((&*self.reader).read(&mut buffer));
            if n == 0 {
                self.writer.shutdown(Shutdown::Write)?;
                return Ok(self.amt.into())
            }

            self.amt += n;
            
            let m = (&*self.writer).write(&buffer[..n])?;
            assert_eq!(m, n);
        }
    }
}

pub struct Socks5;

impl Socks5 {
    pub fn bind(listen_addr: &str) {
        let mut lp = Core::new().unwrap();
        let handle = lp.handle();
        let buffer = Rc::new(RefCell::new(vec![0u8; 64 * 1024]));

        let addr = listen_addr.parse().unwrap();
        let listening = TcpListener::bind(&addr, &handle).unwrap();
        let clients = listening.incoming().map(|(stream, addr)| {
            (SocksConnection {
                buffer: buffer.clone(),
                handle: handle.clone(),
            }.serve::<SimpleConnector>(stream), addr)
        });

        let handle = lp.handle();
        let server = clients.for_each(|(client, addr)| {
            handle.spawn(client.then(move |res| {
                match res {
                    Ok((a, b)) => {
                        println!("proxied {}/{} bytes for {}", a, b, addr);
                    },
                    Err(e) => println!("error for {}: {:?}", addr, e),
                }
                future::ok(())
            }));
            Ok(())
        });

        lp.run(server).unwrap()
    }
}

struct SimpleConnector;

impl Connector for SimpleConnector {
    fn connect(addr: &SocketAddrV4, handle: &Handle)
        -> Box<Future<Item = TcpStream, Error = SocksError>>
    {
        let stream = TcpStream::connect(&SocketAddr::V4(*addr), handle)
            .map_err(SocksError::IO);
        boxup(stream)
    }
}
