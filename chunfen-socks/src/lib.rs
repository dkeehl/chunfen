#[macro_use]
extern crate futures;
#[macro_use]
extern crate tokio_core;
extern crate tokio_io;
extern crate bytes;

use std::net::{SocketAddr, SocketAddrV4, Ipv4Addr};
use std::vec::Vec;
use std::convert::From;
use std::io;

use futures::future;
use futures::{Future, Stream};
use tokio_core::net::{TcpStream, TcpListener};
use tokio_core::reactor::{Handle, Core};
use tokio_io::io::{read_exact, write_all};
use bytes::{Bytes, BytesMut, BufMut};

mod utils;
mod connector;
mod transfer;

pub use crate::connector::{Connector, SimpleConnector};
pub use crate::transfer::{ShutdownWrite, pipe};
use crate::utils::*;

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

type DomainName = Bytes;
type Port = u16;

#[derive(Debug)]
pub enum SocksError {
    IO(io::Error),
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
    //buffer: Rc<RefCell<Vec<u8>>>,
    handle: Handle,
}

impl SocksConnection {
    pub fn new(handle: Handle) -> Self {
        SocksConnection { handle }
    }

    pub fn serve<T>(self, stream: TcpStream, connector: T)
        -> Box<Future<Item = (usize, usize), Error = SocksError>>
        where T: Connector + 'static
    {
        //println!("New socks request");
        let handshaked = start_handshake(stream);

        let handle = self.handle.clone();
        let connected = handshaked.and_then(move |(stream, req)| {
            match req {
                Req::Cmd(Ver::V5, Command::Connect, Addr::Ipv4(addr)) => {
                    connector.connect(&addr, &handle)
                },

                Req::Cmd(Ver::V5, Command::Connect, Addr::DN(dn, port)) => {
                    connector.connect_dn(dn, port, &handle)
                },

                _ => unreachable!(),
            }.map(|conn| (stream, conn)).map_err(SocksError::IO)
        });

        let res = connected.and_then(|(stream, conn)| {
            match conn {
                Some((remote, addr)) => {
                    //println!("Remote connected");
                    let resp = Resp::Success(addr);
                    boxup(response(stream, &resp).and_then(|stream| {
                        pipe(stream, remote).map_err(SocksError::IO)
                    }))
                },
                None => {
                    println!("Failed to connect remote");
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

fn response(stream: TcpStream, resp: &Resp)
    -> Box<Future<Item = TcpStream, Error = SocksError>>
{
    let mut buf = BytesMut::new();
    resp.encode(&mut buf);
    let res = write_all(stream, buf)
        .map(|(s, _)| s)
        .map_err(SocksError::IO);
    boxup(res)
}

impl Resp {
    fn encode(&self, buf: &mut BytesMut) {
        match self {
            Resp::Select(ver, method) => 
                buf.put_slice(&[u8::from(ver), u8::from(method)][..]),

            Resp::Success(SocketAddr::V4(addr)) => {
                let [a, b, c, d] = addr.ip().octets();
                buf.put_slice(&[SOCKS_V5, 0, RSV, ATYP_IP_V4, a, b, c, d][..]);
                buf.put_u16_be(addr.port());
            },

            Resp::Fail =>
                buf.put_slice(&[SOCKS_V5, 1, RSV, ATYP_IP_V4, 0, 0, 0, 0, 0, 0][..]),

            _ => unreachable!("unexpected Resp message"),
        }
    }
}

fn start_handshake(stream: TcpStream)
        -> Box<Future<Item=(TcpStream, Req), Error=SocksError>>
{
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
                let domain_name = Bytes::from(&name_port[..len]);
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

fn parse_method(x: u8) -> Method {
    match x {
        METHOD_NO_AUTH       => Method::NoAuth,
        METHOD_GSSAPI        => Method::GSSAPI,
        METHOD_USER_PASSWORD => Method::UserPassword,
        METHOD_NO_ACCP       => Method::NoAccp,
        n                    => Method::Other(n),
    }
}

pub struct Socks5;

impl Socks5 {
    pub fn bind(listen_addr: &str) {
        let mut lp = Core::new().unwrap();
        let handle = lp.handle();
        //let buffer = Rc::new(RefCell::new(vec![0u8; 64 * 1024]));

        let addr = listen_addr.parse().unwrap();
        let listening = TcpListener::bind(&addr, &handle).unwrap();
        let clients = listening.incoming().map(|(stream, addr)| {
            (SocksConnection {
                //buffer: buffer.clone(),
                handle: handle.clone(),
            }.serve(stream, SimpleConnector), addr)
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
