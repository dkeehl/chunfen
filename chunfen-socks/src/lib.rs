#![warn(unused)]

#[macro_use]
extern crate tokio_io;
#[macro_use]
extern crate log;

use std::net::{SocketAddr};
use std::vec::Vec;
use std::convert::From;
use std::io;

use futures::future;
use futures::{Future, Stream};
use tokio_tcp::{TcpStream, TcpListener};
use tokio_io::AsyncRead;
use tokio_io::io::{read_exact, write_all};
use bytes::{BytesMut, BufMut};

mod utils;
mod transfer;
pub mod connector;

pub use crate::transfer::{ShutdownWrite, pipe};
use crate::connector::{Connector, SimpleConnector, SocksAddr, AddrKind,
    ATYP_IP_V6, ATYP_IP_V4, ATYP_DOMAINNAME};
use crate::utils::*;

const SOCKS_V4:u8 = 4;
const SOCKS_V5:u8 = 5;
const RSV: u8 = 0;
const CMD_CONNECT: u8 = 1;
const CMD_BIND: u8 = 2;
const CMD_UDPASSIATE: u8 = 3;
const METHOD_NO_AUTH: u8 = 0;
const METHOD_GSSAPI: u8 = 1;
const METHOD_USER_PASSWORD: u8 = 2;
const METHOD_NO_ACCP: u8 = 0xFF;

#[derive(Debug)]
pub enum SocksError {
    IO(io::Error),
    Unimplemented,
    Done,
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
    Bind,
    UdpAssociate,
}

enum Resp {
    Select(Method),
    Success(SocksAddr),
    Fail,
}

pub struct SocksConnection;

impl SocksConnection {
    pub fn serve<T>(stream: TcpStream, connector: T)
        -> impl Future<Item = (), Error = ()> + Send
        where T: Connector + 'static
    {
        info!("New socks request");
        handshake(stream).and_then(|(stream, cmd, addr)| {
            match cmd {
                Command::Connect => {
                    let fut = connector.connect(addr).then(|res| {
                        connect_resp(stream, res)
                    });
                    boxup(fut)
                }
                _ => unimplemented!(),
            }
        }).map_err(|e| {
            info!("Err: {:?}", e)
        })
    }
}

fn connect_resp<T>(stream: TcpStream, res: Result<(T, SocksAddr), io::Error>)
    -> impl Future<Item=(), Error=SocksError> + Send
    where T: AsyncRead + io::Write + ShutdownWrite + Send + 'static
{
    match res {
        Ok((remote, addr)) => {
            info!("Remote connected");
            let resp = Resp::Success(addr);
            let fut = response(stream, resp).map(|stream| {
                pipe(stream, remote);
            });
            boxup(fut)
        },
        Err(e) => {
            info!("Failed to connect remote: {}", e);
            let resp = Resp::Fail;
            let fut = response(stream, resp).map(|_| ());
            boxup(fut)
        },
    }
}

fn response(stream: TcpStream, resp: Resp)
    -> impl Future<Item=TcpStream, Error=SocksError> + Send
{
    let mut buf = BytesMut::new();
    resp.encode(&mut buf);
    write_all(stream, buf)
        .map(|(s, _)| s)
        .map_err(SocksError::IO)
}

impl Resp {
    fn encode(self, buf: &mut BytesMut) {
        match self {
            Resp::Select(method) => {
                buf.put_u8(SOCKS_V5);
                buf.put_u8(u8::from(method));
            }
            Resp::Success(SocksAddr { addr: AddrKind::DomainName(..), ..}) =>
                unreachable!(),
            Resp::Success(SocksAddr { addr: AddrKind::Ipv4(l), port }) => {
                buf.put_slice(&[SOCKS_V5, 0, RSV, ATYP_IP_V4][..]);
                buf.put_slice(&l[..]);
                buf.put_u16_be(port);
            }
            Resp::Success(SocksAddr { addr: AddrKind::Ipv6(l), port }) => {
                buf.put_slice(&[SOCKS_V5, 0, RSV, ATYP_IP_V6][..]);
                buf.put_slice(&l[..]);
                buf.put_u16_be(port);
            }
            Resp::Fail =>
                buf.put_slice(&[SOCKS_V5, 1, RSV, ATYP_IP_V4, 0, 0, 0, 0, 0, 0][..]),
        }
    }
}

fn handshake(stream: TcpStream)
    -> impl Future<Item=(TcpStream, Command, SocksAddr), Error=SocksError> + Send
{
    read_methods(stream).and_then(|(stream, methods)| {
        let method = select_method(&methods);
        let resp = Resp::Select(method);
        response(stream, resp).and_then(move |stream| {
            if method == Method::NoAccp {
                Err(SocksError::Done)
            } else {
                Ok(stream)
            }
        })
    }).and_then(|stream| {
        read_command(stream).map_err(SocksError::IO)
    })
}

fn read_methods(stream: TcpStream)
    -> impl Future<Item=(TcpStream, Vec<Method>), Error=SocksError> + Send
{
    read_exact(stream, [0u8]).map_err(SocksError::IO).and_then(|(stream, buf)| {
        match buf[0] {
            SOCKS_V5 => {
                let req = read_exact(stream, [0u8]).and_then(|(stream, num_methods)| {
                    read_exact(stream, vec![0u8; num_methods[0] as usize])
                }).map(|(stream, buf)| {
                    let methods = buf.iter().map(|x| parse_method(*x)).collect();
                    (stream, methods)
                });
                boxup(req.map_err(SocksError::IO))
            },

            _ => boxup(future::err(SocksError::Unimplemented)),
        }
    })
}

fn read_command(stream: TcpStream)
    -> impl Future<Item=(TcpStream, Command, SocksAddr), Error=io::Error> + Send
{
    read_exact(stream, [0u8; 4]).and_then(|(stream, buf)| {
        read_addr(stream, buf[3]).and_then(move |(stream, addr)| {
            match buf {
                [SOCKS_V5, CMD_CONNECT, RSV, _] => {
                    Ok((stream, Command::Connect, addr))
                }
                [SOCKS_V5, CMD_BIND, RSV, _] => {
                    Ok((stream, Command::Bind, addr))
                }
                [SOCKS_V5, CMD_UDPASSIATE, RSV, _] => {
                    Ok((stream, Command::UdpAssociate, addr))
                }
                _ => Err(invalid("invalid request")),
            }
        })
    })
}

fn read_addr(stream: TcpStream, atype: u8) 
    -> impl Future<Item=(TcpStream, SocksAddr), Error=io::Error> + Send
{
    let addr = match atype {
        ATYP_IP_V4 => {
            let fut = read_exact(stream, [0u8; 4]).map(|(stream, buf)| {
                (stream, AddrKind::Ipv4(buf))
            });
            boxup(fut)
        }
        ATYP_DOMAINNAME => {
            let fut = read_exact(stream, [0u8]).and_then(|(stream, len)| {
                read_exact(stream, vec![0u8; len[0] as usize])
            }).map(|(stream, buf)| {
                (stream, AddrKind::DomainName(buf))
            });
            boxup(fut)
        }
        ATYP_IP_V6 => {
            let fut = read_exact(stream, [0u8; 16]).map(|(stream, buf)| {
                (stream, AddrKind::Ipv6(buf))
            });
            boxup(fut)
        }
        _ => boxup(future::err(invalid("invalid atype"))),
    };
    addr.and_then(|(stream, kind)| {
        read_port(stream).map(|(stream, port)| {
            (stream, SocksAddr::new(kind, port))
        })
    })
}

fn read_port(stream: TcpStream)
    -> impl Future<Item=(TcpStream, u16), Error=io::Error> + Send
{
    read_exact(stream, [0u8; 2]).map(|(stream, buf)| {
        let port = ((buf[0] as u16) << 8) | buf[1] as u16;
        (stream, port)
    })
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
    pub fn bind(addr: &SocketAddr) {
        let listening = TcpListener::bind(addr).unwrap();
        println!("Socks server listening on {}...", addr);

        let server = listening.incoming().map_err(|e| {
            error!("Error when accepting: {}", e)
        }).for_each(|stream| {
            let task = SocksConnection::serve(stream, SimpleConnector);
            tokio::spawn(task);
            Ok(())
        });

        tokio::run(server)
    }
}
