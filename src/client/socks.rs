use std::net::{TcpStream, SocketAddrV4, Ipv4Addr};
use std::vec::Vec;
use std::convert::From;

use {Talker, TcpConnection, Result, Error, Addr};
use client::{TunnelMsg, SocksMsg};

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

enum Ver { V4, V5 }

impl From<Ver> for u8 {
    fn from(ver: Ver) -> u8 {
        match ver {
            Ver::V4 => SOCKS_V4,
            Ver::V5 => SOCKS_V5,
        }
    }
}

#[derive(PartialEq, Clone, Copy)]
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

enum Req {
    Methods(Ver, Vec<Method>),
    Cmd(Ver, Command, Addr),
}

enum Resp {
    Select(Ver, Method),
}

//enum State {
//    SelectMethod,
//    GetCommand(Ver),
//
//    Closed,
//}

pub struct SocksConnection {
    tcp: TcpConnection,
    //state: State,
}

impl SocksConnection {
    pub fn new(stream: TcpStream) -> Self {
        let tcp = TcpConnection::new(stream);
        //let state = State::SelectMethod;
        SocksConnection { tcp }
    }

    fn handshake(&mut self) -> Result<TunnelMsg> {
        let req = self.get_methods()?;

        match req {
            Req::Methods(Ver::V5, methods) => {
                let method = select_method(&methods);
                let resp = Resp::Select(Ver::V5, method);
                self.response(resp)?;

                if method == Method::NoAccp {
                    return Err(Error::SocksRequest);
                }
            },

            _ => return Err(Error::SocksRequest),
        }

        let req = self.get_command()?;

        match req {
            Req::Cmd(Ver::V5, Command::Connect, addr) =>
                Ok(TunnelMsg::Connect(addr)),
            _ => Err(Error::SocksRequest),
        }
    }

    //fn read(&mut self) -> Result<Req> {
    //    match self.state {
    //        State::SelectMethod => self.get_methods(),
    //        State::GetCommand => self.get_command(),
    //        _ => Err(Error::SocksState),
    //    }
    //}

    fn response(&mut self, resp: Resp) -> Result<()> {
        match resp {
            Resp::Select(ver, method) =>
                self.tcp.write(&[u8::from(ver), u8::from(method)]),
        }
    }

    fn get_methods(&mut self) -> Result<Req> {
        let version = self.tcp.read_u8().and_then(|x| parse_version(x))?;
        let nmethods = self.tcp.read_u8()?;
        let methods = self.tcp.read_size(nmethods as usize)?;
        let methods = methods.iter().map(|x| parse_method(*x)).collect();
        Ok(Req::Methods(version, methods))
    }

    fn get_command(&mut self) -> Result<Req> {
        let mut buf = [0u8; 4];
        self.tcp.read_to_buf(&mut buf)?;

        match buf {
            [SOCKS_V5, CMD_CONNECT, RSV, atype] => {
                let addr = self.get_addr(atype)?;
                Ok(Req::Cmd(Ver::V5, Command::Connect, addr))
            },

            _ => Err(Error::SocksRequest),
        }
    }

    fn get_addr(&mut self, atype: u8) -> Result<Addr> {
        match atype {
            ATYP_IP_V4 => {
                let mut buf = [0u8; 4];
                self.tcp.read_to_buf(&mut buf)?;
                let port = self.tcp.read_u16()?;
                let [a, b, c, d] = buf;
                Ok(Addr::Ipv4(SocketAddrV4::new(Ipv4Addr::new(a, b, c, d), port)))
            },

            ATYP_DOMAINNAME => {
                let len = self.tcp.read_u8()?;
                let domain_name = self.tcp.read_size(len as usize)?;
                let port = self.tcp.read_u16()?;
                Ok(Addr::DN(domain_name, port))
            },

            _ => Err(Error::SocksRequest),
        }
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

impl Talker<TunnelMsg, SocksMsg> for SocksConnection {
    fn tell<T, W>(&mut self, tunnel: &mut T) where T: Talker<W, TunnelMsg> {
        if let Ok(m) = self.handshake() {
            tunnel.told(m);
            
            loop {
                match self.tcp.read_at_most(1024) {
                    Ok(buf) => tunnel.told(TunnelMsg::Write(buf)),

                    Err(Error::Eof) => {
                        self.tcp.shutdown_read();
                        tunnel.told(TunnelMsg::ShutdownWrite);
                        break
                    },

                    Err(_) => {
                        tunnel.told(TunnelMsg::Close);
                        self.tcp.shutdown();
                        break
                    },
                }
            }
        } else {
            tunnel.told(TunnelMsg::Close);
            self.tcp.shutdown();
        }
    }

    fn told(&mut self, msg: SocksMsg) {
    }
}
