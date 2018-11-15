use std::io;
use std::net::{SocketAddr, ToSocketAddrs};
use std::str::from_utf8;
use std::marker::Sized;

use bytes::{Bytes, BytesMut};
use nom::IResult;

pub type Id = u32;

pub type DomainName = Bytes;

pub type Port = u16;

pub fn tunnel_broken(desc: &str) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, desc)
}

macro_rules! drop_res {
    ($fut:expr) => ($fut.map(|_| ()).map_err(|_| ()))
}

// Codec
pub trait Encode {
    fn encode(&self, dest: &mut BytesMut);
}

pub trait Decode {
    fn decode(src: &[u8]) -> IResult<&[u8], Self>
        where Self: Sized;
}

// Domainname
pub fn parse_domain_name_with_port(dn: DomainName, port: Port)
    -> Option<SocketAddr>
{
    let string = from_utf8(&dn[..]).unwrap_or("");
    let mut addr = (string, port).to_socket_addrs().unwrap();
    addr.nth(0)
}

pub fn parse_domain_name(dn: DomainName) -> Option<SocketAddr> {
    let string = from_utf8(&dn[..]).unwrap_or("");
    let mut addr = string.to_socket_addrs().unwrap();
    addr.nth(0)
}
