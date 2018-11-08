use std::time::{Instant, Duration};
use std::net::{SocketAddr, ToSocketAddrs};
use std::str::from_utf8;
use std::marker::Sized;

use bytes::{Bytes, BytesMut};
use tokio_timer::Delay;
use tokio_timer::timer::Handle;
use futures::{Future, Stream, Poll};
use nom::IResult;

pub type Id = u32;

pub type DomainName = Bytes;

pub type Port = u16;

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

// Timer
pub struct Timer {
    timeout: Delay,
    duration: Duration,
}

impl Timer {
    pub fn new(t: u64, handle: &Handle) -> Timer {
        let t = Duration::from_millis(t);
        let timeout = handle.delay(Instant::now() + t);
        Timer { timeout, duration: t }
    }
}

impl Stream for Timer {
    type Item = ();
    type Error = tokio_timer::Error;

    fn poll(&mut self) -> Poll<Option<()>, Self::Error> {
        try_ready!(self.timeout.poll());
        let next = Instant::now() + self.duration;
        self.timeout.reset(next);
        Ok(Some(()).into())
    }
}

