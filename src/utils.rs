use std::thread;
use std::sync::mpsc;
use std::io;
use std::io::Write;
use std::sync::mpsc::{Sender, Receiver};
use std::time::{Instant, Duration};
use std::vec::Vec;
use std::net::{SocketAddr, ToSocketAddrs};
use std::str::from_utf8;
use std::marker::Sized;

use bytes::BytesMut;
use tokio_core::reactor::{Handle, Timeout};
use futures::{Future, Stream, Poll};
use nom::IResult;

use crate::{Id, DomainName, Port};

macro_rules! drop_res {
    ($fut:expr) => ($fut.map(|_| ()).map_err(|_| ()))
}

// Errors
pub fn not_connected() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "not connected")
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
    timeout: Timeout,
    duration: Duration,
}

impl Timer {
    pub fn new(t: u64, handle: &Handle) -> Timer {
        let t = Duration::from_millis(t);
        let timeout = Timeout::new(t, handle).unwrap();
        Timer { timeout, duration: t }
    }
}

impl Stream for Timer {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<()>, io::Error> {
        try_ready!(self.timeout.poll());
        let next = Instant::now() + self.duration;
        self.timeout.reset(next);
        Ok(Some(()).into())
    }
}

