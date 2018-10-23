use std::thread;
use std::sync::mpsc;
use std::io;
use std::io::Write;
use std::sync::mpsc::{Sender, Receiver};
use std::time::{Instant, Duration};
use std::vec::Vec;
use std::net::{SocketAddr, ToSocketAddrs};
use std::str::from_utf8;

use tokio_core::reactor::{Handle, Timeout};
use futures::{Future, Stream, Poll};

use {Id, DomainName, Port};

pub fn not_connected() -> io::Error {
    io::Error::new(io::ErrorKind::NotConnected, "not connected")
}

pub trait SenderWithId<T> {
    fn get_id(&self) -> Id;

    fn get_sender(&self) -> &Sender<T>;
}

pub fn write_id_data<T, U, F>(t: &mut T, buf: &[u8], f: F)
    -> io::Result<usize> where
    T: SenderWithId<U>, F: FnOnce(Id, Vec<u8>) -> U
{
        let size: usize = 1024;
        let mut to: Vec<u8> = Vec::new();
        let len = buf.len();
        let res = if len > size {
            to.write(&buf[..size])?
        } else {
            to.write(buf)?
        };
        t.get_sender().send(f(t.get_id(), to));
        Ok(res)
}

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

pub struct Timer {
    timeout: Timeout,
    duration: Duration,
    deadline: Instant
}

impl Timer {
    pub fn new(t: u64, handle: &Handle) -> Timer {
        let t = Duration::from_millis(t);
        let timeout = Timeout::new(t, handle).unwrap();
        let deadline = Instant::now() + t;
        Timer { timeout, duration: t, deadline }
    }
}

impl Stream for Timer {
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<()>, io::Error> {
        try_ready!(self.timeout.poll());
        let next = self.deadline + self.duration;
        self.timeout.reset(next);
        self.deadline = next;
        Ok(Some(()).into())
    }
}

