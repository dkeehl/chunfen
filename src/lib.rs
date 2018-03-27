#![feature(slice_patterns)]

extern crate time;

use std::net::{TcpStream, SocketAddrV4, Shutdown};
use std::io::Read;
use std::io::Write;

pub mod protocol {
    pub const HEARTBEAT_INTERVAL_MS: u32 = 5000;
    pub const ALIVE_TIMEOUT_TIME_MS: i64 = 60000;

    pub mod cs {
        pub const OPEN_PORT: u8 = 1;
        pub const CLOSE_PORT: u8 = 2;
        pub const SHUTDOWN_WRITE: u8 = 4;
        pub const CONNECT: u8 = 5;
        pub const CONNECT_DOMAIN_NAME: u8 = 6;
        pub const DATA: u8 = 7;
        pub const HEARTBEAT: u8 = 8;
    }

    pub mod sc {
        pub const CLOSE_PORT: u8 = 1;
        pub const SHUTDOWN_WRITE: u8 = 3;
        pub const CONNECT_OK: u8 = 4;
        pub const DATA: u8 = 5;
        pub const HEARTBEAT_RSP: u8 = 6;
    }
}

#[derive(Debug)]
pub enum Error {
    SocksVersion,
    SocksState,
    SocksRequest,

    //when reading some data to a buffer,
    //if the buffer length is longer than the data read from, return this.
    Eof, 

    TcpIo,

}

type Result<T> = ::std::result::Result<T, Error>;

type DomainName = Vec<u8>;

type Port = u16;

pub enum Addr {
    Ipv4(SocketAddrV4),
    DN(DomainName, Port),
}

pub trait Talker<S, U> {
    fn tell<T, W>(&mut self, other: &mut T) where T: Talker<W, S>;

    fn told(&mut self, word: U);
}

pub fn communicate<A, B, T, U>(a: &mut A, b: &mut B)
    where A: Talker<T, U>, B: Talker<U, T>
{
    a.tell(b);
    b.tell(a);
}

pub struct TcpConnection(TcpStream);

impl TcpConnection {
    pub fn read_u8(&mut self) -> Result<u8> {
        let mut buf = [0u8];
        self.read_to_buf(&mut buf)?;
        Ok(buf[0])
    }

    pub fn read_u16(&mut self) -> Result<u16> {
        let mut buf = [0u8; 2];
        self.read_to_buf(&mut buf)?;
        let x = unsafe { *(buf.as_ptr() as *const u16) };
        Ok(u16::from_be(x))
    }

    pub fn read_size(&mut self, size: usize) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(size);
        unsafe { buf.set_len(size); }
        self.read_to_buf(&mut buf)?;
        Ok(buf)
    }

    fn read_at_most(&mut self, size: usize) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(size);
        unsafe { buf.set_len(size); }

        match self.0.read(&mut buf) {
            Ok(0) => Err(Error::Eof),

            Ok(n) => {
                unsafe { buf.set_len(n); }
                Ok(buf)
            },

            _ => Err(Error::TcpIo),
        }
    }

    // in this function the buffer must be fullfilled, or it returns an Eof error
    fn read_to_buf(&mut self, buf: &mut [u8]) -> Result<()> {
        let mut l = 0;

        while l < buf.len() {
            match self.0.read(&mut buf[l..]) {
                Ok(0) => return Err(Error::Eof),
                Ok(n) => l += n,
                Err(_) => return Err(Error::TcpIo),
            }
        }
        Ok(())
    }

    fn write(&mut self, buf: &[u8]) -> Result<()> {
        let mut l = 0;

        while l < buf.len() {
            match self.0.write(&buf[l..]) {
                Ok(n) => l += n,
                Err(_) => return Err(Error::TcpIo),
            }
        }
        Ok(())
    }

    fn shutdown(&mut self) {
        let _ = self.0.shutdown(Shutdown::Both);
    }

    fn shutdown_read(&mut self) {
        let _ = self.0.shutdown(Shutdown::Read);
    }
    
    fn shutdown_write(&mut self) {
        let _ = self.0.shutdown(Shutdown::Write);
    }

}

pub mod client;
