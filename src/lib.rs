#![feature(slice_patterns)]
#![allow(unused)]

#[macro_use]
extern crate log;
extern crate time;

use std::net::{TcpStream, Shutdown};
use std::io;
use std::io::{Read, Write};
use std::convert::From;

pub mod socks;
pub mod client;
pub mod server;
pub mod utils;
pub mod protocol;

#[derive(Debug)]
pub enum Error {
    //socks errors
    SocksVersion,
    SocksState,
    SocksRequest,
    SocksDisconnected,
    HandshakeFailed,

    Io,

    //client errors
    LostConnectionToServer,
    ServerClosedConnection,
}

impl From<io::Error> for Error {
    fn from(_: io::Error) -> Error { Error::Io }
}

type Result<T> = ::std::result::Result<T, Error>;

type Id = u32;

type PortIp = Vec<u8>;

type DomainName = Vec<u8>;

type Port = u16;

// A marker identifies stream types.
trait Stream {}

trait WriteStream<T>: Stream {
    fn write_stream(&mut self, msg: T) -> Result<()>;
}

trait ParseStream<T>: Stream {
    fn parse_stream(&mut self) -> Option<T>;
}

struct TcpWrapper(TcpStream);

impl Stream for TcpWrapper {}

trait ReadSize {
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<()>;

    fn read_u8(&mut self) -> Result<u8> {
        let mut buf = [0u8];
        self.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn read_u16(&mut self) -> Result<u16> {
        let mut buf = [0u8; 2];
        self.read_exact(&mut buf)?;
        let x = unsafe { *(buf.as_ptr() as *const u16) };
        Ok(u16::from_be(x))
    }

    fn read_u32(&mut self) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.read_exact(&mut buf)?;
        let x = unsafe { *(buf.as_ptr() as *const u32) };
        Ok(u32::from_be(x))
    }

    fn read_size(&mut self, size: usize) -> Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(size);
        unsafe { buf.set_len(size); }
        self.read_exact(&mut buf)?;
        Ok(buf)
    }
}

trait WriteSize {
    fn write_all(&mut self, buf: &[u8]) -> Result<()>;

    fn write_u8(&mut self, x: u8) -> Result<()> {
        let buf = [x];
        self.write_all(&buf)
    }

    fn write_u16(&mut self, x: u16) -> Result<()> {
        let buf = [0u8; 2];
        unsafe { *(buf.as_ptr() as *mut u16) = x.to_be(); }
        self.write_all(&buf)
    }

    fn write_u32(&mut self, x: u32) -> Result<()> {
        let buf = [0u8; 4];
        unsafe { *(buf.as_ptr() as *mut u32) = x.to_be(); }
        self.write_all(&buf)
    }

}

impl ReadSize for TcpWrapper {
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        Ok(self.0.read_exact(buf)?)
    }
}

impl WriteSize for TcpWrapper {
    fn write_all(&mut self, buf: &[u8]) -> Result<()> {
        Ok(self.0.write_all(buf)?)
    }
}

impl TcpWrapper {
    fn shutdown(&mut self) -> Result<()> {
        Ok(self.0.shutdown(Shutdown::Both)?)
    }

    fn shutdown_read(&mut self) -> Result<()> {
        Ok(self.0.shutdown(Shutdown::Read)?)
    }
    
    fn shutdown_write(&mut self) -> Result<()> {
        Ok(self.0.shutdown(Shutdown::Write)?)
    }

}
