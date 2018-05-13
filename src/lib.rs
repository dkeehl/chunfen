#![feature(slice_patterns)]
#![allow(unused)]

#[macro_use]
extern crate log;
extern crate time;
extern crate rand;
extern crate ring;

use std::net::{TcpStream, Shutdown};
use std::io;
use std::io::{Read, Write};
use std::convert::From;

pub mod socks;
pub mod client;
pub mod server;
pub mod utils;
pub mod protocol;
pub mod security;

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

trait Stream {
    fn shutdown(&mut self) -> io::Result<()>;
    fn shutdown_read(&mut self) -> io::Result<()>;
    fn shutdown_write(&mut self) -> io::Result<()>;
}

trait WriteStream<T>: Stream {
    fn write_stream(&mut self, msg: T) -> io::Result<()>;
}

trait ParseStream<T>: Stream {
    fn parse_stream(&mut self) -> Option<T>;
}

impl Stream for TcpStream {
    fn shutdown(&mut self) -> io::Result<()> { 
        TcpStream::shutdown(self, Shutdown::Both)
    }

    fn shutdown_read(&mut self) -> io::Result<()> {
        TcpStream::shutdown(self, Shutdown::Read)
    }

    fn shutdown_write(&mut self) -> io::Result<()> {
        TcpStream::shutdown(self, Shutdown::Write)
    }
}

trait ReadSize: Read {
    fn read_u8(&mut self) -> io::Result<u8> {
        let mut buf = [0u8];
        self.read_exact(&mut buf)?;
        Ok(buf[0])
    }

    fn read_u16(&mut self) -> io::Result<u16> {
        let mut buf = [0u8; 2];
        self.read_exact(&mut buf)?;
        let x = unsafe { *(buf.as_ptr() as *const u16) };
        Ok(u16::from_be(x))
    }

    fn read_u32(&mut self) -> io::Result<u32> {
        let mut buf = [0u8; 4];
        self.read_exact(&mut buf)?;
        let x = unsafe { *(buf.as_ptr() as *const u32) };
        Ok(u32::from_be(x))
    }

    fn read_size(&mut self, size: usize) -> io::Result<Vec<u8>> {
        let mut buf = Vec::with_capacity(size);
        unsafe { buf.set_len(size); }
        self.read_exact(&mut buf)?;
        Ok(buf)
    }
}

trait WriteSize: Write {
    fn write_u8(&mut self, x: u8) -> io::Result<()> {
        let buf = [x];
        self.write_all(&buf)
    }

    fn write_u16(&mut self, x: u16) -> io::Result<()> {
        let buf = [0u8; 2];
        unsafe { *(buf.as_ptr() as *mut u16) = x.to_be(); }
        self.write_all(&buf)
    }

    fn write_u32(&mut self, x: u32) -> io::Result<()> {
        let buf = [0u8; 4];
        unsafe { *(buf.as_ptr() as *mut u32) = x.to_be(); }
        self.write_all(&buf)
    }

}

impl ReadSize for TcpStream {}

impl WriteSize for TcpStream {}
