#![feature(slice_patterns)]
#![allow(unused)]

#[macro_use]
extern crate log;
extern crate time;

use std::net::{TcpStream, Shutdown, SocketAddrV4};
use std::io::{Read, Write};

pub mod socks;
pub mod client;
pub mod server;
pub mod utils;

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
    //socks errors
    SocksVersion,
    SocksState,
    SocksRequest,
    SocksDisconnected,
    HandshakeFailed,

    //when reading some data to a buffer,
    //if the buffer length is longer than the data read from, return this.
    Eof, 

    TcpIo,

    //client errors
    LostConnectionToServer,
    ServerClosedConnection,
}

type Result<T> = ::std::result::Result<T, Error>;

type Id = u32;

type DomainName = Vec<u8>;

type Port = u16;

#[derive(Debug)]
enum ClientMsg {
    HeartBeat,
    OpenPort(Id),
    Connect(Id, SocketAddrV4),
    ConnectDN(Id, DomainName, Port),
    Data(Id, Vec<u8>),
    ShutdownWrite(Id),

    ClosePort(Id),
}

enum ServerMsg {
    HeartBeatRsp,
    ConnectOK(Id, Vec<u8>),
    Data(Id, Vec<u8>),
    ShutdownWrite(Id),

    ClosePort(Id),
}

trait WriteTcp<T> {
    fn send(&mut self, msg: T) -> Result<()>;
}

pub struct TcpWrapper(TcpStream);

impl TcpWrapper {
    fn read_u8(&mut self) -> Result<u8> {
        let mut buf = [0u8];
        self.read_to_buf(&mut buf)?;
        Ok(buf[0])
    }

    fn read_u16(&mut self) -> Result<u16> {
        let mut buf = [0u8; 2];
        self.read_to_buf(&mut buf)?;
        let x = unsafe { *(buf.as_ptr() as *const u16) };
        Ok(u16::from_be(x))
    }

    fn read_u32(&mut self) -> Result<u32> {
        let mut buf = [0u8; 4];
        self.read_to_buf(&mut buf)?;
        let x = unsafe { *(buf.as_ptr() as *const u32) };
        Ok(u32::from_be(x))
    }

    fn read_size(&mut self, size: usize) -> Result<Vec<u8>> {
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

    fn write_u8(&mut self, x: u8) -> Result<()> {
        let buf = [x];
        self.write(&buf)
    }

    fn write_u16(&mut self, x: u16) -> Result<()> {
        let buf = [0u8; 2];
        unsafe { *(buf.as_ptr() as *mut u16) = x.to_be(); }
        self.write(&buf)
    }

    fn write_u32(&mut self, x: u32) -> Result<()> {
        let buf = [0u8; 4];
        unsafe { *(buf.as_ptr() as *mut u32) = x.to_be(); }
        self.write(&buf)
    }

    fn shutdown_prim(&mut self, ty: Shutdown) -> Result<()> {
        self.0.shutdown(ty).map_err(|_| Error::TcpIo)
    }

    fn shutdown(&mut self) -> Result<()> {
        self.shutdown_prim(Shutdown::Both)
    }

    fn shutdown_read(&mut self) -> Result<()> {
        self.shutdown_prim(Shutdown::Read)
    }
    
    fn shutdown_write(&mut self) -> Result<()> {
        self.shutdown_prim(Shutdown::Write)
    }

}

