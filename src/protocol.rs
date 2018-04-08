use std::net::SocketAddrV4;
use {Id, Port, DomainName};

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

#[derive(Debug)]
pub enum ClientMsg {
    HeartBeat,
    OpenPort(Id),
    Connect(Id, SocketAddrV4),
    ConnectDN(Id, DomainName, Port),
    Data(Id, Vec<u8>),
    ShutdownWrite(Id),

    ClosePort(Id),
}

pub enum ServerMsg {
    HeartBeatRsp,
    ConnectOK(Id, Vec<u8>),
    Data(Id, Vec<u8>),
    ShutdownWrite(Id),

    ClosePort(Id),
}

