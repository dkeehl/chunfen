use std::marker::Sized;
use {Id, PortIp, Port, DomainName, Result, Stream,
    WriteSize, WriteStream, ReadSize, ParseStream,};

pub const HEARTBEAT_INTERVAL_MS: u32 = 5000;
pub const ALIVE_TIMEOUT_TIME_MS: i64 = 60000;

mod cs {
    pub const OPEN_PORT: u8 = 1;
    pub const CLOSE_PORT: u8 = 2;
    pub const SHUTDOWN_WRITE: u8 = 4;
    pub const CONNECT: u8 = 5;
    pub const CONNECT_DOMAIN_NAME: u8 = 6;
    pub const DATA: u8 = 7;
    pub const HEARTBEAT: u8 = 8;
}

mod sc {
    pub const CLOSE_PORT: u8 = 1;
    pub const SHUTDOWN_WRITE: u8 = 3;
    pub const CONNECT_OK: u8 = 4;
    pub const DATA: u8 = 5;
    pub const HEARTBEAT_RSP: u8 = 6;
}

pub enum ClientMsg {
    HeartBeat,
    OpenPort(Id),
    Connect(Id, PortIp),
    ConnectDN(Id, DomainName, Port),
    Data(Id, Vec<u8>),
    ShutdownWrite(Id),

    ClosePort(Id),
}

pub enum ServerMsg {
    HeartBeatRsp,
    ConnectOK(Id, PortIp),
    Data(Id, Vec<u8>),
    ShutdownWrite(Id),

    ClosePort(Id),
}

//
// Data transmission layer
//
impl<T: WriteSize + Stream> WriteStream<ClientMsg> for T {
    fn write_stream(&mut self, msg: ClientMsg) -> Result<()> {
        match msg {
            ClientMsg::HeartBeat => self.write_u8(cs::HEARTBEAT),

            ClientMsg::OpenPort(id) =>
                self.write_u8(cs::OPEN_PORT)
                    .and(self.write_u32(id)),

            ClientMsg::Connect(id, buf) =>
                self.write_u8(cs::CONNECT)
                    .and(self.write_u32(id))
                    .and(self.write_u32(buf.len() as u32))
                    .and(self.write_all(&buf[..])),

            ClientMsg::ConnectDN(id, dn, port) =>
                self.write_u8(cs::CONNECT_DOMAIN_NAME)
                    .and(self.write_u32(id))
                    .and(self.write_u32(dn.len() as u32))
                    .and(self.write_all(&dn[..]))
                    .and(self.write_u16(port)),

            ClientMsg::Data(id, buf) =>
                self.write_u8(cs::DATA)
                    .and(self.write_u32(id))
                    .and(self.write_u32(buf.len() as u32))
                    .and(self.write_all(&buf[..])),

            ClientMsg::ShutdownWrite(id) =>
                self.write_u8(cs::SHUTDOWN_WRITE)
                    .and(self.write_u32(id)),

            ClientMsg::ClosePort(id) =>
                self.write_u8(cs::CLOSE_PORT)
                    .and(self.write_u32(id)),
        }
    }
}

impl<T: WriteSize + Stream> WriteStream<ServerMsg> for T {
    fn write_stream(&mut self, msg: ServerMsg) -> Result<()> {
        match msg {
            ServerMsg::HeartBeatRsp => self.write_u8(sc::HEARTBEAT_RSP),

            ServerMsg::ConnectOK(id, buf) =>
                self.write_u8(sc::CONNECT_OK)
                    .and(self.write_u32(id))
                    .and(self.write_u32(buf.len() as u32))
                    .and(self.write_all(&buf)),

            ServerMsg::Data(id, buf) =>
                self.write_u8(sc::DATA)
                    .and(self.write_u32(id))
                    .and(self.write_u32(buf.len() as u32))
                    .and(self.write_all(&buf)),

            ServerMsg::ShutdownWrite(id) =>
                self.write_u8(sc::SHUTDOWN_WRITE)
                    .and(self.write_u32(id)),

            ServerMsg::ClosePort(id) =>
                self.write_u8(sc::CLOSE_PORT)
                    .and(self.write_u32(id)),
        }
    }
}

impl<T: ReadSize + Stream> ParseStream<ClientMsg> for T {
    fn parse_stream(&mut self) -> Option<ClientMsg> {
        match self.read_u8() {
            Ok(cs::HEARTBEAT) => Some(ClientMsg::HeartBeat),

            Ok(op) => self.read_u32().ok().and_then(|id| {
                match op {
                    cs::OPEN_PORT => Some(ClientMsg::OpenPort(id)),

                    cs::CONNECT =>
                        self.read_u32()
                            .and_then(|size| self.read_size(size as usize))
                            .map(|buf| ClientMsg::Connect(id, buf)).ok(),

                    cs::CONNECT_DOMAIN_NAME =>
                        self.read_u32()
                            .and_then(|size| self.read_size(size as usize))
                            .and_then(|buf| {
                                self.read_u16()
                                    .map(|port| ClientMsg::ConnectDN(id, buf, port))
                            }).ok(),

                    cs::DATA =>
                        self.read_u32()
                            .and_then(|size| self.read_size(size as usize))
                            .map(|buf| ClientMsg::Data(id, buf)).ok(),

                    cs::SHUTDOWN_WRITE => Some(ClientMsg::ShutdownWrite(id)),
                    
                    _ => None,
                }
            }),

            Err(_) => None,
        }
    }
}

impl<T: ReadSize + Stream> ParseStream<ServerMsg> for T {
    fn parse_stream(&mut self) -> Option<ServerMsg> {
        match self.read_u8() {
            Ok(sc::HEARTBEAT_RSP) => Some(ServerMsg::HeartBeatRsp),

            Ok(op) => self.read_u32().ok().and_then(|id| {
                match op {
                    sc::CLOSE_PORT => Some(ServerMsg::ClosePort(id)),

                    sc::SHUTDOWN_WRITE => Some(ServerMsg::ShutdownWrite(id)),

                    sc::CONNECT_OK => 
                        self.read_u32()
                            .and_then(|size| self.read_size(size as usize))
                            .map(|buf| ServerMsg::ConnectOK(id, buf)).ok(),

                    sc::DATA => 
                        self.read_u32()
                            .and_then(|size| self.read_size(size as usize))
                            .map(|buf| ServerMsg::Data(id, buf)).ok(),

                    _ => None,
                }
            }),

            Err(_) => None,
        }
    }
}
