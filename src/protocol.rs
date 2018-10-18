use {Id, DomainName, Port, Encode};
use nom::Endianness;
use bytes::{BufMut, BytesMut};

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

type PortIp = BytesMut;

#[derive(PartialEq, Eq, Debug)]
pub enum ClientMsg {
    HeartBeat,
    OpenPort(Id),
    Connect(Id, PortIp),
    ConnectDN(Id, DomainName, Port),
    Data(Id, BytesMut),
    ShutdownWrite(Id),

    ClosePort(Id),
}

#[derive(PartialEq, Eq, Debug)]
pub enum ServerMsg {
    HeartBeatRsp,
    ConnectOK(Id, PortIp),
    Data(Id, BytesMut),
    ShutdownWrite(Id),

    ClosePort(Id),
}

//
// Data transmission layer
//
impl Encode for ClientMsg {
    fn encode(&self) -> BytesMut {
        use protocol::ClientMsg::*;

        let mut buf = BytesMut::new();
        match *self {
            HeartBeat => buf.put_u8(cs::HEARTBEAT),

            OpenPort(id) => {
                buf.put_u8(cs::OPEN_PORT);
                buf.put_u32_be(id);
            },
            Connect(id, ref addr) => {
                buf.put_u8(cs::CONNECT);
                buf.put_u32_be(id);
                buf.put_u32_be(addr.len() as u32);
                buf.put_slice(&addr[..]);
            },
            ConnectDN(id, ref dn, port) => {
                buf.put_u8(cs::CONNECT_DOMAIN_NAME);
                buf.put_u32_be(id);
                buf.put_u32_be(dn.len() as u32);
                buf.put_slice(&dn[..]);
                buf.put_u16_be(port);
            },
            Data(id, ref data) => {
                buf.put_u8(cs::DATA);
                buf.put_u32_be(id);
                buf.put_u32_be(data.len() as u32);
                buf.put_slice(&data[..]);
            },
            ShutdownWrite(id) => {
                buf.put_u8(cs::SHUTDOWN_WRITE);
                buf.put_u32_be(id);
            },
            ClosePort(id) => {
                buf.put_u8(cs::CLOSE_PORT);
                buf.put_u32_be(id);
            }
        }
        buf
    }
}

impl Encode for ServerMsg {
    fn encode(&self) -> BytesMut {
        use protocol::ServerMsg::*;

        let mut buf = BytesMut::new();
        match *self {
            HeartBeatRsp => buf.put_u8(sc::HEARTBEAT_RSP),

            ConnectOK(id, ref addr) => {
                buf.put_u8(sc::CONNECT_OK);
                buf.put_u32_be(id);
                buf.put_u32_be(addr.len() as u32);
                buf.put_slice(&addr[..]);
            },
            Data(id, ref data) => {
                buf.put_u8(sc::DATA);
                buf.put_u32_be(id);
                buf.put_u32_be(data.len() as u32);
                buf.put_slice(&data[..]);
            },
            ShutdownWrite(id) => {
                buf.put_u8(sc::SHUTDOWN_WRITE);
                buf.put_u32_be(id);
            },
            ClosePort(id) => {
                buf.put_u8(sc::CLOSE_PORT);
                buf.put_u32_be(id);
            }
        }
        buf
    }
}

// Messgae parses
const BE: Endianness = Endianness::Big;

fn to_vec(bytes: &[u8]) -> BytesMut {
    let mut buf = BytesMut::new();
    buf.extend_from_slice(bytes);
    buf
}

named!(id<&[u8], u32>, u32!(BE));
named!(sized<&[u8], BytesMut>, do_parse!(
    len: u32!(BE) >>
    buf: take!(len) >>
    (to_vec(buf))
));

// Server message.
named!(s_heartbeat_rsp<&[u8], ServerMsg>,
    map!(tag!([sc::HEARTBEAT_RSP]), |_| ServerMsg::HeartBeatRsp));

named!(s_close_port<&[u8], ServerMsg>, do_parse!(
    tag!([sc::CLOSE_PORT]) >>
    id: id >>
    (ServerMsg::ClosePort(id))
));

named!(s_shutdown_write<&[u8], ServerMsg>, do_parse!(
    tag!([sc::SHUTDOWN_WRITE]) >>
    id: id >>
    (ServerMsg::ShutdownWrite(id))
));

named!(s_connect_ok<&[u8], ServerMsg>, do_parse!(
    tag!([sc::CONNECT_OK]) >>
    id: id >>
    buf: sized >>
    (ServerMsg::ConnectOK(id, buf))
));

named!(s_data<&[u8], ServerMsg>, do_parse!(
    tag!([sc::DATA]) >>
    id: id >>
    buf: sized >>
    (ServerMsg::Data(id, buf))
));

named!(server_msg<&[u8], ServerMsg>, alt!(
    s_data |
    s_heartbeat_rsp |
    s_connect_ok |
    s_shutdown_write |
    s_close_port
));


/*
impl<T: ReadSize> ParseStream<ClientMsg> for T {
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
*/


// Client message.
named!(c_heartbeat<&[u8], ClientMsg>,
    map!(tag!([cs::HEARTBEAT]), |_| ClientMsg::HeartBeat));

named!(c_open_port<&[u8], ClientMsg>, do_parse!(
    tag!([cs::OPEN_PORT]) >>
    id: id >>
    (ClientMsg::OpenPort(id))
));

named!(c_close_port<&[u8], ClientMsg>, do_parse!(
    tag!([cs::CLOSE_PORT]) >>
    id: id >>
    (ClientMsg::ClosePort(id))
));

named!(c_connect<&[u8], ClientMsg>, do_parse!(
    tag!([cs::CONNECT]) >>
    id: id >>
    buf: sized >>
    (ClientMsg::Connect(id, buf))
));

named!(c_connect_dn<&[u8], ClientMsg>, do_parse!(
    tag!([cs::CONNECT_DOMAIN_NAME]) >>
    id: id >>
    buf: sized >>
    port: u16!(BE) >>
    (ClientMsg::ConnectDN(id, buf, port))
));

named!(c_data<&[u8], ClientMsg>, do_parse!(
    tag!([cs::DATA]) >>
    id: id >>
    buf: sized >>
    (ClientMsg::Data(id, buf))
));

named!(c_shutdown_write<&[u8], ClientMsg>, do_parse!(
    tag!([cs::SHUTDOWN_WRITE]) >>
    id: id >>
    (ClientMsg::ShutdownWrite(id))
));

named!(client_msg<&[u8], ClientMsg>, alt!(
    c_data |
    c_heartbeat |
    c_open_port |
    c_close_port |
    c_connect |
    c_connect_dn |
    c_shutdown_write
));


#[cfg(test)]
mod test {
    use super::{id, sized, server_msg, client_msg};
    use nom::Err::Incomplete;
    use nom::Needed::Size;
    use bytes::BytesMut;
    use Encode;

    #[test]
    fn parse_id() {
        assert_eq!(id(&[0, 0, 0, 4]), Ok((&[][..], 4)));
        assert_eq!(id(&[0, 0, 1, 1]), Ok((&[][..], 257)));
    }

    #[test]
    fn parse_sized() {
        let mut buf = BytesMut::new();
        buf.extend_from_slice(&[3, 4][..]);
        assert_eq!(sized(&[0, 0, 0, 2, 3, 4]), Ok((&[][..], buf)));
        assert_eq!(sized(&[0, 0, 1, 0, 2, 3]), Err(Incomplete(Size(256))));
    }

    #[test]
    fn encode_and_parse_client_msg() {
        use protocol::ClientMsg::*;

        let buf: [u8; 4] = [1,2,3,4];
        let buf = BytesMut::from(&buf[..]);

        let msgs = [
            HeartBeat,
            OpenPort(42),
            Connect(9999, buf.clone()),
            ConnectDN(17, buf.clone(), 1080),
            Data(1, buf.clone()),
            ShutdownWrite(1),
            ClosePort(1),
        ];

        for msg in msgs.iter() {
            let buf: BytesMut = msg.encode();
            let (remain, val) = client_msg(&buf).unwrap(); 
            assert_eq!(remain, &[][..]);
            assert_eq!(&val, msg);
        }
    }

    #[test]
    fn encode_and_parse_server_msg() {
        use protocol::ServerMsg::*;

        let buf: [u8; 4] = [1,2,3,4];
        let buf = BytesMut::from(&buf[..]);

        let msgs = [
            HeartBeatRsp,
            ConnectOK(42, buf.clone()),
            Data(1, buf.clone()),
            ShutdownWrite(0),
            ClosePort(0),
        ];

        for msg in msgs.iter() {
            let buf: BytesMut = msg.encode();
            let (remain, val) = server_msg(&buf).unwrap();
            assert_eq!(remain, &[][..]);
            assert_eq!(&val, msg);
        }
    }
}

