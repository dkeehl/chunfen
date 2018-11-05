use std::fmt;

use nom::{IResult, Endianness};
use bytes::{BufMut, BytesMut, Bytes};

use crate::utils::{Id, DomainName, Port, Encode, Decode};

pub const HEARTBEAT_INTERVAL_MS: u32 = 5000;
pub const ALIVE_TIMEOUT_TIME_MS: i64 = 60000;

mod c {
    pub const OPEN_PORT: u8 = 1;
    pub const CLOSE_PORT: u8 = 2;
    pub const SHUTDOWN_WRITE: u8 = 4;
    pub const CONNECT: u8 = 5;
    pub const CONNECT_DOMAIN_NAME: u8 = 6;
    pub const DATA: u8 = 7;
    pub const HEARTBEAT: u8 = 8;
}

mod s {
    pub const CLOSE_PORT: u8 = 1;
    pub const SHUTDOWN_WRITE: u8 = 3;
    pub const CONNECT_OK: u8 = 4;
    pub const DATA: u8 = 5;
    pub const HEARTBEAT_RSP: u8 = 6;
}

const MAX_HEADER_LEN: usize = 1 + 4 + 4;

type PortIp = Bytes;

#[derive(PartialEq, Eq, Debug)]
pub enum ClientMsg {
    HeartBeat,
    OpenPort(Id),
    Connect(Id, PortIp),
    ConnectDN(Id, DomainName, Port),
    Data(Id, Bytes),
    ShutdownWrite(Id),

    ClosePort(Id),
}

#[derive(PartialEq, Eq, Debug)]
pub enum ServerMsg {
    HeartBeatRsp,
    ConnectOK(Id, PortIp),
    Data(Id, Bytes),
    ShutdownWrite(Id),

    ClosePort(Id),
}

impl fmt::Display for ServerMsg {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ServerMsg::*;

        match *self {
            HeartBeatRsp => write!(f, "HeartBeatRsp"),
            ConnectOK(id, ref buf) => {
                let res = if buf.is_empty() {
                    "failed"
                } else {
                    "successed"
                };
                write!(f, "Connect {} on port {}", res, id)
            },
            Data(id, ref buf) =>
                write!(f, "Data for port {} of size {}", id, buf.len()),
            ShutdownWrite(id) => write!(f, "Server EOF of {}", id),
            ClosePort(id) => write!(f, "Close port {}", id),
        }
    }
}

impl fmt::Display for ClientMsg {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::ClientMsg::*;

        match *self {
            HeartBeat => write!(f, "HeartBeat"),
            OpenPort(id) => write!(f, "Request to open port {}", id),
            Connect(id, _) => write!(f, "Port {} connects ip", id),
            ConnectDN(id, ..) => write!(f, "Port {} connects domain name", id),
            Data(id, ref buf) => write!(f, "Data from port {}, size {}", id, buf.len()),
            ShutdownWrite(id) => write!(f, "Client EOF of {}", id),
            ClosePort(id) => write!(f, "Close port {}", id),
        }
    }
}

impl Encode for ClientMsg {
    fn encode(&self, buf: &mut BytesMut) {
        use self::ClientMsg::*;

        if buf.remaining_mut() < MAX_HEADER_LEN {
            buf.reserve(MAX_HEADER_LEN);
        }
        match *self {
            HeartBeat => buf.put_u8(c::HEARTBEAT),

            OpenPort(id) => {
                buf.put_u8(c::OPEN_PORT);
                buf.put_u32_be(id);
            },
            Connect(id, ref addr) => {
                buf.put_u8(c::CONNECT);
                buf.put_u32_be(id);
                buf.put_u32_be(addr.len() as u32);
                buf.extend_from_slice(&addr[..]);
            },
            ConnectDN(id, ref dn, port) => {
                buf.put_u8(c::CONNECT_DOMAIN_NAME);
                buf.put_u32_be(id);
                buf.put_u32_be(dn.len() as u32);
                buf.extend_from_slice(&dn[..]);
                buf.put_u16_be(port);
            },
            Data(id, ref data) => {
                buf.put_u8(c::DATA);
                buf.put_u32_be(id);
                buf.put_u32_be(data.len() as u32);
                buf.extend_from_slice(&data[..]);
            },
            ShutdownWrite(id) => {
                buf.put_u8(c::SHUTDOWN_WRITE);
                buf.put_u32_be(id);
            },
            ClosePort(id) => {
                buf.put_u8(c::CLOSE_PORT);
                buf.put_u32_be(id);
            }
        }
    }
}

impl Encode for ServerMsg {
    fn encode(&self, buf: &mut BytesMut) {
        use self::ServerMsg::*;

        if buf.remaining_mut() < MAX_HEADER_LEN {
            buf.reserve(MAX_HEADER_LEN);
        }
        match *self {
            HeartBeatRsp => buf.put_u8(s::HEARTBEAT_RSP),

            ConnectOK(id, ref addr) => {
                buf.put_u8(s::CONNECT_OK);
                buf.put_u32_be(id);
                buf.put_u32_be(addr.len() as u32);
                buf.extend_from_slice(&addr[..]);
            },
            Data(id, ref data) => {
                buf.put_u8(s::DATA);
                buf.put_u32_be(id);
                buf.put_u32_be(data.len() as u32);
                buf.extend_from_slice(&data[..]);
            },
            ShutdownWrite(id) => {
                buf.put_u8(s::SHUTDOWN_WRITE);
                buf.put_u32_be(id);
            },
            ClosePort(id) => {
                buf.put_u8(s::CLOSE_PORT);
                buf.put_u32_be(id);
            }
        }
    }
}

impl Decode for ClientMsg {
    fn decode(src: &[u8]) -> IResult<&[u8], ClientMsg> {
        parse_client_msg(src)
    }
}

impl Decode for ServerMsg {
    fn decode(src: &[u8]) -> IResult<&[u8], ServerMsg> {
        parse_server_msg(src)
    }
}

// Messgae parses
const BE: Endianness = Endianness::Big;

fn to_bytes(bytes: &[u8]) -> Bytes {
    Bytes::from(bytes)
}

named!(id<&[u8], u32>, u32!(BE));
named!(sized<&[u8], Bytes>, do_parse!(
    len: u32!(BE) >>
    buf: take!(len) >>
    (to_bytes(buf))
));

// Server message.
named!(s_heartbeat_rsp<&[u8], ServerMsg>,
    map!(tag!([s::HEARTBEAT_RSP]), |_| ServerMsg::HeartBeatRsp));

named!(s_close_port<&[u8], ServerMsg>, do_parse!(
    tag!([s::CLOSE_PORT]) >>
    id: id >>
    (ServerMsg::ClosePort(id))
));

named!(s_shutdown_write<&[u8], ServerMsg>, do_parse!(
    tag!([s::SHUTDOWN_WRITE]) >>
    id: id >>
    (ServerMsg::ShutdownWrite(id))
));

named!(s_connect_ok<&[u8], ServerMsg>, do_parse!(
    tag!([s::CONNECT_OK]) >>
    id: id >>
    buf: sized >>
    (ServerMsg::ConnectOK(id, buf))
));

named!(s_data<&[u8], ServerMsg>, do_parse!(
    tag!([s::DATA]) >>
    id: id >>
    buf: sized >>
    (ServerMsg::Data(id, buf))
));

named!(pub parse_server_msg<&[u8], ServerMsg>, alt!(
    s_data |
    s_heartbeat_rsp |
    s_connect_ok |
    s_shutdown_write |
    s_close_port
));


// Client message.
named!(c_heartbeat<&[u8], ClientMsg>,
    map!(tag!([c::HEARTBEAT]), |_| ClientMsg::HeartBeat));

named!(c_open_port<&[u8], ClientMsg>, do_parse!(
    tag!([c::OPEN_PORT]) >>
    id: id >>
    (ClientMsg::OpenPort(id))
));

named!(c_close_port<&[u8], ClientMsg>, do_parse!(
    tag!([c::CLOSE_PORT]) >>
    id: id >>
    (ClientMsg::ClosePort(id))
));

named!(c_connect<&[u8], ClientMsg>, do_parse!(
    tag!([c::CONNECT]) >>
    id: id >>
    buf: sized >>
    (ClientMsg::Connect(id, buf))
));

named!(c_connect_dn<&[u8], ClientMsg>, do_parse!(
    tag!([c::CONNECT_DOMAIN_NAME]) >>
    id: id >>
    buf: sized >>
    port: u16!(BE) >>
    (ClientMsg::ConnectDN(id, buf, port))
));

named!(c_data<&[u8], ClientMsg>, do_parse!(
    tag!([c::DATA]) >>
    id: id >>
    buf: sized >>
    (ClientMsg::Data(id, buf))
));

named!(c_shutdown_write<&[u8], ClientMsg>, do_parse!(
    tag!([c::SHUTDOWN_WRITE]) >>
    id: id >>
    (ClientMsg::ShutdownWrite(id))
));

named!(pub parse_client_msg<&[u8], ClientMsg>, alt!(
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
    use super::{id, sized, parse_server_msg, parse_client_msg};
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
        use crate::protocol::ClientMsg::*;

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
            let (remain, val) = parse_client_msg(&buf).unwrap(); 
            assert_eq!(remain, &[][..]);
            assert_eq!(&val, msg);
        }
    }

    #[test]
    fn encode_and_parse_server_msg() {
        use crate::protocol::ServerMsg::*;

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
            let (remain, val) = parse_server_msg(&buf).unwrap();
            assert_eq!(remain, &[][..]);
            assert_eq!(&val, msg);
        }
    }
}

