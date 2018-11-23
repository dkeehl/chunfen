use std::fmt;

use nom::{be_u32, IResult};
use bytes::{BufMut, BytesMut, Bytes};

use chunfen_socks::connector::SocksAddr;
use chunfen_socks::connector::parser::socks_addr;
use crate::utils::{Id, Encode, Decode};

pub const HEARTBEAT_INTERVAL_MS: u32 = 5000;
pub const ALIVE_TIMEOUT_TIME_MS: u64 = 60000;

const HEARTBEAT: u8 = 1;
const HEARTBEAT_RSP: u8 = 2;
const CONNECT: u8 = 3;
const SUCCESS: u8 = 4;
const FAIL: u8 = 5;
const DATA: u8 = 6;
const SHUTDOWN_WRITE: u8 = 7;
const CLOSE_PORT: u8 = 8;

#[derive(PartialEq, Eq, Debug)]
pub enum Msg {
    HeartBeat,
    HeartBeatRsp,
    Connect(Id, SocksAddr),
    Success(Id, SocksAddr),
    Fail(Id),
    Data(Id, Bytes),
    ShutdownWrite(Id),
    ClosePort(Id),
}

impl fmt::Display for Msg {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use self::Msg::*;

        match *self {
            HeartBeat => write!(f, "HeartBeat"),
            HeartBeatRsp => write!(f, "HeartBeatRsp"),
            Connect(id, _) => write!(f, "Port {} wants to connect", id),
            Success(id, _) =>
                write!(f, "Port {} connected", id),
            Fail(id) => write!(f, "Failed to connect port {}", id),
            Data(id, ref buf) =>
                write!(f, "Data for port {} of size {}", id, buf.len()),
            ShutdownWrite(id) => write!(f, "Port {} EOF", id),
            ClosePort(id) => write!(f, "Close port {}", id),
        }
    }
}

impl Encode for Msg {
    fn encode(&self, buf: &mut BytesMut) {
        use self::Msg::*;

        buf.reserve(24);
        match *self {
            HeartBeat => buf.put_u8(HEARTBEAT),
            HeartBeatRsp => buf.put_u8(HEARTBEAT_RSP),
            Connect(id, ref addr) => {
                buf.put_u8(CONNECT);
                buf.put_u32_be(id);
                addr.encode(buf);
            },
            Success(id, ref addr) => {
                buf.put_u8(SUCCESS);
                buf.put_u32_be(id);
                addr.encode(buf);
            },
            Fail(id) => {
                buf.put_u8(FAIL);
                buf.put_u32_be(id);
            }
            Data(id, ref data) => {
                buf.put_u8(DATA);
                buf.put_u32_be(id);
                buf.put_u32_be(data.len() as u32);
                buf.extend_from_slice(&data[..]);
            },
            ShutdownWrite(id) => {
                buf.put_u8(SHUTDOWN_WRITE);
                buf.put_u32_be(id);
            },
            ClosePort(id) => {
                buf.put_u8(CLOSE_PORT);
                buf.put_u32_be(id);
            }
        }
    }
}

impl Decode for Msg {
    fn decode(src: &[u8]) -> IResult<&[u8], Msg> {
        parse_msg(src)
    }
}

// Some helpers
fn to_bytes(bytes: &[u8]) -> Bytes {
    Bytes::from(bytes)
}

named! {
    sized<&[u8], Bytes>,
    do_parse!(
        len: be_u32 >>
        buf: take!(len) >>
        (to_bytes(buf))
    )
}

// Parse Msg
named! {
    heartbeat<&[u8], Msg>,
    map!(tag!([HEARTBEAT]), |_| Msg::HeartBeat)
}

named! {
    heartbeat_rsp<&[u8], Msg>,
    map!(tag!([HEARTBEAT_RSP]), |_| Msg::HeartBeatRsp)
}

named! {
    connect<&[u8], Msg>,
    do_parse!(
        tag!([CONNECT]) >>
        id: be_u32 >>
        addr: socks_addr >>
        (Msg::Connect(id, addr))
    )
}

named! {
    close_port<&[u8], Msg>,
    do_parse!(
        tag!([CLOSE_PORT]) >>
        id: be_u32 >>
        (Msg::ClosePort(id))
    )
}

named! {
    shutdown_write<&[u8], Msg>,
    do_parse!(
        tag!([SHUTDOWN_WRITE]) >>
        id: be_u32 >>
        (Msg::ShutdownWrite(id))
    )
}

named! {
    success<&[u8], Msg>,
    do_parse!(
        tag!([SUCCESS]) >>
        id: be_u32 >>
        addr: socks_addr >>
        (Msg::Success(id, addr))
    )
}

named! {
    data<&[u8], Msg>,
    do_parse!(
        tag!([DATA]) >>
        id: be_u32 >>
        buf: sized >>
        (Msg::Data(id, buf))
    )
}

named! {
    fail<&[u8], Msg>,
    do_parse!(
        tag!([FAIL]) >>
        id: be_u32 >>
        (Msg::Fail(id))
    )
}

named! {
    parse_msg<&[u8], Msg>,
    alt!(
        data |
        connect |
        success |
        fail |
        shutdown_write |
        close_port |
        heartbeat |
        heartbeat_rsp
    )
}

#[cfg(test)]
mod test {
    use super::{sized, parse_msg};
    use nom::Err::Incomplete;
    use nom::Needed::Size;
    use bytes::{BytesMut, Bytes};
    use chunfen_socks::connector::SocksAddr;
    use crate::utils::Encode;

    #[test]
    fn parse_sized() {
        let buf = Bytes::from(&[3, 4][..]);
        assert_eq!(sized(&[0, 0, 0, 2, 3, 4]), Ok((&[][..], buf)));
        assert_eq!(sized(&[0, 0, 1, 0, 2, 3]), Err(Incomplete(Size(256))));
    }

    #[test]
    fn encode_and_parse_msg() {
        use crate::protocol::Msg::*;

        let buf = Bytes::from(&[1,2,3,4][..]);
        let dn = Vec::from(&b"github.com"[..]);
        let ip = [127, 0, 0, 1];
        let port = 80;

        let msgs = [
            HeartBeat,
            HeartBeatRsp,
            Connect(9999, SocksAddr::domain_name(dn, port)),
            Success(17, SocksAddr::ipv4(ip, port)),
            Fail(42),
            Data(1, buf.clone()),
            ShutdownWrite(1),
            ClosePort(1),
        ];

        for msg in msgs.iter() {
            let mut buf = BytesMut::with_capacity(24);
            msg.encode(&mut buf);
            let (remain, val) = parse_msg(&buf).unwrap(); 
            assert_eq!(remain, &[][..]);
            assert_eq!(&val, msg);
        }
    }
}
