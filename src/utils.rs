use std::io;
use std::marker::Sized;

use bytes::{BytesMut};
use nom::IResult;

pub type Id = u32;

pub fn tunnel_broken<T: AsRef<str>>(desc: T) -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, desc.as_ref())
}

macro_rules! drop_res {
    ($fut:expr) => ($fut.map(|_| ()).map_err(|_| ()))
}

// Codec
pub trait Encode {
    fn encode(&self, dest: &mut BytesMut);
}

pub trait Decode: Sized {
    fn decode(src: &[u8]) -> IResult<&[u8], Self>;
}
