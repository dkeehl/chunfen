use std::io::{self, Write};
use std::marker::PhantomData;

use bytes::{BufMut, BytesMut};
use futures::{Poll, Async, Stream};
use tokio_core::net::TcpStream;
use tokio_io::AsyncRead;
use nom::Err::Incomplete;

use crate::utils::{Encode, Decode};

pub struct Framed<I, O> {
    stream: TcpStream,
    r_buffer: BytesMut,
    w_buffer: BytesMut,
    phantom: PhantomData<(I, O)>,
}

impl<I, O> Framed<I, O>
where O: Encode
{
    pub fn new(stream: TcpStream) -> Framed<I, O> {
        Framed {
            stream,
            r_buffer: BytesMut::new(),
            w_buffer: BytesMut::new(),
            phantom: PhantomData,
        }
    }

    fn fill_buffer(&mut self) -> Poll<(), io::Error> {
        loop {
            self.r_buffer.reserve(1024);
            let n = try_ready!(self.stream.read_buf(&mut self.r_buffer));
            if n == 0 {
                return Ok(Async::Ready(()))
            }
        }
    }

    pub fn buffer_msg(&mut self, msg: O) {
        msg.encode(&mut self.w_buffer);
    }

    pub fn poll_flush(&mut self) -> Poll<(), io::Error> {
        while !self.w_buffer.is_empty() {
            let len = try_nb!(self.stream.write(&self.w_buffer));
            assert!(len > 0);
            self.w_buffer.advance(len);
        }
        Ok(Async::Ready(()))
    }
}

enum ParseResult<T> {
    Ok { msg: T, consumed: usize },
    Incomplete,
    Err,
}

impl<I, O> Stream for Framed<I, O>
where I: Decode,
      O: Encode
{
    type Item = I;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<I>, io::Error> {
        let eof = self.fill_buffer()?.is_ready();
        let res = {
            match I::decode(&self.r_buffer) {
                Ok((remain, msg)) => {
                    let remain = remain.len();
                    let len = self.r_buffer.len();
                    ParseResult::Ok{ msg, consumed: len - remain }
                },
                Err(Incomplete(_)) => ParseResult::Incomplete,
                Err(e) => {
                    //println!("parse error: {}", e);
                    ParseResult::Err
                },
            }
        };

        match res {
            ParseResult::Ok { msg, consumed } => {
                self.r_buffer.advance(consumed);
                //println!("consumed {}, msg: {}", consumed, msg);
                Ok(Async::Ready(Some(msg)))
            },
            ParseResult::Incomplete => {
                //println!("incomplete, now buffer has {}", self.r_buffer.len());
                if eof {
                        Ok(Async::Ready(None))
                } else {
                    Ok(Async::NotReady)
                }
            },
            ParseResult::Err => 
                Err(io::Error::new(io::ErrorKind::InvalidData, "ServerMsg")),
        }
    }
}

