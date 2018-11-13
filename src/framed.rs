use std::io::{self, Write};
use std::marker::PhantomData;

use time::{get_time, Timespec, Duration};
use bytes::BytesMut;
use futures::{Poll, Async, Stream, Sink, AsyncSink, StartSend};
use futures::sync::BiLock;
use tokio_io::AsyncRead;
use nom::Err::Incomplete;

//use time::precise_time_ns;

use crate::utils::{Encode, Decode, tunnel_broken};

// A framed stream with optional timeout.
// S: A stream
// This structure reads the underlying stream, then parsing to data of type I;
// and can send data of type O.
pub struct Framed<I, O, S> {
    stream: S,
    r_buffer: BytesMut,
    w_buffer: BytesMut,
    timeout: Option<Duration>,
    alive_time: Timespec,
    closed: bool,
    phantom: PhantomData<(I, O)>,
}

impl<I, O, S> Framed<I, O, S>
where I: Decode,
      O: Encode,
      S: AsyncRead + Write
{
    pub fn new(stream: S, timeout: Option<Duration>) -> Framed<I, O, S> {
        Framed {
            stream,
            r_buffer: BytesMut::new(),
            w_buffer: BytesMut::new(),
            timeout,
            alive_time: get_time(),
            closed: false,
            phantom: PhantomData,
        }
    }

    #[allow(unused)]
    pub fn split(self) -> (ReadHalf<I, O, S>, WriteHalf<I, O, S>) {
        let (rd, wt) = BiLock::new(self);
        let rd = ReadHalf { inner: rd };
        let wt = WriteHalf { inner: wt };
        (rd, wt)
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
}

impl<I, O, S> Stream for Framed<I, O, S>
where I: Decode,
      O: Encode,
      S: AsyncRead + Write
{
    type Item = I;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<I>, io::Error> {
        if self.closed {
            return Err(tunnel_broken())
        }
        //let start = precise_time_ns();
        let eof = self.fill_buffer()?.is_ready();

        enum ParseResult<T> {
            Ok { msg: T, consumed: usize },
            Incomplete,
            Err,
        }
        let res = {
            match I::decode(&self.r_buffer) {
                Ok((remain, msg)) => {
                    let remain = remain.len();
                    let len = self.r_buffer.len();
                    ParseResult::Ok{ msg, consumed: len - remain }
                },
                Err(Incomplete(_)) => ParseResult::Incomplete,
                Err(_) => ParseResult::Err,
            }
        };

        match res {
            ParseResult::Ok { msg, consumed } => {
                self.r_buffer.advance(consumed);
                self.alive_time = get_time();
                //println!("polled in {} milliseconds", (precise_time_ns() - start) / 1_000_000);
                Ok(Async::Ready(Some(msg)))
            },
            ParseResult::Incomplete => {
                let timeout = if let Some(dur) = self.timeout {
                    get_time() - self.alive_time > dur
                } else {
                    false
                };
                if eof || timeout {
                    self.closed = true;
                    Ok(Async::Ready(None))
                } else {
                    Ok(Async::NotReady)
                }
            },
            ParseResult::Err => 
                Err(io::Error::new(io::ErrorKind::InvalidData, "invalid data")),
        }
    }
}

impl<I, O, S> Sink for Framed<I, O, S>
where I: Decode,
      O: Encode,
      S: AsyncRead + Write
{
    type SinkItem = O;
    type SinkError = io::Error;

    fn start_send(&mut self, msg: O) -> StartSend<O, io::Error> {
        if !self.closed {
            msg.encode(&mut self.w_buffer);
            Ok(AsyncSink::Ready)
        } else {
            Err(tunnel_broken())
        }
    }

    fn poll_complete(&mut self) -> Poll<(), io::Error> {
        while !self.w_buffer.is_empty() {
            let len = try_nb!(self.stream.write(&self.w_buffer));
            assert!(len > 0);
            self.w_buffer.advance(len);
        }
        Ok(Async::Ready(()))
    }
}

pub struct ReadHalf<I, O, S> {
    inner: BiLock<Framed<I, O, S>>,
}

pub struct WriteHalf<I, O, S> {
    inner: BiLock<Framed<I, O, S>>,
}

impl<I, O, S> Stream for ReadHalf<I, O, S> 
where I: Decode,
      O: Encode,
      S: AsyncRead + Write
{
    type Item = I;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Option<I>, io::Error> {
         match self.inner.poll_lock() {
            Async::Ready(mut s) => s.poll(),
            Async::NotReady => Ok(Async::NotReady),
         }
    }
}

impl<I, O, S> Sink for WriteHalf<I, O, S>
where I: Decode,
      O: Encode,
      S: AsyncRead + Write
{
    type SinkItem = O;
    type SinkError = io::Error;

    fn start_send(&mut self, msg: O) -> StartSend<O, io::Error> {
        match self.inner.poll_lock() {
            Async::Ready(mut stream) => stream.start_send(msg),
            Async::NotReady => Ok(AsyncSink::NotReady(msg)),
        }
    }

    fn poll_complete(&mut self) -> Poll<(), io::Error> {
        match self.inner.poll_lock() {
            Async::Ready(mut stream) => stream.poll_complete(),
            Async::NotReady => Ok(Async::NotReady),
        }
    }
}
