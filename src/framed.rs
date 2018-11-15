use std::io::{self, Write};
use std::marker::PhantomData;
use std::time::Duration;

use bytes::BytesMut;
use futures::{Future, Poll, Async, Stream, Sink, AsyncSink, StartSend};
use tokio_io::AsyncRead;
use tokio_timer::{sleep, Delay};
use nom::Err::Incomplete;

use crate::utils::{Encode, Decode, tunnel_broken};

const INITIAL_CAPACITY: usize = 8 * 1024;
const BACK_PRESSURE_BOUNDARY: usize = INITIAL_CAPACITY;

// A framed stream with timeout.
// S: A stream
// This structure reads the underlying stream, then parsing to data of type I;
// and can send data of type O.
pub struct Framed<I, O, S> {
    stream: S,
    r_buffer: BytesMut,
    w_buffer: BytesMut,
    may_be_readable: bool,
    duration: Duration,
    timeout_alarm: Option<Delay>,
    closed: bool,
    phantom: PhantomData<(I, O)>,
}

impl<I, O, S> Framed<I, O, S>
where I: Decode,
      O: Encode,
      S: AsyncRead + Write
{
    pub fn new(stream: S, duration: Duration) -> Framed<I, O, S> {
        Framed {
            stream,
            r_buffer: BytesMut::with_capacity(INITIAL_CAPACITY),
            w_buffer: BytesMut::with_capacity(INITIAL_CAPACITY),
            may_be_readable: false,
            duration,
            timeout_alarm: Some(sleep(duration)),
            closed: false,
            phantom: PhantomData,
        }
    }

    fn set_alarm(&mut self) {
        debug_assert!(self.timeout_alarm.is_none());
        let mut alarm = sleep(self.duration);
        // regist the task
        let not_ready = alarm.poll().expect("timer error");
        assert!(!not_ready.is_ready());
        self.timeout_alarm = Some(alarm)
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
        enum ParseResult<T> {
            Ok { msg: T, consumed: usize },
            Incomplete,
            Err,
        }
        loop {
            if self.may_be_readable {
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
                        return Ok(Async::Ready(Some(msg)))
                    }
                    ParseResult::Incomplete => self.may_be_readable = false,
                    ParseResult::Err => 
                        return Err(io::Error::new(io::ErrorKind::InvalidData, "invalid data")),
                }
            }

            if let Some(mut alarm) = self.timeout_alarm.take() {
                if alarm.poll().expect("timer error").is_ready() {
                    self.closed = true;
                    return Err(tunnel_broken("timeout"))
                }
            }

            self.r_buffer.reserve(1024);
            match self.stream.read_buf(&mut self.r_buffer)? {
                Async::NotReady => {
                    self.set_alarm();
                    return Ok(Async::NotReady)
                }
                Async::Ready(0) => return Ok(None.into()),
                Async::Ready(_) => self.may_be_readable = true,
            }
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
        if self.closed {
            return Err(tunnel_broken("timeout"))
        }
        if self.w_buffer.len() > BACK_PRESSURE_BOUNDARY {
            self.poll_complete()?;
            if self.w_buffer.len() > BACK_PRESSURE_BOUNDARY {
                return Ok(AsyncSink::NotReady(msg))
            }
        }
        msg.encode(&mut self.w_buffer);
        Ok(AsyncSink::Ready)
    }

    fn poll_complete(&mut self) -> Poll<(), io::Error> {
        while !self.w_buffer.is_empty() {
            let len = try_nb!(self.stream.write(&self.w_buffer));
            assert!(len > 0);
            self.w_buffer.advance(len);
        }
        try_nb!(self.stream.flush());
        Ok(Async::Ready(()))
    }
}
