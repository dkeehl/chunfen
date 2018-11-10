use std::io::{self, Write};
use std::net::Shutdown;

use futures::{Async, Poll, Future};
use futures::sync::BiLock;
use tokio_io::AsyncRead;
use tokio_tcp::TcpStream;
use bytes::BytesMut;

pub fn pipe<T, S>(a: T, b: S)
    -> impl Future<Item = (usize, usize), Error = io::Error> + Send
    where
        T: AsyncRead + Write + ShutdownWrite + Send + 'static,
        S: AsyncRead + Write + ShutdownWrite + Send + 'static
{
    let (ar, aw) = BiLock::new(a);
    let (br, bw) = BiLock::new(b);

    let half1 = transfer(ar, bw);
    let half2 = transfer(br, aw);
    half1.join(half2)
}

fn transfer<R, W>(reader: BiLock<R>, writer: BiLock<W>) -> Transfer<R, W>
    where R: AsyncRead + 'static,
          W: Write + ShutdownWrite + 'static
{
    Transfer {
        reader,
        writer,
        buffer: BytesMut::new(),
        closing: false,
        wlen: 0,
    }
}

struct Transfer<R, W> {
    reader: BiLock<R>,
    writer: BiLock<W>,
    buffer: BytesMut,
    closing: bool,
    wlen: usize,
}

macro_rules! ready {
    ($lock: expr) => {
        match $lock.poll_lock() {
            Async::Ready(val) => val,
            Async::NotReady => return Ok(Async::NotReady),
        }
    }
}

impl<R, W> Future for Transfer<R, W>
where R: AsyncRead + 'static,
      W: Write + ShutdownWrite + 'static
{
    type Item = usize;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<usize, io::Error> {
        loop {
            if self.closing {
                let mut writer = ready!(self.writer); 
                try_nb!(writer.shutdown_write());
                return Ok(self.wlen.into())
            }

            if self.buffer.is_empty() {
                self.buffer.reserve(2 * 1024);
                let mut reader = ready!(self.reader);
                let n = try_ready!(reader.read_buf(&mut self.buffer));
                if n == 0 {
                    self.closing = true;
                    continue
                }
            }

            let mut writer = ready!(self.writer);
            let n = try_nb!(writer.write(&self.buffer));
            assert!(n > 0);
            self.buffer.advance(n);
            self.wlen += n;
        }
    }
}

pub trait ShutdownWrite {
    fn shutdown_write(&mut self) -> io::Result<()>;
}

impl ShutdownWrite for TcpStream {
    fn shutdown_write(&mut self) -> io::Result<()> {
        TcpStream::shutdown(self, Shutdown::Write)
    }
}
