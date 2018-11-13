use std::io::{self, Write, Read};
use std::net::Shutdown;

use futures::{Async, Poll, Future};
use futures::sync::BiLock;
use tokio_tcp::TcpStream;

// Panics when called out of a tokio run.
pub fn pipe<T, S>(a: T, b: S)
    where
        T: Read + Write + ShutdownWrite + Send + 'static,
        S: Read + Write + ShutdownWrite + Send + 'static
{
    let (ar, aw) = BiLock::new(a);
    let (br, bw) = BiLock::new(b);

    let half1 = transfer(ar, bw).map_err(|_| ());
    let half2 = transfer(br, aw).map_err(|_| ());
    tokio::spawn(half1);
    tokio::spawn(half2);
}

fn transfer<R, W>(reader: BiLock<R>, writer: BiLock<W>) -> Transfer<R, W>
    where R: Read + 'static,
          W: Write + ShutdownWrite + 'static
{
    Transfer {
        reader,
        writer,
        buffer: Box::new([0u8; 4 * 1024]),
        closing: false,
        top: 0,
        pos: 0,
    }
}

struct Transfer<R, W> {
    reader: BiLock<R>,
    writer: BiLock<W>,
    buffer: Box<[u8; 4 * 1024]>,
    closing: bool,
    top: usize,
    pos: usize,
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
where R: Read + 'static,
      W: Write + ShutdownWrite + 'static
{
    type Item = ();
    type Error = io::Error;

    fn poll(&mut self) -> Poll<(), io::Error> {
        assert!(self.pos <= self.top);

        loop {
            if self.closing {
                let mut writer = ready!(self.writer); 
                try_nb!(writer.shutdown_write());
                return Ok(().into())
            }

            if self.top == 0 {
                let mut reader = ready!(self.reader);
                let n = try_nb!(reader.read(&mut self.buffer[..]));
                if n == 0 {
                    self.closing = true;
                    continue
                } else {
                    self.top = n
                }
            }

            let mut writer = ready!(self.writer);
            let n = try_nb!(writer.write(&self.buffer[self.pos..self.top]));
            assert!(n > 0);
            self.pos += n;

            if self.pos == self.top {
                self.pos = 0;
                self.top = 0
            }
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
