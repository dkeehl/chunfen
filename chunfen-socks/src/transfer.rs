use std::io;
use std::rc::Rc;
use std::cell::RefCell;
use std::net::Shutdown;

use futures::{Poll, Future};
use tokio_io::AsyncRead;
use tokio_tcp::TcpStream;
use bytes::BytesMut;

use crate::utils::boxup;

pub fn pipe<T, S>(a: T, b: S)
    -> Box<Future<Item = (usize, usize), Error = io::Error>>
    where
        T: AsyncRead + io::Write + ShutdownWrite + 'static,
        S: AsyncRead + io::Write + ShutdownWrite + 'static
{
    let r1 = Rc::new(RefCell::new(a));
    let w1 = Rc::new(RefCell::new(b));
    let r2 = w1.clone();
    let w2 = r1.clone();

    let half1 = transfer(r1, w1);
    let half2 = transfer(r2, w2);
    boxup(half1.join(half2))
}

fn transfer<R, W>(reader: Rc<RefCell<R>>, writer: Rc<RefCell<W>>) -> Transfer<R, W>
    where R: AsyncRead + 'static,
          W: io::Write + ShutdownWrite + 'static
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
    reader: Rc<RefCell<R>>,
    writer: Rc<RefCell<W>>,
    buffer: BytesMut,
    closing: bool,
    wlen: usize,
}

impl<R, W> Future for Transfer<R, W>
where R: AsyncRead + 'static,
      W: io::Write + ShutdownWrite + 'static
{
    type Item = usize;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<usize, io::Error> {
        loop {
            if self.closing {
                try_nb!(self.writer.borrow_mut().shutdown_write());
                return Ok(self.wlen.into())
            }

            if self.buffer.is_empty() {
                self.buffer.reserve(2 * 1024);
                let n = try_ready!(
                    self.reader.borrow_mut().read_buf(&mut self.buffer));
                if n == 0 {
                    self.closing = true;
                    continue
                }
            }

            let n = try_nb!(self.writer.borrow_mut().write(&self.buffer));
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
