use std::io::{self, Read, Write};

use futures::{Poll, Async, Future};
use tokio_core::net::TcpStream;
use tokio_io::AsyncRead;

use chunfen_sec::{Session, SecureStream};

pub fn connect<T>(session: T, stream: TcpStream)
    -> impl Future<Item=Tls<T, TcpStream>, Error=io::Error>
    where T: Session + 'static
{
    Connect {
        stream: Some(stream),
        session: Some(session),
    }
}

struct Connect<T> {
    stream: Option<TcpStream>,
    session: Option<T>
}

impl<T> Future for Connect<T>
where T: Session + 'static {
    type Item = Tls<T, TcpStream>;
    type Error = io::Error;

    fn poll(&mut self) -> Poll<Self::Item, io::Error> {
        loop {
            if self.session.as_ref().unwrap().is_handshaking() {
                let stream = self.stream.as_mut().unwrap();
                let session = self.session.as_mut().unwrap();
                let _ = try_nb!(session.complete_io(stream));
            } else {
                let stream = self.stream.take().unwrap();
                let session = self.session.take().unwrap();
                let stream = Tls {
                    inner: SecureStream::new(session, stream),
                };
                return Ok(Async::Ready(stream))
            }
        }
    }
}

pub struct Tls<S: Session, T: Read + Write> {
    inner: SecureStream<S, T>
}

impl<S, T> Read for Tls<S, T> where S: Session, T: Read + Write {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.inner.read(buf)
    }
}

impl<S, T> Write for Tls<S, T> where S: Session, T: Read + Write {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.inner.write(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

impl<S, T> AsyncRead for Tls<S, T> where S: Session, T: Read + Write {}
