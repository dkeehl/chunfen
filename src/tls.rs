use std::io::{self, Read, Write};

use futures::{Poll, Async, Future};
use tokio_tcp::TcpStream;
use tokio_io::AsyncRead;

use chunfen_sec::Session;

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
                let io = self.stream.take().unwrap();
                let session = self.session.take().unwrap();
                let stream = Tls {
                    session,
                    io,
                    eof: false,
                };
                return Ok(Async::Ready(stream))
            }
        }
    }
}

pub struct Tls<S: Session, T: Read + Write> {
    session: S,
    io: T,
    eof: bool,
}

impl<S, T> Read for Tls<S, T> where S: Session, T: Read + Write {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.eof {
            return Ok(0)
        }
        while self.session.want_to_read() {
            if let (0, 0) = self.session.complete_io(&mut self.io)? {
                break
            }
        }
        match self.session.read(buf) {
            Ok(0) => {self.eof = true; Ok(0)},
            Ok(n) => Ok(n),
            Err(ref e) if e.kind() == io::ErrorKind::ConnectionAborted => {
                self.eof = true;
                self.session.send_close_notify();
                Ok(0)
            },
            Err(e) => Err(e),
        }
    }
}

impl<S, T> Write for Tls<S, T> where S: Session, T: Read + Write {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let len = self.session.write(buf)?;
        while self.session.want_to_write() {
            match self.session.complete_io(&mut self.io) {
                Ok(_) => {},
                Err(ref e) if e.kind() == io::ErrorKind::WouldBlock && len != 0 =>
                    break,
                Err(e) => return Err(e),
            }
        }
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.session.flush()?;
        if self.session.want_to_write() {
            self.session.complete_io(&mut self.io)?;
        }
        self.io.flush()
    }
}

impl<S, T> AsyncRead for Tls<S, T> where S: Session, T: Read + Write {}
