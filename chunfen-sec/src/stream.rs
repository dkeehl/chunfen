use std::io::{self, Read, Write};
use crate::session::Session;

pub struct SecureStream<S: Session, T: Read + Write> {
    pub session: S,
    pub socket: T,
}

impl<S, T> SecureStream<S, T> where S: Session, T: Read + Write {
    pub fn new(session: S, socket: T) -> SecureStream<S, T> {
        SecureStream { session, socket }
    }

    pub fn complete_prior_io(&mut self) -> io::Result<()> {
        if self.session.is_handshaking() {
            self.session.complete_io(&mut self.socket)?;
        }

        if self.session.want_to_write() {
            self.session.complete_io(&mut self.socket)?;
        }

        Ok(())
    }
}

impl<S: Session, T: Read + Write> Read for SecureStream<S, T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.complete_prior_io()?;

        while self.session.want_to_read() {
            //println!("starting session io");
            let (rlen, _) = self.session.complete_io(&mut self.socket)?;
            //println!("{} bytes read, {} bytes wrote.", rlen, wlen);
            if rlen == 0 {
                break
            }
        }

        //println!("session io completed");
        self.session.read(buf)
    }
}

impl<S: Session, T: Read + Write> Write for SecureStream<S, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.complete_prior_io()?;

        let len = self.session.write(buf)?;
        self.session.complete_io(&mut self.socket)?;
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.complete_prior_io()?;

        self.session.flush()?;
        if self.session.want_to_write() {
            self.session.complete_io(&mut self.socket)?;
        }
        Ok(())
    }
}

