use std::io::{Read, Write, self};
use security::{ContentType, PlainText, TLSError, SessionCommon, Session,};

pub struct ServerSession {
    common: SessionCommon,
    state: Option<Box<State>>,
}

impl Read for ServerSession {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.common.read(buf)
    }
}

impl Write for ServerSession {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.common.send_plaintext(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.common.flush_plaintext();
        Ok(())
    }
}

impl ServerSession {
   pub fn new() -> ServerSession {
       ServerSession {
           common: SessionCommon::new(),
           state: Some(Box::new(ExpectTraffic))
       }
   }
   fn process_msg(&mut self, msg: PlainText) -> Result<(), TLSError> {
        match msg.content_type {
            ContentType::Handshake => {
                /*
                self.common.handshake_joiner.take_message(msg)
                    .ok_or_else(|| {
                        self.common.send_alert(AlertDescription::DecryptError);
                        TLSError::CorruptData(ContentType::Handshake)
                    })?;
                self.process_new_handshake_message()
                */
                unreachable!()
            },
            ContentType::Alert => self.common.process_alert(msg),

            _ => self.process_main_protocol(msg),
        }
    }
    
    fn process_main_protocol(&mut self, msg: PlainText) -> Result<(), TLSError> {
        let state = self.state.take().unwrap();
        self.state = Some(state.handle(self, msg)?);
        Ok(())
    }
}

impl Session for ServerSession {
    fn read_tls(&mut self, r: &mut Read) -> Result<usize, io::Error> {
        self.common.read_tls(r)
    }

    fn write_tls(&mut self, w: &mut Write) -> Result<usize, io::Error> {
        self.common.write_tls(w)
    }

    fn is_handshaking(&self) -> bool {
        !self.common.traffic
    }

    fn want_to_write(&self) -> bool {
        !self.common.sendable_tls.is_empty()
    }

    fn want_to_read(&self) -> bool {
        !self.common.has_readable_plaintext()
    }

    fn process_new_packets(&mut self) -> Result<(), TLSError> {
        while let Some(msg) = self.common.msg_deframer.frames.pop_front() {
            let msg = self.common.decrypt_incoming(msg)?;
            self.process_msg(msg)?
        }
        Ok(())
    }

    //fn send_close_notify(&mut self) {
    //    self.common.send_close_notify()
    //}
}

type NextState = Box<State>;
type NextStateOrError = Result<NextState, TLSError>;

trait State {
    fn handle(self: Box<Self>, session: &mut ServerSession, msg: PlainText)
        -> NextStateOrError;
}

struct ExpectTraffic;

impl State for ExpectTraffic {
    fn handle(self: Box<Self>, session: &mut ServerSession, msg: PlainText)
        -> NextStateOrError
    {
        if let PlainText { content_type: ContentType::ApplicationData,
        fragment } = msg {
            session.common.take_received_plaintext(fragment);
            Ok(self)
        } else {
            unreachable!()
        }
    }
}
