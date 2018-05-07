use std::io;
use std::io::{Read, Write};

use security::{Session, SessionCommon, PlainText, TLSError, ContentType,};

pub struct ClientSession {
    common: SessionCommon,
    state: Option<Box<State>>,
}

impl Read for ClientSession {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.common.read(buf)
    }
}

impl Write for ClientSession {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.common.send_plaintext(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.common.flush_plaintext();
        Ok(())
    }
}

impl Session for ClientSession {
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

impl ClientSession {
    pub fn new() -> ClientSession {
        ClientSession {
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

    /*
    fn process_new_handshake_message(&mut self) -> Result<(), TLSError> {
        while let Some(msg) = self.handshake_joiner.frames.pop_front() {
            self.process_main_protocol(msg)?
        }
        Ok(())
    }
    */

    fn process_main_protocol(&mut self, msg: PlainText) -> Result<(), TLSError> {
        let state = self.state.take().unwrap();
        self.state = Some(state.handle(self, msg)?);
        Ok(())
    }
}

type NextState = Box<State>;
type NextStateOrError = Result<NextState, TLSError>;

trait State {
    fn handle(self: Box<Self>, session: &mut ClientSession, msg: PlainText)
        -> NextStateOrError;
}

struct ExpectTraffic;

impl State for ExpectTraffic {
    fn handle(self: Box<Self>, session: &mut ClientSession, msg: PlainText)
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
/*
struct ExpectServerHello(SecurityParams);

impl ExpectServerHello {
    fn into_expect_server_done(self) -> NextState {
        Box::new(ExpectServerDone(self.0))
    }
}

struct ExpectServerDone(SecurityParams);

fn start_handshake(&mut session: ClientSession) -> NextState {
    let params = SecurityParams::for_client();
    let random = Random::from_slice(&params.client_random);
    let hash = client_key_hash(&params.client_random, &session.common.key);
    let mut fragment = Vec::new();
    Handshake::ClientHello(random, hash).encode_to(&mut fragment);
    let ch = PlainText {
        content_type: ContentType::Handshake,
        fragment,
    };

    session.common.send_msg(ch);

    let next = ExpectServerHello(params);
    Box::new(next)
}

impl State for ExpectServerHello {
    fn handle(self: Box<Self>, session: &mut ClientSession, msg: Plaintext)
        -> NextStateOrError
    {
        if let PlainText { content_type: ContentType::Handshake, fragment } = msg {
            if let Some(Handshake::ServerHello(rand, hash)) = decode(fragment) {
                let hash0 = server_key_hash(&rand, &(*self).0.client_random,
                &session.common.key);
                if hash == hash0 {
                    (*self).0.server_random = rand;
                    Ok(self.into_expect_server_done())
                } else {
                    session.common.send_alert(Alert::Fatal(HANDSHAKE_FAILURE));
                    Err(TLSError::IncorrectKeyHash)
                }
            } else {
                session.common.send_alert(Alert::Fatal(UNEXPECTED_MESSAGE));
                Err(TLSError::UnexpectedMessage)
            }
        } else {
            unreachable!()
        }
    }
}
*/
