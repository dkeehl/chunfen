use std::io::{self, Read, Write};

use ring::constant_time;

use crate::{Session, SessionCommon, PlainText, TLSError, ContentType,
    AlertDescription, };
use crate::handshake::{Handshake, HandshakeDetails, extract_handshake, Hash,};
use crate::key_schedule::{SecretKind, KeySchedule,};
use crate::encryption::{MsgEncryptor, MsgDecryptor,};
use crate::codec::Codec;
use crate::rand;

pub struct ClientSession {
    common: SessionCommon,
    state: Option<Box<State>>,
    shared_key: Vec<u8>,
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
}

impl ClientSession {
    pub fn new(key: Vec<u8>) -> ClientSession {
        let mut cs = ClientSession {
            common: SessionCommon::new(),
            state: None,
            shared_key: key,
        };

        cs.state = Some(start_handshake(&mut cs));
        cs
    }

    fn take_received_plaintext(&mut self, bytes: Vec<u8>) {
        self.common.take_received_plaintext(bytes)
    }

    fn send_close_notify(&mut self) {
        self.common.send_close_notify()
    }

    fn send_msg(&mut self, msg: PlainText) {
        self.common.send_msg(msg)
    }

    fn get_key_schedule(&self) -> &KeySchedule {
        self.common.get_key_schedule()
    }

    fn process_msg(&mut self, msg: PlainText) -> Result<(), TLSError> {
        match msg.content_type {
            ContentType::Alert => self.common.process_alert(msg),

            _ => self.process_main_protocol(msg),
        }
    }

    fn process_main_protocol(&mut self, msg: PlainText) -> Result<(), TLSError> {
        let state = self.state.take().unwrap();
        match state.handle(self, msg) {
            Ok(new_state) => {
                self.state = Some(new_state);
                Ok(())
            },
            Err(e) => {
                self.send_close_notify();
                Err(e)
            }
        }
    }
}

type NextState = Box<State>;
type NextStateOrError = Result<NextState, TLSError>;

trait State {
    fn handle(self: Box<Self>, session: &mut ClientSession, msg: PlainText)
        -> NextStateOrError;
}

fn start_handshake(session: &mut ClientSession) -> NextState {
    let mut hs = HandshakeDetails::new();

    // The client random
    let mut random = [0u8; 32];
    rand::fill_random(&mut random);

    // handshake, client hello
    let mut fragment = Vec::new();
    Handshake::client_hello(random).encode(&mut fragment);
    let ch = PlainText {
        content_type: ContentType::Handshake,
        fragment,
    };

    hs.add_message(&ch);
    trace!("Sent client hello, waiting for server hello");
    session.send_msg(ch);

    let next = ExpectServerHello { details: hs };
    Box::new(next)
}

struct ExpectServerHello {
    details: HandshakeDetails,
}

impl ExpectServerHello {
    fn into_expect_server_done(self) -> NextState {
        Box::new(ExpectServerDone { details: self.details })
    }
}

impl State for ExpectServerHello {
    fn handle(mut self: Box<Self>, session: &mut ClientSession, msg: PlainText)
        -> NextStateOrError
    {
        if let Handshake::ServerHello(_) = extract_handshake(&msg)? {
            trace!("Got server hello, waiting for server hello done");
            self.details.add_message(&msg);
            Ok(self.into_expect_server_done())
        } else {
            warn!("unexpected message, expect server hello");
            Err(TLSError::UnexpectedMessage)
        }
    }
}

struct ExpectServerDone {
    details: HandshakeDetails,
}

impl ExpectServerDone {
    fn into_expect_finished(self) -> Box<ExpectFinished> {
        Box::new(ExpectFinished { details: self.details })
    }

    fn emit_finished(&mut self, session: &mut ClientSession) {
        let handshake_hash = self.details.get_current_hash();
        let verify_data =
            session.get_key_schedule()
                   .sign_finish(SecretKind::ClientTraffic, &handshake_hash);
        let mut fragment = Vec::new();
        Handshake::Finished(verify_data).encode(&mut fragment);
        let msg = PlainText {
            content_type: ContentType::Handshake,
            fragment
        };
        self.details.add_message(&msg);
        session.send_msg(msg);
    }
}

impl State for ExpectServerDone {
    fn handle(mut self: Box<Self>, session: &mut ClientSession, msg: PlainText)
        -> NextStateOrError
    {
        if let Handshake::ServerHelloDone = extract_handshake(&msg)? {
            trace!("Got server hello done");
            self.details.add_message(&msg);

            let suite = session.common.get_suite();
            let hash_alg = suite.get_hash_alg();
            let mut key_schedule = KeySchedule::new(hash_alg);
            key_schedule.input_secret(&session.shared_key[..]);
            self.details.start_hash(hash_alg);
            let handshake_hash = self.details.get_current_hash();
            let write_key = key_schedule.derive(SecretKind::ClientTraffic, &handshake_hash);
            let read_key = key_schedule.derive(SecretKind::ServerTraffic, &handshake_hash);
            session.common.set_msg_encryptor(MsgEncryptor::new(suite, &write_key));
            session.common.set_msg_decryptor(MsgDecryptor::new(suite, &read_key));

            key_schedule.current_client_traffic_secret = write_key;
            key_schedule.current_server_traffic_secret = read_key;
            session.common.set_key_schedule(key_schedule);

            trace!("Client finished, waiting for server finish");
            self.emit_finished(session);
            Ok(self.into_expect_finished())
        } else {
            warn!("unexpected message, expect server done");
            Err(TLSError::UnexpectedMessage)
        }
    }
}

struct ExpectFinished {
    details: HandshakeDetails,
}

impl ExpectFinished {
    fn into_expect_traffic(self) -> Box<ExpectTraffic> {
        Box::new(ExpectTraffic)
    }

    fn check_finish_hash(&self, session: &ClientSession, hash: &Hash)
        -> Result<(), TLSError>
    {
        let handshake_hash = self.details.get_current_hash();

        let expect_verify_data: Vec<u8> =
            session.common.get_key_schedule()
                   .sign_finish(SecretKind::ServerTraffic, &handshake_hash);

        constant_time::verify_slices_are_equal(&expect_verify_data, hash)
            .map_err(|_| {
                warn!("then server's finish hash is incorrect!");
                TLSError::DecryptError
            })
    }
}

impl State for ExpectFinished {
    fn handle(mut self: Box<Self>, session: &mut ClientSession, msg: PlainText)
        -> NextStateOrError
    {
        if let Handshake::Finished(hash) = extract_handshake(&msg)? {
            trace!("Got server finish, checking hash");
            self.check_finish_hash(session, &hash)?;
            trace!("Hash ok, server finished");
            self.details.add_message(&msg);
            session.common.start_traffic();
            Ok(self.into_expect_traffic())
        } else {
            warn!("unexpected message, expect server finish");
            Err(TLSError::UnexpectedMessage)
        }
    }
}

struct ExpectTraffic;

impl State for ExpectTraffic {
    fn handle(mut self: Box<Self>, session: &mut ClientSession, msg: PlainText)
        -> NextStateOrError
    {
        if let PlainText { content_type: ContentType::ApplicationData, fragment } = msg {
            session.take_received_plaintext(fragment);
            Ok(self)
        } else {
            warn!("unexpected message, expect application data");
            Err(TLSError::UnexpectedMessage)
        }
    }
}

