use std::io;
use std::io::{Read, Write};

use security::{Session, SessionCommon, PlainText, TLSError, ContentType,};

pub struct ClientSession {
    common: SessionCommon,
    state: Option<Box<State>>,
    shared_key: &'static [u8],
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
    pub fn new(key: &str) -> ClientSession {
        ClientSession {
            common: SessionCommon::new(),
            state: Some(Box::new(ExpectTraffic)),
            shared_key: key.to_string(),
        }
    }

    fn take_received_plaintext(&mut self, bytes: Vec<u8>) {
        self.common.take_received_plaintext(bytes)
    }

    fn send_alert(&mut self, alert: AlertDescription) {
        self.common.send_alert(alert)
    }

    fn send_msg(&mut self, msg: PlainText) {
        self.common.send_msg(msg)
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

fn start_handshake(&mut session: ClientSession) -> NextState {
    let mut hs = HandshakeDetails::new();

    // The client random
    let mut random = [0u8; 32];
    thread_rng().fill_bytes(&mut random);

    // handshake, client hello
    let mut fragment = Vec::new();
    Handshake::client_hello(random).encode(&mut fragment);
    let ch = PlainText {
        content_type: ContentType::Handshake,
        fragment,
    };

    hs.details.add_message(&ch);
    session.send_msg(ch);

    let next = ExpectServerHello(hs);
    Box::new(next)
}

struct ExpectServerHello {
    details: HandshakeDetails,
}

impl ExpectServerHello {
    fn into_expect_server_done(self) -> NextState {
        Box::new(ExpectServerDone(self.details))
    }
}

impl State for ExpectServerHello {
    fn handle(self: Box<Self>, session: &mut ClientSession, msg: Plaintext)
        -> NextStateOrError
    {
        if let Handshake::ServerHello(random) = extract_handshake(&msg)? {
            self.details.server_random = random;
            self.details.add_message(&msg);
            Ok(self.into_expect_server_done())
        } else {
            Err(TLSError::UnexpectedMessage)
        }
    }
}

struct ExpectServerDone {
    details: HandshakeDetails,
}

impl ExpectServerDone {
    fn into_expect_change_cipher_spec(self) -> Box<ExpectChangeCipherSpec> {
        Box::new(ExpectChangeCipherSpec { self.details })
    }

    fn emit_finished(&self, session: &mut ClientSession) {
        let handshake_hash = self.details.get_current_hash();
        let verify_data =
            session.get_key_schedule()
                   .sign_finish(SecretKind::ClientTraffic, &handshake_hash);
        let mut fragment = Vec::new();
        Handshake::Finished(verify_data).encode(&mut fragment);
        let msg = PlainText {
            ContentType: ContentType::Handshake,
            fragment
        };
        self.details.add_message(&msg);
        session.send_msg(msg);
    }
}

impl State for ExpectServerDone {
    fn handle(self: Box<Self>, session: &mut ClientSession, msg: Plaintext)
        -> NextStateOrError
    {
        if let Handshake::ServerHelloDone = extract_handshake(&msg)? {
            self.details.add_message(&msg);
            session.common.send_change_cipher_spec();

            let suite = session.common.get_suite();
            let hash_alg = suite.get_hash_alg();
            let mut key_schedule = KeySchedule::new(hash_alg);
            key_schedule.input_secret(&self.shared_key);
            self.details.start_hash(hash_alg);
            let handshake_hash = self.details.get_current_hash();
            let write_key = key_schedule.derive(SecretKind::ClientTraffic, &handshake_hash);
            let read_key = key_schedule.derive(SecretKind::ServerTraffic, &handshake_hash);
            session.common.set_msg_encryptor(MsgEncryptor::new(&suite, &write_key));
            session.common.set_msg_decryptor(MsgDecryptor::new(&suite, &read_key));

            key_schedule.current_client_traffic_secret = write_key;
            key_schedule.current_server_traffic_secret = read_key;
            session.common.set_key_schedule(key_schedule);

            session.common.we_now_encrypting()

            self.emit_finished(session);
            Ok(self.into_expect_change_cipher_spec())
        } else {
            Err(TLSError::UnexpectedMessage)
        }
    }
}

struct ExpectChangeCipherSpec {
    details: HandshakeDetails,
}

impl ExpectChangeCipherSpec {
    fn into_expect_finished(self) -> Box<ExpectFinished> {
        Box::new(ExpectFinished { details: self.details })
    }
}

impl State for ExpectChangeCipherSpec {
    fn handle(self: Box<Self>, session: &mut ClientSession, msg: Plaintext)
        -> NextStateOrError
    {
        if let PlainText { ContentType: ChangeCipherSpec, fragment } = msg {
            if fragment.is_empty() {
                session.common.peer_now_encrypting();
                Ok(self.into_expect_finished())
            } else {
                Err(TLSError::CorruptData(ContentType::ChangeCipherSpec))
            }
        } else {
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

        let expect_verify_data =
            session.get_key_schedule()
                   .sign_finish(SecretKind::ServerTraffic, &handshake_hash);

        constant_time::verify_slices_are_equal(&expect_verify_data, hash)
            .map_err(|| TLSError::DecryptError)
    }
}

impl State for ExpectFinished {
    fn handle(self: Box<Self>, session: &mut ClientSession, msg: Plaintext)
        -> NextStateOrError
    {
        if let Handshake::Finished(hash) = extract_handshake(&msg)? {
            self.check_finish_hash(session, &hash)?;
            self.details.add_message(&msg);
            session.common.start_traffic();
            Ok(self.into_expect_traffic())
        } else {
            Err(TLSError::UnexpectedMessage)
        }
    }
}

struct ExpectTraffic;

impl State for ExpectTraffic {
    fn handle(self: Box<Self>, session: &mut ClientSession, msg: PlainText)
        -> NextStateOrError
    {
        if let PlainText { content_type: ContentType::ApplicationData, fragment } = msg {
            session.take_received_plaintext(fragment);
            Ok(self)
        } else {
            Err(TLSError::UnexpectedMessage)
        }
    }
}

