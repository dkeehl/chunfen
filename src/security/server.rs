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

struct ExpectClientHello {
    details: HandshakeDetails,
}

impl ExpectClientHello {
    fn into_expect_change_cipher_spec(self) -> Box<ExpectChangeCipherSpec> {
        Box::new(ExpectChangeCipherSpec { details: self.details })
    }

    fn emit_server_hello(&mut self, session: &mut ServerSession) {
        // the server random
        let mut random = [0u8; 32];
        thread_rng().fill_bytes(&mut random);

        let mut fragment = Vec::new();
        Handshake::server_hello(random).encode(&mut fragment);
        let sh = PlainText {
            content_type: ContentType::Handshake,
            fragment,
        };

        self.details.add_message(&sh);
        session.send_msg(sh)
    }

    fn emit_server_hello_done(&mut self, session: &mut ServerSession) {
        let mut fragment = Vec::new();
        Handshake::ServerHelloDone.encode(&mut fragment);
        let m = PlainText {
            content_type: ContentType::Handshake,
            fragment,
        };
        
        self.details.add_message(&m);
        session.send_msg(m)
    }
}

impl State for ExpectClientHello {
    fn handle(self: Box<Self>, session: &mut ServerSession, msg: PlainText)
        - NextStateOrError
    {
        if let Handshake::ClientHello(random) = extract_handshake(&msg) {
            self.details.add_message(&msg);
            self.emit_server_hello(session);
            self.emit_server_hello_done(session);

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
    fn handle(self: Box<Self>, session: &mut ServerSession, msg: PlainText)
        - NextStateOrError
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

    fn emit_finished(&mut self, session: &mut ServerSession) {
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
        session.send_msg(msg)
    }

    fn check_finish_hash(&self, session: &ServerSession, hash: &Hash)
        -> Result<(), TLSError>
    {
        let handshake_hash = self.details.get_current_hash();

        let expect_verify_data =
            session.get_key_schedule()
                   .sign_finish(SecretKind::ServerTraffic, &handshake_hash);

        constant_time::verify_slices_are_equal(&expect_verify_data, hash)
            .map_err(|| TLSError::DecryptError
    }
}

impl State for ExpectFinished {
    fn handle(self: Box<Self>, session: &mut ServerSession, msg: PlainText)
        - NextStateOrError
    {
        if let Handshake::Finished(hash) = extract_handshake(&msg)? {
            self.check_finish_hash(session, &hash)?;
            self.details.add_message(&msg);
            
            session.common.send_change_cipher_spec();
            session.common.we_now_encrypting();

            self.emit_finished(session);
            session.common.start_traffic();
            Ok(self.into_expect_traffic())
        } else {
            Err(TLSError::UnexpectedMessage)
        }
    }
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
