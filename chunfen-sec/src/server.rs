use std::io::{self, Read, Write};

use ring::constant_time;

use crate::data::{PlainText, TLSError, ContentType, AlertDescription};
use crate::session::{Session, SessionCommon};
use crate::handshake::{Handshake, HandshakeDetails, extract_handshake, Hash,};
use crate::key_schedule::{SecretKind, KeySchedule,};
use crate::encryption::{MsgEncryptor, MsgDecryptor,};
use crate::utils::rand;
use crate::utils::codec::Codec;

impl_session!(ServerSession, State);

impl ServerSession {
    pub fn new(key: &[u8]) -> ServerSession {
        let details = HandshakeDetails::new();
        ServerSession {
            common: SessionCommon::new(),
            state: Some(Box::new(ExpectClientHello { details })),
            shared_key: Vec::from(key),
        }
    }
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
    fn into_expect_finished(self) -> Box<ExpectFinished> {
        Box::new(ExpectFinished { details: self.details })
    }

    fn emit_server_hello(&mut self, session: &mut ServerSession) {
        // the server random
        let mut random = [0u8; 32];
        rand::fill_random(&mut random);

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
    fn handle(mut self: Box<Self>, session: &mut ServerSession, msg: PlainText)
        -> NextStateOrError
    {
        if let Handshake::ClientHello(_) = extract_handshake(&msg)? {
            trace!("Got a client hello");
            self.details.add_message(&msg);
            trace!("Sending server hello");
            self.emit_server_hello(session);
            self.emit_server_hello_done(session);

            let suite = session.common.get_suite();
            let hash_alg = suite.get_hash_alg();
            let mut key_schedule = KeySchedule::new(hash_alg);
            key_schedule.input_secret(&session.shared_key[..]);
            self.details.start_hash(hash_alg);
            let handshake_hash = self.details.get_current_hash();
            let write_key = key_schedule.derive(SecretKind::ServerTraffic, &handshake_hash);
            let read_key = key_schedule.derive(SecretKind::ClientTraffic, &handshake_hash);
            session.common.set_msg_encryptor(MsgEncryptor::new(&suite, &write_key));
            session.common.set_msg_decryptor(MsgDecryptor::new(&suite, &read_key));

            key_schedule.current_client_traffic_secret = write_key;
            key_schedule.current_server_traffic_secret = read_key;
            session.common.set_key_schedule(key_schedule);

            //session.common.peer_now_encrypting();
            trace!("Waiting for client finish");
            Ok(self.into_expect_finished())
        } else {
            warn!("unexpected message, expect client hello");
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
            session.common.get_key_schedule()
                   .sign_finish(SecretKind::ClientTraffic, &handshake_hash);
        let mut fragment = Vec::new();
        Handshake::Finished(verify_data).encode(&mut fragment);
        let msg = PlainText {
            content_type: ContentType::Handshake,
            fragment
        };
        self.details.add_message(&msg);
        session.send_msg(msg)
    }

    fn check_finish_hash(&self, session: &ServerSession, hash: &Hash)
        -> Result<(), TLSError>
    {
        let handshake_hash = self.details.get_current_hash();

        let expect_verify_data: Vec<u8> =
            session.common.get_key_schedule()
                   .sign_finish(SecretKind::ServerTraffic, &handshake_hash);

        constant_time::verify_slices_are_equal(&expect_verify_data, hash)
            .map_err(|_| {
                warn!("the client's finish hash is incorrect!");
                TLSError::DecryptError
            })
    }
}

impl State for ExpectFinished {
    fn handle(mut self: Box<Self>, session: &mut ServerSession, msg: PlainText)
        -> NextStateOrError
    {
        if let Handshake::Finished(hash) = extract_handshake(&msg)? {
            trace!("Got client finish, checking hash");
            self.check_finish_hash(session, &hash)?;
            trace!("Hash ok, finished");
            self.details.add_message(&msg);
            
            self.emit_finished(session);
            session.common.start_traffic();
            Ok(self.into_expect_traffic())
        } else {
            warn!("unexpected message, expect client finish");
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
            warn!("unexpected message, expect application data");
            Err(TLSError::UnexpectedMessage)
        }
    }
}
