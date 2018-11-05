use std::io::{self, Read, Write};

use ring::constant_time;

use crate::data::{PlainText, TLSError, ContentType, AlertDescription};
use crate::session::{Session, SessionCommon};
use crate::handshake::{Handshake, HandshakeDetails, extract_handshake, Hash,};
use crate::key_schedule::{SecretKind, KeySchedule,};
use crate::encryption::{MsgEncryptor, MsgDecryptor,};
use crate::utils::rand;
use crate::utils::codec::Codec;

impl_session!(ClientSession, State);

impl ClientSession {
    pub fn new(key: &[u8]) -> ClientSession {
        let mut cs = ClientSession {
            common: SessionCommon::new(),
            state: None,
            shared_key: Vec::from(key),
        };

        cs.state = Some(start_handshake(&mut cs));
        cs
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
    fn handle(mut self: Box<Self>, _session: &mut ClientSession, msg: PlainText)
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
            session.common.get_key_schedule()
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
    fn handle(self: Box<Self>, session: &mut ClientSession, msg: PlainText)
        -> NextStateOrError
    {
        if let PlainText { content_type: ContentType::ApplicationData, fragment } = msg {
            session.common.take_received_plaintext(fragment);
            Ok(self)
        } else {
            warn!("unexpected message, expect application data");
            Err(TLSError::UnexpectedMessage)
        }
    }
}

