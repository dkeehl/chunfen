use std::io::{self, Read, Write};

use ring::constant_time;

use crate::data::{PlainText, TLSError, ContentType, AlertDescription};
use crate::session::{Session, SessionCommon, Handler};
use crate::handshake::{Handshake, HandshakeDetails, extract_handshake, Hash,};
use crate::key_schedule::{SecretKind, KeySchedule,};
use crate::encryption::{MsgEncryptor, MsgDecryptor,};
use crate::utils::rand;
use crate::utils::codec::Codec;

session_struct!(ServerSession with state: ServerState);

impl ServerSession {
    pub fn new(key: &[u8]) -> ServerSession {
        let details = HandshakeDetails::new();
        let state = ServerState {
            kind: StateKind::ExpectClientHello,
            details,
        };
        ServerSession { common: SessionCommon::new(key), state: Some(state) }
    }
}

pub struct ServerState {
    kind: StateKind,
    details: HandshakeDetails,
}

#[derive(Debug)]
enum StateKind {
    ExpectClientHello,
    ExpectFinished,
    ExpectTraffic,
}

impl ServerSession {
    fn emit_server_hello(&mut self, details: &mut HandshakeDetails) {
        // the server random
        let mut random = [0u8; 32];
        rand::fill_random(&mut random);

        let mut fragment = Vec::new();
        Handshake::server_hello(random).encode(&mut fragment);
        let sh = PlainText {
            content_type: ContentType::Handshake,
            fragment,
        };

        details.add_message(&sh);
        self.common.send_msg(sh)
    }

    fn emit_server_hello_done(&mut self, details: &mut HandshakeDetails) {
        let mut fragment = Vec::new();
        Handshake::ServerHelloDone.encode(&mut fragment);
        let m = PlainText {
            content_type: ContentType::Handshake,
            fragment,
        };
        
        details.add_message(&m);
        self.common.send_msg(m)
    }

    fn start_encrypt(&mut self, details: &mut HandshakeDetails) {
        let suite = self.common.get_suite();
        let hash_alg = suite.get_hash_alg();
        let mut key_schedule = KeySchedule::new(hash_alg);
        key_schedule.input_secret(self.common.get_shared_key());
        details.start_hash(hash_alg);
        let hs_hash = details.get_current_hash();
        let write_key = key_schedule.derive(SecretKind::ServerTraffic, &hs_hash);
        let read_key = key_schedule.derive(SecretKind::ClientTraffic, &hs_hash);
        self.common.set_msg_encryptor(MsgEncryptor::new(&suite, &write_key));
        self.common.set_msg_decryptor(MsgDecryptor::new(&suite, &read_key));

        key_schedule.current_client_traffic_secret = write_key;
        key_schedule.current_server_traffic_secret = read_key;
        self.common.set_key_schedule(key_schedule);
    }

    fn emit_finished(&mut self, details: &mut HandshakeDetails) { 
        let handshake_hash = details.get_current_hash();
        let verify_data = self.common.get_key_schedule()
            .sign_finish(SecretKind::ClientTraffic, &handshake_hash);
        let mut fragment = Vec::new();
        Handshake::Finished(verify_data).encode(&mut fragment);
        let msg = PlainText {
            content_type: ContentType::Handshake,
            fragment
        };
        details.add_message(&msg);
        self.common.send_msg(msg)
    }

    fn check_finish_hash(&self, details: &mut HandshakeDetails, hash: &Hash)
        -> Result<(), TLSError>
    {
        let handshake_hash = details.get_current_hash();

        let expect_verify_data: Vec<u8> = self.common.get_key_schedule()
            .sign_finish(SecretKind::ServerTraffic, &handshake_hash);

        constant_time::verify_slices_are_equal(&expect_verify_data, hash).map_err(|_| {
            warn!("the client's finish hash is incorrect!");
            TLSError::DecryptError
        })
    }
}
impl Handler for ServerSession {
    type State = ServerState;

    fn handle(&mut self, state: ServerState, msg: PlainText)
        -> Result<ServerState, TLSError>
    {
        use self::StateKind::*;
        use self::ContentType::*;
        use self::Handshake::*;

        let ServerState { kind, mut details } = state;
        let next_state = match (kind, msg) {
            (kind, msg @ PlainText { content_type: Handshake, .. }) => {
                let hs = extract_handshake(&msg)?;
                match (kind, hs) {
                    (ExpectClientHello, ClientHello(..)) => {
                        trace!("Got a client hello");
                        details.add_message(&msg);
                        trace!("Sending server hello");
                        self.emit_server_hello(&mut details);
                        self.emit_server_hello_done(&mut details);
                        self.start_encrypt(&mut details);
                        trace!("Waiting for client finish");
                        ExpectFinished
                    }
                    (ExpectFinished, Finished(hash)) => {
                        trace!("Got client finish, checking hash");
                        self.check_finish_hash(&mut details, &hash)?;
                        trace!("Hash ok, finished");
                        details.add_message(&msg);
                        
                        self.emit_finished(&mut details);
                        self.common.start_traffic();
                        ExpectTraffic
                    }
                    (kind, hs) => {
                        warn!("Unexpected message. {:?}, got {}.", kind, hs);
                        return Err(TLSError::UnexpectedMessage)
                    }
                }
            }
            (ExpectTraffic, PlainText { content_type: ApplicationData, fragment }) => {
                self.common.take_received_plaintext(fragment);
                ExpectTraffic
            }
            (kind, msg) => {
                warn!("Unexpected message. {:?}, got {}.", kind, msg);
                return Err(TLSError::UnexpectedMessage)
            }
        };
        let next = ServerState {
            kind: next_state,
            details,
        };
        Ok(next)
    }
}
