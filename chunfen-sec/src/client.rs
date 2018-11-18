use std::io::{self, Read, Write};

use ring::constant_time;

use crate::data::{PlainText, TLSError, ContentType};
use crate::session::{Session, SessionCommon, Handler};
use crate::handshake::{Handshake, extract_handshake, Hash,};
use crate::key_schedule::{SecretKind, KeySchedule,};
use crate::encryption::{MsgEncryptor, MsgDecryptor,};
use crate::utils::rand;
use crate::utils::codec::Codec;

session_struct!(ClientSession with state: ClientState);

impl ClientSession {
    pub fn new(key: Vec<u8>) -> ClientSession {
        let mut session = ClientSession {
            common: SessionCommon::new(),
            state: None,
            shared_key: key,
        };
        session.start_handshake();
        session
    }

    fn start_handshake(&mut self) {
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

        self.common.hs_transcript.add_message(&ch);
        trace!("Sent client hello, waiting for server hello");
        self.common.send_msg(ch);

        let state = ClientState::ExpectServerHello;
        self.state = Some(state)
    }

    fn start_encrypt(&mut self) {
        let suite = self.common.get_suite();
        let hash_alg = suite.get_hash_alg();
        let mut key_schedule = KeySchedule::new(hash_alg);
        key_schedule.input_secret(&self.shared_key);
        self.common.hs_transcript.start_hash(hash_alg);
        let hs_hash = self.common.hs_transcript.get_current_hash();
        
        let write_key = key_schedule.derive(SecretKind::ClientTraffic, &hs_hash);
        let read_key = key_schedule.derive(SecretKind::ServerTraffic, &hs_hash);
        self.common.set_msg_encryptor(MsgEncryptor::new(suite, &write_key));
        self.common.set_msg_decryptor(MsgDecryptor::new(suite, &read_key));

        key_schedule.current_client_traffic_secret = write_key;
        key_schedule.current_server_traffic_secret = read_key;
        self.common.set_key_schedule(key_schedule);
    }

    fn emit_finished(&mut self) {
        let handshake_hash = self.common.hs_transcript.get_current_hash();
        let verify_data =
            self.common.get_key_schedule()
                   .sign_finish(SecretKind::ClientTraffic, &handshake_hash);
        let mut fragment = Vec::new();
        Handshake::Finished(verify_data).encode(&mut fragment);
        let msg = PlainText {
            content_type: ContentType::Handshake,
            fragment
        };
        self.common.hs_transcript.add_message(&msg);
        self.common.send_msg(msg);
    }

    fn check_finish_hash(&self, hash: &Hash)
        -> Result<(), TLSError>
    {
        let handshake_hash = self.common.hs_transcript.get_current_hash();

        let expect_verify_data: Vec<u8> = self.common.get_key_schedule()
            .sign_finish(SecretKind::ServerTraffic, &handshake_hash);

        constant_time::verify_slices_are_equal(&expect_verify_data, hash).map_err(|_| {
            warn!("then server's finish hash is incorrect!");
            TLSError::DecryptError
        })
    }
}

#[derive(Debug)]
pub enum ClientState {
    ExpectServerHello,
    ExpectServerDone,
    ExpectFinished,
    ExpectTraffic,
}

impl Handler for ClientSession {
    type State = ClientState;

    fn handle(&mut self, state: ClientState, msg: PlainText)
        -> Result<ClientState, TLSError>
    {
        use self::ClientState::*;
        use self::ContentType::*;
        use self::Handshake::*;

        let next_state = match (state, msg) {
            (state, msg @ PlainText { content_type: Handshake, .. }) => {
                let hs = extract_handshake(&msg)?;
                match (state, hs) {
                    (ExpectServerHello, ServerHello(..)) => {
                        trace!("Got server hello, waiting for server hello done");
                        self.common.hs_transcript.add_message(&msg);
                        ExpectServerDone
                    }
                    (ExpectServerDone, ServerHelloDone) => {
                        trace!("Got server hello done");
                        self.common.hs_transcript.add_message(&msg);
                        self.start_encrypt();
                        trace!("Client finished, waiting for server finish");
                        self.emit_finished();
                        ExpectFinished
                    }
                    (ExpectFinished, Finished(hash)) => {
                        trace!("Got server finish, checking hash");
                        self.check_finish_hash(&hash)?;
                        trace!("Hash ok, server finished");
                        self.common.hs_transcript.add_message(&msg);
                        self.common.start_traffic();
                        ExpectTraffic
                    }
                    (state, hs) => {
                        warn!("Unexpected message. {:?}, got {}.", state, hs);
                        return Err(TLSError::UnexpectedMessage)
                    }
                }
            }
            (ExpectTraffic, PlainText { content_type: ApplicationData, fragment }) => {
                self.common.take_received_plaintext(fragment);
                ExpectTraffic
            }
            (state, msg) => {
                warn!("Unexpected message. {:?}, got {}.", state, msg);
                return Err(TLSError::UnexpectedMessage)
            }
        };
        Ok(next_state)
    }
}
