use std::io::{self, Read, Write};
use std::collections::VecDeque;

use crate::data::{TLSError, AlertDescription, PlainText, CipherText,
BorrowedMessage, ContentType, Message};
use crate::encryption::{MsgEncryptor, MsgDecryptor};
use crate::key_schedule::KeySchedule;
use crate::suites::{SupportedCipherSuite, TLS13_AES_128_GCM_SHA256};
use crate::utils::codec::Codec;
use crate::utils::{VecBuffer, MsgDeframer, fragmenter};

pub trait Session: Read + Write {
    fn read_tls(&mut self, r: &mut Read) -> Result<usize, io::Error>;

    fn write_tls(&mut self, w: &mut Write) -> Result<usize, io::Error>;

    fn is_handshaking(&self) -> bool;

    fn want_to_write(&self) -> bool;

    fn want_to_read(&self) -> bool;

    fn process_new_packets(&mut self) -> Result<(), TLSError>;

    fn send_close_notify(&mut self);

    fn complete_io<T>(&mut self, io: &mut T)
        -> Result<(usize, usize), io::Error> where T: Read + Write
    {
        let until_handshaked = self.is_handshaking();
        let mut eof = false;
        let mut wlen = 0;
        let mut rlen = 0;

        loop {
            // write to peer
            while self.want_to_write() {
                wlen += self.write_tls(io)?;
            }

            // Return if this is not a handshake session, and we have
            // successfully written some data.
            if !until_handshaked && wlen > 0 {
                return Ok((rlen, wlen))
            }

            // Read peer
            // Reach here either if this is a handshake session, or if
            // we didn't write anything.
            if !eof && self.want_to_read() {
                match self.read_tls(io)? {
                    0 => eof = true,  // peer eof
                    n => rlen += n,
                }
            }

            if let Err(e) = self.process_new_packets() {
                let _ = self.write_tls(io);
                return Err(io::Error::new(io::ErrorKind::InvalidData, e))
            }

            match (eof, until_handshaked, self.is_handshaking()) {
                // Handshake finished
                (_, true, false) => return Ok((rlen, wlen)),
                // Not a handshake session. We have performed
                // either a write_all action or a read action with a
                // process_new_packets action
                (_, false, _) => return Ok((rlen, wlen)),
                // In a handshake session, the handshake is not finished
                // yet, bub we reached an eof.
                (true, true, true) =>
                    return Err(io::Error::from(io::ErrorKind::UnexpectedEof)),
                _ => (),
            }
        }
    }
}

pub struct SessionCommon {
    pub traffic: bool,
    pub peer_eof: bool,

    // Outcoming: sendable_plaintext -> sendable_tls
    // Incoming: msg_deframer -> received_plaintext
    sendable_plaintext: VecBuffer,  // application data, raw
    pub sendable_tls: VecBuffer,    // raw data
    pub received_plaintext: VecBuffer,  // application data, raw

    // Buffers incoiming tls cipher text, parsed
    pub msg_deframer: MsgDeframer,

    pub write_seq: u64,
    pub read_seq: u64,
    msg_encryptor: Box<MsgEncryptor>,
    msg_decryptor: Box<MsgDecryptor>,

    suite: Option<&'static SupportedCipherSuite>,
    key_schedule: Option<KeySchedule>,
    shared_key: Vec<u8>,
}

impl SessionCommon {
    pub fn new(key: &[u8]) -> SessionCommon {
        SessionCommon {
            traffic: false,
            peer_eof: false,

            sendable_plaintext: VecBuffer::new(),
            sendable_tls: VecBuffer::new(),
            received_plaintext: VecBuffer::new(),
            msg_deframer: MsgDeframer::new(),

            write_seq: 0,
            read_seq: 0,
            msg_encryptor: MsgEncryptor::plain(),
            msg_decryptor: MsgDecryptor::plain(),

            // TODO: negotiate to determin a suite
            suite: Some(&TLS13_AES_128_GCM_SHA256), 
            key_schedule: None,
            shared_key: Vec::from(key),
        }
    }

    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let len = self.received_plaintext.read(buf)?;
        if len == 0 && self.connection_at_eof() && self.received_plaintext.is_empty() {
            return Err(io::Error::new(io::ErrorKind::ConnectionAborted,
                                      "CloseNotify alert received."))
        }
        Ok(len)
    }

    fn connection_at_eof(&self) -> bool {
        self.peer_eof && !self.msg_deframer.has_pending()
    }

    pub fn send_plaintext(&mut self, buf: &[u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0)
        }

        let mut plain_messages = VecDeque::new();
        fragmenter::borrow_split(ContentType::ApplicationData, buf, &mut plain_messages);
        
        for m in plain_messages {
            self.send_single_fragment(m);
        }

        Ok(buf.len())
    }

    fn send_single_fragment(&mut self, m: BorrowedMessage) {
        let em = self.encrypt_outgoing(m);
        self.queue_tls_message(em);
    }

    fn queue_tls_message(&mut self, m: CipherText) {
        self.sendable_tls.append(m.get_encoding());
    }

    pub fn flush_plaintext(&mut self) {
        if !self.traffic {
            return
        }

        while !self.sendable_plaintext.is_empty() {
            let buf = self.sendable_plaintext.take_one();
            self.send_plaintext(&buf).unwrap();
        }
    }

    pub fn take_received_plaintext(&mut self, bytes: Vec<u8>) {
        self.received_plaintext.append(bytes);
    }

    pub fn decrypt_incoming(&mut self, msg: CipherText)
        -> Result<PlainText, TLSError> {
        let seq = self.read_seq;
        self.read_seq += 1;
        self.msg_decryptor.decrypt(msg, seq)
    }

    fn encrypt_outgoing(&mut self, plain: BorrowedMessage) -> CipherText {
        let seq = self.write_seq;
        self.write_seq += 1;
        self.msg_encryptor.encrypt(plain, seq).unwrap()
    }

    pub fn process_alert(&mut self, msg: PlainText) -> Result<(), TLSError> {
        error!("Alert received!");

        if let Some(Message::Alert(desc)) = msg.decode() {
            if desc == AlertDescription::CloseNotify {
                self.peer_eof = true;
                Ok(())
            } else {
                Err(TLSError::AlertReceived(desc))
            }
        } else {
            Err(TLSError::CorruptData(ContentType::Alert))
        }
    }

    pub fn send_alert(&mut self, alert: AlertDescription) {
        let m = PlainText::build_alert(alert);
        self.send_msg(m);
    }

    pub fn send_msg(&mut self, msg: PlainText) {
        let mut to_send = VecDeque::new();
        fragmenter::split(msg, &mut to_send);
        for m in to_send {
            self.send_single_fragment(m.to_borrowed());
        }
    }

    pub fn start_traffic(&mut self) { self.traffic = true }

    pub fn set_key_schedule(&mut self, ks: KeySchedule) {
        self.key_schedule = Some(ks);
    }

    pub fn get_key_schedule(&self) -> &KeySchedule {
        self.key_schedule.as_ref().unwrap()
    }

    pub fn get_suite(&self) -> &'static SupportedCipherSuite {
        self.suite.as_ref().unwrap()
    }

    pub fn set_msg_encryptor(&mut self, enc: Box<MsgEncryptor>) {
        self.msg_encryptor = enc;
    }

    pub fn set_msg_decryptor(&mut self, dec: Box<MsgDecryptor>) {
        self.msg_decryptor = dec;
    }

    pub fn get_shared_key(&self) -> &[u8] {
        &self.shared_key
    }
}

pub trait Handler {
    type State: Send + 'static;

    fn handle(&mut self, state: Self::State, msg: PlainText)
        -> Result<Self::State, TLSError>;
}

macro_rules! session_struct {
    ($session:ident with state : $state:ty) => {
        pub struct $session {
            common: SessionCommon,
            state: Option<$state>,
        }

        impl $session {
            fn process_msg(&mut self, msg: PlainText) -> Result<(), TLSError> {
                match msg.content_type {
                    ContentType::Alert => self.common.process_alert(msg),
                    _ => self.process_main_protocol(msg),
                }
            }

            fn process_main_protocol(&mut self, msg: PlainText) -> Result<(), TLSError> {
                let state = self.state.take().unwrap();
                match self.handle(state, msg) {
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

        impl Read for $session {
            fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
                self.common.read(buf)
            }
        }

        impl Write for $session {
            fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
                self.common.send_plaintext(buf)
            }

            fn flush(&mut self) -> io::Result<()> {
                self.common.flush_plaintext();
                Ok(())
            }
        }

        impl Session for $session {
            fn read_tls(&mut self, r: &mut Read) -> Result<usize, io::Error> {
                self.common.msg_deframer.read_from(r)
            }

            fn write_tls(&mut self, w: &mut Write) -> Result<usize, io::Error> {
                self.common.sendable_tls.write_to(w)
            }

            fn is_handshaking(&self) -> bool {
                !self.common.traffic
            }

            fn send_close_notify(&mut self) {
                self.common.send_alert(AlertDescription::CloseNotify)
            }

            fn want_to_write(&self) -> bool {
                !self.common.sendable_tls.is_empty()
            }

            fn want_to_read(&self) -> bool {
                self.common.received_plaintext.is_empty()
            }

            fn process_new_packets(&mut self) -> Result<(), TLSError> {
                while let Some(msg) = self.common.msg_deframer.pop_front() {
                    let msg = self.common.decrypt_incoming(msg)?;
                    self.process_msg(msg)?
                }
                Ok(())
            }
        }
    }
}

