#![allow(unused)]
/// A very limited subset of TLS

#[macro_use]
extern crate log;
extern crate ring;

use std::vec::Vec;
use std::collections::VecDeque;
use std::io::{Read, Write, self};
use std::marker::PhantomData;
use std::fmt;
use std::error::Error;

#[macro_use]
mod macros;

pub mod client;
pub mod server;
pub mod encryption;
pub mod codec;
pub mod handshake;
pub mod key_schedule;
pub mod suites;
pub mod rand;

#[cfg(test)]
mod test;

use crate::codec::{Reader, Codec,};
use crate::encryption::{MsgEncryptor, MsgDecryptor};
use crate::key_schedule::KeySchedule;
use crate::suites::{SupportedCipherSuite, TLS13_AES_128_GCM_SHA256};

enum_builder! {@U8
    EnumName: ContentType;
    EnumVal {
        ChangeCipherSpec => 0x14,
        Alert => 0x15,
        Handshake => 0x16,
        ApplicationData => 0x17
    }
}

#[derive(Clone, PartialEq, Debug)]
pub struct PlainText {
    pub content_type: ContentType,
    pub fragment: Vec<u8>,
}

impl PlainText {
    fn decode(self) -> Option<Message> {
        let PlainText { content_type, fragment } = self;

        match content_type {
            ContentType::Alert => {
                let mut r = Reader::init(&fragment[..]);
                AlertDescription::read(&mut r)
                    .map(|desc| Message::Alert(desc))
            },
            ContentType::ApplicationData => Some(Message::Opaque(fragment)),

            _ => None,
        }
    }

    fn to_borrowed(&self) -> BorrowedMessage {
        BorrowedMessage {
            ty: self.content_type,
            fragment: &self.fragment
        }
    }

    fn build_alert(alert: AlertDescription) -> PlainText {
        let mut fragment: Vec<u8> = Vec::new();
        alert.encode(&mut fragment);
        PlainText {
            content_type: ContentType::Alert,
            fragment,
        }
    }

    fn encode(&self, bytes: &mut Vec<u8>) {
        self.content_type.encode(bytes);
        (self.fragment.len() as u16).encode(bytes);
        bytes.extend_from_slice(&self.fragment);
    }
}

enum Message {
    Alert(AlertDescription),
    Opaque(Vec<u8>),
}

#[derive(Debug)]
pub struct BorrowedMessage<'a> {
    pub ty: ContentType,
    pub fragment: &'a [u8],
}

pub struct Encrypted {
    data: Vec<u8>,
}

impl Encrypted {
    pub fn mark(data: Vec<u8>) -> Encrypted {
        Encrypted { data }
    }

    pub fn extract(self) -> Vec<u8> {
        self.data
    }
}

pub struct CipherText {
    pub content_type: ContentType,
    pub fragment: Encrypted,
}

impl fmt::Debug for CipherText {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "CipherText {{ {:?}, Encrypted data of size {} }}",
               self.content_type,
               self.fragment.data.len())
    }
}

impl Codec for CipherText {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.content_type.encode(bytes);
        (self.fragment.data.len() as u16).encode(bytes);
        bytes.extend_from_slice(&self.fragment.data);
    }
    
    fn read(r: &mut Reader) -> Option<CipherText> {
        ContentType::read(r).and_then(|content_type| {
            u16::read(r).and_then(|len| {
                r.sub(len as usize).and_then(|mut rd| {
                    let data = rd.rest().to_vec();
                    let fragment = Encrypted::mark(data);
                    Some(CipherText { content_type, fragment })
                })
            })
        })
    }
}

enum_builder! {@U8
    EnumName: AlertDescription;
    EnumVal {
        CloseNotify => 0x00
        //UnexpectedMessage => 0x0a,
        //BadRecordMac => 0x14,
        //DecryptionFailed => 0x15,
        //RecordOverflow => 0x16,
        //HandshakeFailure => 0x28,
        //NoCertificate => 0x29,
        //BadCertificate => 0x2a,
        //UnsupportedCertificate => 0x2b,
        //CertificateRevoked => 0x2c,
        //CertificateExpired => 0x2d,
        //CertificateUnknown => 0x2e,
        //IllegalParameter => 0x2f,
        //AccessDenied => 0x31,
        //DecodeError => 0x32,
        //DecryptError => 0x33,
        //InternalError => 0x50,
        //CertificateUnobtainable => 0x6f,
        //UnrecognisedName => 0x70,
        //BadCertificateStatusResponse => 0x71,
        //BadCertificateHashValue => 0x72,
        //UnknownPSKIdentity => 0x73,
        //CertificateRequired => 0x74,
        //NoApplicationProtocol => 0x78
    }
}

#[derive(Debug, PartialEq, Clone)]
pub enum TLSError {
    CorruptData(ContentType),
    AlertReceived(AlertDescription),
    General(String),
    DecryptError,
    PeerSentOversizedRecord,
    PeerMisbehavedError(String),
    UnexpectedMessage,
}

impl fmt::Display for TLSError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            TLSError::CorruptData(ref typ) =>
                write!(f, "{} of type {:?}", self.description(), typ),
            TLSError::AlertReceived(ref alert) =>
                write!(f, "{}, {:?}", self.description(), alert),
            TLSError::PeerMisbehavedError(ref why) =>
                write!(f, "{}, {}", self.description(), why),
            TLSError::DecryptError |
            TLSError::PeerSentOversizedRecord => write!(f, "{}", self.description()),
            _ => write!(f, "{}: {:?}", self.description(), self),
        }
    }
}

impl Error for TLSError {
    fn description(&self) -> &str {
        match *self {
            TLSError::CorruptData(_) => "received corrupt data",
            TLSError::AlertReceived(_) => "received fatal alert",
            TLSError::DecryptError => "cannot decrypt peer's message",
            TLSError::General(_) => "unexpected error",
            TLSError::PeerSentOversizedRecord => "peer sent excess record size",
            TLSError::PeerMisbehavedError(_) => "peer misbehaved",
            TLSError::UnexpectedMessage => "unexpected tls message",
        }
    }
}

pub trait Session: Read + Write {
    fn read_tls(&mut self, r: &mut Read) -> Result<usize, io::Error>;

    fn write_tls(&mut self, w: &mut Write) -> Result<usize, io::Error>;

    fn is_handshaking(&self) -> bool;

    fn want_to_write(&self) -> bool;

    fn want_to_read(&self) -> bool;

    fn process_new_packets(&mut self) -> Result<(), TLSError>;

    //fn send_close_notify(&mut self);

    fn complete_io<T>(&mut self, io: &mut T)
        -> Result<(usize, usize), io::Error> where T: Read + Write
    {
        let until_handshaked = self.is_handshaking();
        let mut eof = false;
        let mut wlen = 0;
        let mut rlen = 0;

        loop {
            while self.want_to_write() {
                wlen += self.write_tls(io)?;
            }

            // Return if this is not a handshake session, and we have
            // successfully written some data.
            if !until_handshaked && wlen > 0 {
                return Ok((rlen, wlen))
            }

            // Reach here either if this is a handshake session, or if
            // we didn't write anything.
            if !eof && self.want_to_read() {
                match self.read_tls(io)? {
                    0 => eof = true,
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

pub struct SecureStream<S: Session, T: Read + Write> {
    pub session: S,
    pub socket: T,
}

impl<S, T> SecureStream<S, T> where S: Session, T: Read + Write {
    pub fn new(session: S, socket: T) -> SecureStream<S, T> {
        SecureStream { session, socket }
    }

    fn complete_prior_io(&mut self) -> io::Result<()> {
        if self.session.is_handshaking() {
            self.session.complete_io(&mut self.socket)?;
        }

        if self.session.want_to_write() {
            self.session.complete_io(&mut self.socket)?;
        }

        Ok(())
    }
}

impl<S: Session, T: Read + Write> Read for SecureStream<S, T> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        self.complete_prior_io()?;

        //while self.session.want_to_read() &&
        //    self.session.complete_io(&mut self.socket)?.0 != 0 {}
        while self.session.want_to_read() {
            //println!("starting session io");
            let (rlen, wlen) = self.session.complete_io(&mut self.socket)?;
            //println!("{} bytes read, {} bytes wrote.", rlen, wlen);
            if rlen == 0 {
                break
            }
        }

        //println!("session io completed");
        self.session.read(buf)
    }
}

impl<S: Session, T: Read + Write> Write for SecureStream<S, T> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.complete_prior_io()?;

        let len = self.session.write(buf)?;
        self.session.complete_io(&mut self.socket)?;
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.complete_prior_io()?;

        self.session.flush()?;
        if self.session.want_to_write() {
            self.session.complete_io(&mut self.socket)?;
        }
        Ok(())
    }
}


struct SessionCommon {
    pub traffic: bool,
    pub peer_eof: bool,

    // Outcoming: sendable_plaintext -> sendable_tls
    // Incoming: msg_deframer -> received_plaintext
    sendable_plaintext: VecBuffer,  // application data, raw
    sendable_tls: VecBuffer,        // raw data
    received_plaintext: VecBuffer,  // application data, raw

    // Buffers incoiming tls cipher text, parsed
    pub msg_deframer: MsgDeframer,

    pub write_seq: u64,
    pub read_seq: u64,
    msg_encryptor: Box<MsgEncryptor>,
    msg_decryptor: Box<MsgDecryptor>,

    suite: Option<&'static SupportedCipherSuite>,
    key_schedule: Option<KeySchedule>,
}

impl SessionCommon {
    pub fn new() -> SessionCommon {
        SessionCommon {
            traffic: false,
            peer_eof: false,

            sendable_plaintext: VecBuffer::new(),
            sendable_tls: VecBuffer::new(),
            received_plaintext: VecBuffer::new(),
            msg_deframer: MsgDeframer::new(),

            //handshake_joiner: HandshakeJoiner::new(),

            write_seq: 0,
            read_seq: 0,
            msg_encryptor: MsgEncryptor::plain(),
            msg_decryptor: MsgDecryptor::plain(),

            // TODO: negotiate to determin a suite
            suite: Some(&TLS13_AES_128_GCM_SHA256), 
            key_schedule: None,
        }
    }

    pub fn has_readable_plaintext(&self) -> bool {
        !self.received_plaintext.is_empty()
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

    pub fn read_tls(&mut self, r: &mut Read) -> Result<usize, io::Error> {
        self.msg_deframer.read_from(r)
    }

    pub fn write_tls(&mut self, w: &mut Write) -> Result<usize, io::Error> {
        self.sendable_tls.write_to(w)
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

    pub fn encrypt_outgoing(&mut self, plain: BorrowedMessage) -> CipherText {
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

    pub fn send_close_notify(&mut self) {
        self.send_alert(AlertDescription::CloseNotify)
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
}

pub mod fragmenter { 
    use crate::{BorrowedMessage, ContentType, PlainText};
    use std::collections::VecDeque;

    pub const MAX_FRAGMENT_LEN: usize = 16384;

    pub fn borrow_split<'a>(ty: ContentType,
                            src: &'a [u8],
                            out: &mut VecDeque<BorrowedMessage<'a>>) {
        for fragment in src.chunks(MAX_FRAGMENT_LEN) {
            let bm = BorrowedMessage { ty, fragment, };
            out.push_back(bm);
        }
    }

    pub fn split(msg: PlainText, out: &mut VecDeque<PlainText>) {
        if msg.fragment.len() <= MAX_FRAGMENT_LEN {
            out.push_back(msg);
            return
        }

        let PlainText { content_type, fragment } = msg;
        for chunk in fragment.chunks(MAX_FRAGMENT_LEN) {
            let m = PlainText {
                content_type,
                fragment: chunk.to_vec(),
            };
            out.push_back(m);
        }
    }
}

struct MsgDeframer {
    pub frames: VecDeque<CipherText>, // completed frames for output
    
    // set to true if the peer not talking in the right protocol
    pub desynced: bool,
    buf: Vec<u8>,
}

const HEADER_SIZE: usize = 1 + 2;
const MAX_MESSAGES: usize = 16384 + 2048 + HEADER_SIZE;

impl MsgDeframer {
    pub fn new() -> MsgDeframer {
        MsgDeframer {
            frames: VecDeque::new(),
            desynced: false,
            buf: Vec::new(),
        }
    }

    pub fn has_pending(&self) -> bool {
        !self.frames.is_empty() || !self.buf.is_empty()
    }

    pub fn read_from(&mut self, r: &mut Read) -> io::Result<usize> {
        let used = self.buf.len();
        self.buf.resize(MAX_MESSAGES, 0u8);

        match r.read(&mut self.buf[used..MAX_MESSAGES]) {
            Ok(new_bytes) => {
                self.buf.truncate(used + new_bytes);
                loop {
                    match self.buf_contains_message() {
                        None => {
                            self.desynced = true;
                            break
                        },
                        Some(true) => {
                            self.deframe_one();
                        },
                        Some(false) => break,
                    }
                }
                Ok(new_bytes)
            },
            Err(e) => {
                self.buf.truncate(used);
                Err(e)
            },
        }
    }

    fn deframe_one(&mut self) {
        let used = {
            let mut r = Reader::init(&self.buf);
            let m = CipherText::read(&mut r).unwrap();
            self.frames.push_back(m);
            r.used()
        };
        self.buf = self.buf.split_off(used);
    }

    fn buf_contains_message(&self) -> Option<bool> {
        if self.buf.len() < HEADER_SIZE {
            return Some(false) 
        }

        check_header(&self.buf).and_then(|len|
            if len >= MAX_MESSAGES - HEADER_SIZE {
                None
            } else {
                let is_full_message = self.buf.len() >= len + HEADER_SIZE;
                Some(is_full_message)
            }
        )
    }
}

fn check_header(buf: &[u8]) -> Option<usize> {
    let mut buf = Reader::init(buf);
    ContentType::read(&mut buf).and_then(|ty| {
        match ty {
            ContentType::Unknown(_) => None,
            _ => u16::read(&mut buf).map(|x| x as usize)
        }
    })
}

struct VecBuffer {
    pub chunks: VecDeque<Vec<u8>>,
}

impl VecBuffer {
    pub fn new() -> VecBuffer {
        VecBuffer { chunks: VecDeque::new() }
    }

    pub fn is_empty(&self) -> bool {
        self.chunks.is_empty()
    }

    pub fn take_one(&mut self) -> Vec<u8> {
        self.chunks.pop_front().unwrap()
    }

    pub fn append(&mut self, bytes: Vec<u8>) -> usize {
        let len = bytes.len();

        if !bytes.is_empty() {
            self.chunks.push_back(bytes);
        }
        len
    }

    pub fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let mut offset = 0;

        while offset < buf.len() && !self.is_empty() {
            let used = self.chunks[0].as_slice().read(&mut buf[offset..])?;
            if used == self.chunks[0].len() {
                self.take_one();
            } else {
                self.chunks[0] = self.chunks[0].split_off(used);
            }
            offset += used;
        }
        Ok(offset)
    }

    pub fn write_to(&mut self, w: &mut Write) -> io::Result<usize> {
        if self.is_empty() {
            Ok(0)
        } else {
            let used = w.write(&self.chunks[0])?;
            if used == self.chunks[0].len() {
                self.take_one();
            } else {
                self.chunks[0] = self.chunks[0].split_off(used);
            }
            Ok(used)
        }
    }
}
