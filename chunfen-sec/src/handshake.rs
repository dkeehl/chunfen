use std::io::Write;
use crate::{ContentType, PlainText, TLSError,};
use crate::codec::{Reader, Codec, self,};

use ring::digest;

enum_builder! {@U8
    EnumName: HandshakeType;
    EnumVal{
        //HelloRequest => 0x00,
        ClientHello => 0x01,
        ServerHello => 0x02,
        //NewSessionTicket => 0x04,
        //EndOfEarlyData => 0x05,
        //HelloRetryRequest => 0x06,
        //EncryptedExtensions => 0x08,
        //Certificate => 0x0b,
        //ServerKeyExchange => 0x0c,
        //CertificateRequest => 0x0d,
        ServerHelloDone => 0x0e,
        //CertificateVerify => 0x0f,
        ClientKeyExchange => 0x10,
        Finished => 0x14
        //CertificateURL => 0x15,
        //CertificateStatus => 0x16,
        //KeyUpdate => 0x18,
        //MessageHash => 0xfe
    }
}

pub type Hash = Vec<u8>;

#[derive(Debug)]
pub struct Random([u8; 32]);

impl Codec for Random {
    fn encode(&self, bytes: &mut Vec<u8>) {
        bytes.extend_from_slice(&self.0);
    }

    fn read(r: &mut Reader) -> Option<Random> {
        let mut opaque = [0; 32];
        r.take(32).map(|bytes| {
            opaque.clone_from_slice(bytes);
            Random(opaque)
        })
    }
}

impl Random {
    pub fn from_slice(bytes: &[u8]) -> Random {
        let mut rd = Reader::init(bytes);
        Random::read(&mut rd).unwrap()
    }

    //pub fn write_slice(&self, mut bytes: &[u8]) {
    //    let buf = self.get_encoding();
    //    bytes.write_all(&buf).unwrap();
    //}
}

/*
pub struct HelloPayload {
    pub random: Random,
    pub hash: Hash,
}

impl Codec for HelloPayload {
    fn encode(&self, bytes: &mut Vec<u8>) {
        self.random.encode(bytes);
        bytes.extend_from_slice(&self.hash);
    }

    fn read(r: &mut Reader) -> Option<HelloPayload> {
        Random::read(r).map(|random|
            HelloPayload { random, hash: r.rest().to_vec() })
    }
}
*/

#[derive(Debug)]
pub enum Handshake {
    ClientHello(Random),
    ServerHello(Random),
    ServerHelloDone,
    ClientKeyExchange(Vec<u8>),
    Finished(Hash),
}

impl Handshake {
    pub fn client_hello(rand: [u8; 32]) -> Handshake {
        Handshake::ClientHello(Random(rand))
    }

    pub fn server_hello(rand: [u8; 32]) -> Handshake {
        Handshake::ServerHello(Random(rand))
    }
}

impl Codec for Handshake {
    fn encode(&self, bytes: &mut Vec<u8>) {
        match *self {
            Handshake::ClientHello(ref rand) => {
                HandshakeType::ClientHello.encode(bytes);
                let mut buf = Vec::new();
                rand.encode(&mut buf);
                codec::u24(buf.len() as u32).encode(bytes);
                bytes.append(&mut buf);
            }
            Handshake::ServerHello(ref rand) => {
                HandshakeType::ServerHello.encode(bytes);
                let mut buf = Vec::new();
                rand.encode(&mut buf);
                codec::u24(buf.len() as u32).encode(bytes);
                bytes.append(&mut buf);
            }
            Handshake::ServerHelloDone => {
                HandshakeType::ServerHelloDone.encode(bytes);
                codec::u24(0).encode(bytes);
            }
            Handshake::ClientKeyExchange(ref sec) => {
                HandshakeType::ClientKeyExchange.encode(bytes);
                codec::u24(sec.len() as u32).encode(bytes);
                bytes.extend_from_slice(sec);
            }
            Handshake::Finished(ref data) => {
                HandshakeType::Finished.encode(bytes);
                codec::u24(data.len() as u32).encode(bytes);
                bytes.extend_from_slice(data);
            }
        }
    }

    fn read(r: &mut Reader) -> Option<Handshake> {
        HandshakeType::read(r).and_then(|typ| 
        codec::u24::read(r).and_then(   |len| 
        r.sub(len.0 as usize).and_then( |mut sub| 
        match typ {
            HandshakeType::ClientHello =>
                Random::read(&mut sub)
                    .map(|rand| Handshake::ClientHello(rand)),

            HandshakeType::ServerHello =>
                Random::read(&mut sub)
                    .map(|rand| Handshake::ServerHello(rand)),

            HandshakeType::ServerHelloDone =>
                if sub.any_left() {
                    None
                } else {
                    Some(Handshake::ServerHelloDone)
                },
            HandshakeType::ClientKeyExchange =>
                Some(Handshake::ClientKeyExchange(sub.to_vec())),

            HandshakeType::Finished =>
                Some(Handshake::Finished(sub.to_vec())),

            HandshakeType::Unknown(_) => None,
        })))
    }
}

pub fn extract_handshake(msg: &PlainText) -> Result<Handshake, TLSError> {
    if let PlainText { content_type: ContentType::Handshake, ref fragment } = *msg {
        let mut r = Reader::init(fragment);
        Handshake::read(&mut r)
            .ok_or(TLSError::CorruptData(ContentType::Handshake))
    } else {
        Err(TLSError::UnexpectedMessage)
    }
}

pub struct HandshakeDetails {
    pub error: Option<TLSError>,
    transcript: HandshakeHash,
}

impl HandshakeDetails {
    pub fn new() -> HandshakeDetails {
        HandshakeDetails {
            error: None,
            transcript: HandshakeHash::new(),
        }
    }

    pub fn start_hash(&mut self, alg: &'static digest::Algorithm) {
        self.transcript.start_hash(alg)
    }

    pub fn add_message(&mut self, msg: &PlainText) {
        self.transcript.add_message(msg)
    }

    pub fn get_current_hash(&self) -> Vec<u8> {
        self.transcript.get_current_hash()
    }
}

struct HandshakeHash {
    alg: Option<&'static digest::Algorithm>,
    ctx: Option<digest::Context>,
    buffer: Vec<u8>,
}

impl HandshakeHash {
    fn new() -> HandshakeHash {
        HandshakeHash {
            alg: None,
            ctx: None,
            buffer: Vec::new(),
        }
    }

    fn start_hash(&mut self, alg: &'static digest::Algorithm) {
        if let Some(started) = self.alg {
            if started != alg {
                panic!("hash type is changing")
            } else {
                return
            }
        }

        self.alg = Some(alg);
        debug_assert!(self.ctx.is_none());

        let mut ctx = digest::Context::new(alg);
        ctx.update(&self.buffer);
        self.ctx = Some(ctx)
    }

    fn add_message(&mut self, m: &PlainText) {
        match *m {
            PlainText { content_type: ContentType::Handshake, ref fragment } => {
                self.update_raw(fragment);
            },
            _ => unreachable!()
        }
    }

    fn update_raw(&mut self, buf: &[u8]) {
        match self.ctx {
            None => { self.buffer.extend_from_slice(buf); },
            Some(ref mut ctx) => { ctx.update(buf); },
        }
    }

    fn get_current_hash(&self) -> Vec<u8> {
        let hash = self.ctx.as_ref().unwrap().clone().finish();
        let mut vec = Vec::new();
        vec.extend_from_slice(hash.as_ref());
        vec
    }
}


