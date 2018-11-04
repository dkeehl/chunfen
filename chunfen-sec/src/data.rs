use std::fmt;
use std::error::Error;

use crate::utils::codec::{Reader, Codec};

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
    pub fn decode(self) -> Option<Message> {
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

    #[cfg(test)]
    pub fn encode(&self, buf: &mut Vec<u8>) {
        self.content_type.encode(buf);
        (self.fragment.len() as u16).encode(buf);
        buf.extend_from_slice(&self.fragment[..]);
    }

    pub fn to_borrowed(&self) -> BorrowedMessage {
        BorrowedMessage {
            ty: self.content_type,
            fragment: &self.fragment
        }
    }

    pub fn build_alert(alert: AlertDescription) -> PlainText {
        let mut fragment: Vec<u8> = Vec::new();
        alert.encode(&mut fragment);
        PlainText {
            content_type: ContentType::Alert,
            fragment,
        }
    }
}

pub enum Message {
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
