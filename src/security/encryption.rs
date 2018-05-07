use security::{PlainText, CipherText, Encrypted, BorrowedMessage, TLSError,};

pub trait MsgEncryptor {
    fn encrypt(&self, m: BorrowedMessage, seq: u64) -> Result<CipherText, TLSError>;
}


pub trait MsgDecryptor {
    fn decrypt(&self, m: CipherText, seq: u64) -> Result<PlainText, TLSError>;
}

pub struct NoEncryption;

impl MsgEncryptor for NoEncryption {
    fn encrypt(&self, m: BorrowedMessage, seq: u64) -> Result<CipherText, TLSError> {
        let BorrowedMessage { ty, fragment } = m;
        let buf = Encrypted::new(fragment.to_vec());
        Ok(CipherText { content_type: ty, fragment: buf })
    }
}

impl MsgDecryptor for NoEncryption {
    fn decrypt(&self, m: CipherText, seq: u64) -> Result<PlainText, TLSError> {
        let CipherText { content_type, fragment } = m;
        Ok(PlainText { content_type, fragment: fragment.extract()})
    }
}

impl MsgEncryptor {
    pub fn plain() -> Box<MsgEncryptor> {
        Box::new(NoEncryption)
    }
}

impl MsgDecryptor {
    pub fn plain() -> Box<MsgDecryptor> {
        Box::new(NoEncryption)
    }
}
