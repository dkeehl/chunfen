use std::io::Write;
use security::{PlainText, CipherText, ContentType, Encrypted,
    BorrowedMessage, TLSError,};
use security::codec::{self, Codec};
use security::fragmenter::MAX_FRAGMENT_LEN;
use security::key_schedule::{derive_traffic_key, derive_traffic_iv};
use security::suites::SupportedCipherSuite;
use ring;

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
        let buf = Encrypted::mark(fragment.to_vec());
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
    
    pub fn new(suite: &SupportedCipherSuite, secret: &[u8]) -> Box<MsgEncryptor> {
        let hash_alg = suite.get_hash_alg();
        let aead_alg = suite.get_aead_alg();
        let enc_key_len = suite.enc_key_len;
        let fixed_iv_len = suite.fixed_iv_len;

        let key = derive_traffic_key(hash_alg, secret, enc_key_len);
        let iv = derive_traffic_iv(hash_alg, secret, fixed_iv_len);
        Box::new(TLS13MessageEncrypter::new(aead_alg, &key, &iv))
    }
}

impl MsgDecryptor {
    pub fn plain() -> Box<MsgDecryptor> {
        Box::new(NoEncryption)
    }

    pub fn new(suite: &SupportedCipherSuite, secret: &[u8]) -> Box<MsgDecryptor> {
        let hash_alg = suite.get_hash_alg();
        let aead_alg = suite.get_aead_alg();
        let enc_key_len = suite.enc_key_len;
        let fixed_iv_len = suite.fixed_iv_len;

        let key = derive_traffic_key(hash_alg, secret, enc_key_len);
        let iv = derive_traffic_iv(hash_alg, secret, fixed_iv_len);
        Box::new(TLS13MessageDecrypter::new(aead_alg, &key, &iv))
    }
}

struct TLS13MessageEncrypter {
    alg: &'static ring::aead::Algorithm,
    enc_key: ring::aead::SealingKey,
    enc_offset: [u8; 12],
}

struct TLS13MessageDecrypter {
    alg: &'static ring::aead::Algorithm,
    dec_key: ring::aead::OpeningKey,
    dec_offset: [u8; 12],
}

impl TLS13MessageEncrypter {
    fn new(alg: &'static ring::aead::Algorithm,
           enc_key: &[u8],
           enc_iv: &[u8]) -> TLS13MessageEncrypter {
        let mut ret = TLS13MessageEncrypter {
            alg: alg,
            enc_key: ring::aead::SealingKey::new(alg, enc_key).unwrap(),
            enc_offset: [0u8; 12],
        };

        ret.enc_offset.as_mut().write_all(enc_iv).unwrap();
        ret
    }
}

impl TLS13MessageDecrypter {
    fn new(alg: &'static ring::aead::Algorithm,
           dec_key: &[u8],
           dec_iv: &[u8]) -> TLS13MessageDecrypter {
        let mut ret = TLS13MessageDecrypter {
            alg: alg,
            dec_key: ring::aead::OpeningKey::new(alg, dec_key).unwrap(),
            dec_offset: [0u8; 12],
        };

        ret.dec_offset.as_mut().write_all(dec_iv).unwrap();
        ret
    }
}

fn xor(accum: &mut [u8], offset: &[u8]) {
    for i in 0..accum.len() {
        accum[i] ^= offset[i];
    }
}

impl MsgEncryptor for TLS13MessageEncrypter {
    fn encrypt(&self, msg: BorrowedMessage, seq: u64) -> Result<CipherText, TLSError> {
        let mut nonce = [0u8; 12];
        codec::put_u64(seq, &mut nonce[4..]);
        xor(&mut nonce, &self.enc_offset);

        // make output buffer with room for content type and tag
        let tag_len = self.alg.tag_len();
        let total_len = msg.fragment.len() + 1 + tag_len;
        let mut buf = Vec::with_capacity(total_len);
        buf.extend_from_slice(msg.fragment);
        msg.ty.encode(&mut buf);
        buf.resize(total_len, 0u8);

        ring::aead::seal_in_place(&self.enc_key, &nonce, &[], &mut buf, tag_len)
            .map_err(|_| TLSError::General("encrypt failed".to_string()))?;

        Ok(CipherText {
            content_type: ContentType::ApplicationData,
            fragment: Encrypted::mark(buf),
        })
    }
}

fn unpad_tls13(v: &mut Vec<u8>) -> ContentType {
    loop {
        match v.pop() {
            Some(0) => {}

            Some(content_type) =>
                return ContentType::read_bytes(&[content_type]).unwrap(),

            None => return ContentType::Unknown(0),
        }
    }
}

impl MsgDecryptor for TLS13MessageDecrypter {
    fn decrypt(&self, mut msg: CipherText, seq: u64) -> Result<PlainText, TLSError> {
        let mut nonce = [0u8; 12];
        codec::put_u64(seq, &mut nonce[4..]);
        xor(&mut nonce, &self.dec_offset);

        let mut buf = msg.fragment.extract();

        if buf.len() < self.alg.tag_len() {
            return Err(TLSError::DecryptError);
        }

        let plain_len = ring::aead::open_in_place(&self.dec_key, &nonce, &[], 0, &mut buf)
            .map_err(|_| TLSError::DecryptError)?
            .len();

        buf.truncate(plain_len);

        if buf.len() > MAX_FRAGMENT_LEN + 1 {
            return Err(TLSError::PeerSentOversizedRecord);
        }

        let content_type = unpad_tls13(&mut buf);
        if content_type == ContentType::Unknown(0) {
            let msg = "peer sent bad TLSInnerPlaintext".to_string();
            return Err(TLSError::PeerMisbehavedError(msg));
        }

        if buf.len() > MAX_FRAGMENT_LEN {
            return Err(TLSError::PeerSentOversizedRecord);
        }

        Ok(PlainText {
            content_type,
            fragment: buf,
        })
    }
}

#[cfg(test)]
mod test {
    use std::vec::Vec;
    use rand::{Rng, thread_rng};
    use security::{PlainText, ContentType};
    use security::codec::Codec;
    use super::{MsgEncryptor, MsgDecryptor};

    const SECRET: &[u8] = b"encryption_test";

    #[test]
    fn encryptions_change_data() {
        let e = MsgEncryptor::new(SECRET);

        for i in 0..5 {
            let mut buf = [0u8; 100];
            thread_rng().fill_bytes(&mut buf);
            let msg = PlainText {
                content_type: ContentType::ApplicationData,
                fragment: buf.to_vec(),
            };

            let cipher = e.encrypt(msg.to_borrowed(), i).unwrap();
            let mut orig = Vec::new();
            let mut enc = Vec::new();
            msg.encode(&mut orig);
            cipher.encode(&mut enc);
            assert_ne!(orig, enc);
        }
    }

    #[test]
    fn decrypt_encryption_id() {
        let e = MsgEncryptor::new(SECRET);
        let d = MsgDecryptor::new(SECRET);

        for i in 0..5 {
            let mut buf = [0u8; 100];
            thread_rng().fill_bytes(&mut buf);
            let msg = PlainText {
                content_type: ContentType::ApplicationData,
                fragment: buf.to_vec(),
            };

            let cipher = e.encrypt(msg.to_borrowed(), i).unwrap();
            let plain = d.decrypt(cipher, i).unwrap();
            assert_eq!(plain, msg);
        }
    }
}
