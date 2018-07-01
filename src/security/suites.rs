
#[allow(non_camel_case_types)]
pub enum BulkAlgorithm {
    AES_128_GCM,
    /// AES_256_GCM,
    /// CHACHA20_POLY1305,
}

pub enum HashAlgorithm {
    /// NONE,
    /// MD5,
    /// SHA1,
    /// SHA224,
    SHA256,
    /// SHA384,
    /// SHA512,
}

pub struct SupportedCipherSuite {
    /// How to do bulk encryption.
    pub bulk: BulkAlgorithm,

    /// How to do hashing.
    pub hash: HashAlgorithm,

    /// Encryption key length, for the bulk algorithm.
    pub enc_key_len: usize,

    /// How long the fixed part of the 'IV' is.
    ///
    /// This isn't usually an IV, but we continue the
    /// terminology misuse to match the standard.
    pub fixed_iv_len: usize,
}

impl SupportedCipherSuite {
    pub fn get_hash_alg(&self) -> &'static ring::digest::Algorithm {
        match self.hash {
            HashAlgorithm::SHA256 => &ring::digest::SHA256,
        }
    }

    pub fn get_aead_alg(&self) -> &'static ring::aead::Algorithm {
        match self.bulk {
            BulkAlgorithm::AES_128_GCM => &ring::aead::AES_128_GCM,
        }
    }

}

pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite = SupportedCipherSuite {
    bulk: BulkAlgorithm::AES_128_GCM,
    hash: HashAlgorithm::SHA256,
    enc_key_len: 16,
    fixed_iv_len: 12,
};
