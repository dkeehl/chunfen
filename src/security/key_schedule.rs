use ring::{hmac, digest, hkdf};

pub struct KeySchedule {
    current: hmac::SigningKey,
    hash_alg: &'static digest::Algorithm,
    hash_of_empty_message: [u8; digest::MAX_OUTPUT_LEN],
    pub current_client_traffic_secret: Vec<u8>,
    pub current_server_traffic_secret: Vec<u8>,
}

impl KeySchedule {
    pub fn new(hash: &'static digest::Algorithm) -> KeySchedule {
        let zeroes = [0u8; digest::MAX_OUTPUT_LEN];

        let mut empty_hash = [0u8; digest::MAX_OUTPUT_LEN];
        empty_hash[..hash.output_len]
            .clone_from_slice(digest::digest(hash, &[]).as_ref());

        KeySchedule {
            current: hmac::SigningKey::new(hash, &zeroes[..hash.output_len]),
            hash_alg: hash,
            hash_of_empty_message: empty_hash,
            current_server_traffic_secret: Vec::new(),
            current_client_traffic_secret: Vec::new(),
        }
    }

    pub fn input_secret(&mut self, secret: &[u8]) {
        let new = hkdf::extract(&self.current, secret);
        self.current = new
    }

    pub fn derive(&self, kind: SecretKind, hs_hash: &[u8]) -> Vec<u8> {
        debug_assert_eq!(hs_hash.len(), self.hash_alg.output_len);
        _hkdf_expand_label_vec(&self.current,
                               kind.to_bytes(),
                               hs_hash,
                               self.hash_alg.output_len)
    }

    pub fn sign_finish(&self, kind: SecretKind, hash: &[u8]) -> Vec<u8> {
        let base_key = self.current_traffic_secret(kind);
        self.sign_verify_data(base_key, hash)
    }

    fn current_traffic_secret(&self, kind: SecretKind) -> &[u8] {
        match kind {
            SecretKind::ClientTraffic => &self.current_client_traffic_secret,
            SecretKind::ServerTraffic => &self.current_server_traffic_secret,
        }
    }

    fn sign_verify_data(&self, base_key: &[u8], hash: &[u8]) -> Vec<u8> {
        debug_assert_eq!(hash.len(), self.hash_alg.output_len);

        let hmac_key =
            _hkdf_expand_label_vec(&hmac::SigningKey::new(self.hash_alg, base_key),
                                   b"finished",
                                   &[],
                                   self.hash_alg.output_len);

        hmac::sign(&hmac::SigningKey::new(self.hash_alg, &hmac_key), hash)
            .as_ref()
            .to_vec()
    }
}

pub enum SecretKind {
    ClientTraffic,
    ServerTraffic,
}

impl SecretKind {
    fn to_bytes(self) -> &'static [u8] {
        match self {
            SecretKind::ClientTraffic => b"c traffic",
            SecretKind::ServerTraffic => b"s traffic",
        }
    }
}

fn _hkdf_expand_label_vec(secret: &ring::hmac::SigningKey,
                          label: &[u8],
                          context: &[u8],
                          len: usize) -> Vec<u8> {
    let mut v = Vec::new();
    v.resize(len, 0u8);
    _hkdf_expand_label(&mut v, secret, label, context);
    v
}

fn _hkdf_expand_label(output: &mut [u8],
                      secret: &ring::hmac::SigningKey,
                      label: &[u8],
                      context: &[u8]) {
    let label_prefix = b"tls13 ";

    let mut hkdflabel = Vec::new();
    (output.len() as u16).encode(&mut hkdflabel);
    ((label.len() + label_prefix.len()) as u8).encode(&mut hkdflabel);
    hkdflabel.extend_from_slice(label_prefix);
    hkdflabel.extend_from_slice(label);
    (context.len() as u8).encode(&mut hkdflabel);
    hkdflabel.extend_from_slice(context);

    ring::hkdf::expand(secret, &hkdflabel, output)
}

pub fn derive_traffic_key(hash_alg: &'static ring::digest::Algorithm,
                      secret: &[u8],
                      len: usize) -> Vec<u8> {
    _hkdf_expand_label_vec(
        &ring::hmac::SigningKey::new(hash_alg, secret), b"key", &[], len)
}

pub fn derive_traffic_iv(hash_alg: &'static ring::digest::Algorithm,
                     secret: &[u8],
                     len: usize) -> Vec<u8> {
    _hkdf_expand_label_vec(
        &ring::hmac::SigningKey::new(hash_alg, secret), b"iv", &[], len)
}

