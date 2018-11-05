use ring::rand::{SystemRandom, SecureRandom};

/// Fill the whole slice with random material.
pub fn fill_random(bytes: &mut [u8]) {
    SystemRandom::new()
        .fill(bytes)
        .unwrap();
}
