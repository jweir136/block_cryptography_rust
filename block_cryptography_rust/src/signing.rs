use ring::error::Unspecified;
#[allow(unused_imports)]
use ring::{
    rand,
    signature::{self, KeyPair, Ed25519KeyPair, Signature},
};

pub fn generate_keys() -> std::result::Result<Ed25519KeyPair, Unspecified> {
    let rng = rand::SystemRandom::new();
    let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)?;
    let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())?;
    Ok(key_pair)
}

pub fn sign_data(key_pair: &Ed25519KeyPair, data: &[u8]) -> Signature {
    key_pair.sign(data)
}

pub fn verify_data(public_key_bytes: &[u8], data: &[u8], signature: Signature) -> bool {
    let peer_public_key = signature::UnparsedPublicKey::new(&signature::ED25519, public_key_bytes);
    match peer_public_key.verify(data, signature.as_ref()) {
        Ok(()) => { true },
        _ => { false }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn correct_signing_test() {
        let tests: [&str; 3] = [
            "test",
            "hello world",
            "hashing is fun"
        ];

        for test in &tests {
            let keys: Ed25519KeyPair = generate_keys().unwrap();

            let sig = sign_data(&keys, test.as_bytes());
            #[allow(unreachable_patterns)]
            match verify_data(keys.public_key().as_ref(), test.as_bytes(), sig) {
                false => { panic!(); },
                true => {},
                _ => { panic!(); }
            };
        }
    }

    #[test]
    pub fn incorrect_signing_test() {
        let mut keys = generate_keys().unwrap();
        let sig = sign_data(&keys, "test".as_bytes());
        keys = generate_keys().unwrap();

        match verify_data(keys.public_key().as_ref(), "test".as_bytes(), sig) {
            false => {},
            _ => { panic!(); }
        };
    }
}