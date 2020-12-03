use std::fs::File;
use std::io::{Read, Write};
use std::path::Path;
use ring::error::Unspecified;
use ring::pkcs8::Document;
#[allow(unused_imports)]
use ring::{
    rand,
    signature::{self, KeyPair, Ed25519KeyPair, Signature},
};

pub type RSAKeyPair = Ed25519KeyPair;
pub type RSASignature = Signature;

pub fn generate_keys() -> std::result::Result<(RSAKeyPair, Document), Unspecified> {
    let rng = rand::SystemRandom::new();
    let pkcs8_bytes = signature::Ed25519KeyPair::generate_pkcs8(&rng)?;
    let key_pair = signature::Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref())?;
    Ok((key_pair, pkcs8_bytes))
}

pub fn sign_data(key_pair: &Ed25519KeyPair, data: &[u8]) -> Signature {
    key_pair.sign(data)
}

pub fn verify_data(public_key_bytes: &[u8], data: &[u8], signature: RSASignature) -> bool {
    let peer_public_key = signature::UnparsedPublicKey::new(&signature::ED25519, public_key_bytes);
    match peer_public_key.verify(data, signature.as_ref()) {
        Ok(()) => { true },
        _ => { false }
    }
}

pub fn save_key(key: &[u8], filename: String) -> Result<(), &str> {
    if Path::new(&filename).is_file() {
        Err("File already exists")
    } else {
        match File::create(filename) {
            Ok(mut fs) =>   {
                            fs.write_all(key).unwrap();
                            fs.flush().unwrap();
                            Ok(())
                        },
            _ =>        {
                            Err("File cannot be created")
                        }
        }
    }
}

pub fn load_key(filename: String) -> Result<RSAKeyPair, String> {
    match File::open(filename) {
        Ok(mut fs) =>   { 
                            let mut byte_vec = Vec::<u8>::new();
                            fs.read_to_end(&mut byte_vec).unwrap();
                            Ok(signature::Ed25519KeyPair::from_pkcs8(&byte_vec[..]).unwrap())
                        },
        _ =>            {
                            Err("Cannot open file".to_string())
                        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ring::pkcs8::Document;
    
    #[test]
    fn correct_signing_test() {
        let tests: [&str; 3] = [
            "test",
            "hello world",
            "hashing is fun"
        ];

        for test in &tests {
            let (keys, _document): (RSAKeyPair, Document) = generate_keys().unwrap();

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
    fn incorrect_signing_test() {
        let (keys, _document): (RSAKeyPair, Document) = generate_keys().unwrap();
        let sig = sign_data(&keys, "test".as_bytes());
        let (keys, _document) = generate_keys().unwrap();

        match verify_data(keys.public_key().as_ref(), "test".as_bytes(), sig) {
            false => {},
            _ => { panic!(); }
        };
    }

    #[test]
    fn key_saving_and_loading_test() {
        let (keys, bytes) = generate_keys().unwrap();
        save_key(bytes.as_ref(), "test.bin".to_string()).unwrap();
        let newkey = load_key("test.bin".to_string()).unwrap();
        assert_eq!(format!("{:?}", keys), format!("{:?}", newkey));
    }
}