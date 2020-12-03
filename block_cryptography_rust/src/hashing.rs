use ring::digest::{SHA256, Context, Digest};

pub fn sha256_hash(bytes: &[u8]) -> Digest {
    let mut cntxt = Context::new(&SHA256);
    cntxt.update(bytes);
    cntxt.finish()
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn hashing_test() {
        let tests = [
            "test",
            "hello world",
            "hashing is fun"
        ];
        let answers = [
            "SHA256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
            "SHA256:b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
            "SHA256:5d030b8379ed270994f48fd245537aca5ba01294048185049d6e36dfaa8ade5a"
        ];

        let mut i = 0;
        loop {
            if i == 2 {
                break;
            } else {
                let hash = sha256_hash(&tests[i].as_bytes());
                assert_eq!(format!("{:?}", hash), answers[i]);
                i += 1;
            }
        }
    }
}