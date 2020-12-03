use ring::digest::{SHA256, Context, Digest};

pub fn sha256_hash(bytes: &[u8]) -> Digest {
    let mut cntxt = Context::new(&SHA256);
    cntxt.update(bytes);
    cntxt.finish()
}