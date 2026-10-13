use sha2::{Digest, Sha256};
use std::io::{self, Read};

pub fn digest(input: &mut impl Read) -> Result<[u8; 32], io::Error> {
    let mut hash = Sha256::new();
    let mut buffer = [0_u8; 65536];
    loop {
        let count = input.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hash.update(&buffer[..count]);
    }
    Ok(hash.finalize().into())
}
