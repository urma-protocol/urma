use crate::error::IdentityError;

const INPUT: &str = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";
const CHECKSUM: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATOR: [u64; 5] = [
    0xf5dee51989,
    0xa9fdca3312,
    0x1bab10e32d,
    0x3706b1677a,
    0x644d626ffd,
];

pub fn with_checksum(descriptor: &str) -> Result<String, IdentityError> {
    let mut checksum = 1;
    let mut class = 0;
    let mut count = 0;
    for symbol in descriptor.chars() {
        let position = INPUT.find(symbol).ok_or(IdentityError::Descriptor)?;
        let position = u64::try_from(position)?;
        checksum = polymod(checksum, position & 31);
        class = class * 3 + (position >> 5);
        count += 1;
        if count == 3 {
            checksum = polymod(checksum, class);
            class = 0;
            count = 0;
        }
    }
    if count > 0 {
        checksum = polymod(checksum, class);
    }
    for _ in 0..8 {
        checksum = polymod(checksum, 0);
    }
    checksum ^= 1;
    let mut text = format!("{descriptor}#");
    for group in (0..8u64).rev() {
        let symbol = usize::try_from((checksum >> (5 * group)) & 31)?;
        text.push(char::from(CHECKSUM[symbol]));
    }
    Ok(text)
}

fn polymod(checksum: u64, value: u64) -> u64 {
    let top = checksum >> 35;
    let mut next = ((checksum & 0x7_ffff_ffff) << 5) ^ value;
    for (bit, generator) in GENERATOR.iter().enumerate() {
        if (top >> bit) & 1 == 1 {
            next ^= generator;
        }
    }
    next
}
