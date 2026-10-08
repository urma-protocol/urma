use crate::error::{Error, ensure};
use crate::format::Urma;

pub fn decode_pixels(bytes: &[u8; Urma::AVATAR_BYTES]) -> [u8; Urma::AVATAR_PIXELS] {
    let mut pixels = [0; Urma::AVATAR_PIXELS];
    for (at, byte) in bytes.iter().enumerate() {
        pixels[at * 2] = byte >> 4;
        pixels[at * 2 + 1] = byte & 0x0F;
    }
    pixels
}

pub fn encode_pixels(
    pixels: &[u8; Urma::AVATAR_PIXELS],
) -> Result<[u8; Urma::AVATAR_BYTES], Error> {
    let mut bytes = [0; Urma::AVATAR_BYTES];
    for (at, pair) in pixels.as_chunks::<2>().0.iter().enumerate() {
        ensure!(
            usize::from(pair[0]) < Urma::AVATAR_PALETTE.len()
                && usize::from(pair[1]) < Urma::AVATAR_PALETTE.len(),
            "avatar color indices must be in 0..=15"
        );
        bytes[at] = (pair[0] << 4) | pair[1];
    }
    Ok(bytes)
}
