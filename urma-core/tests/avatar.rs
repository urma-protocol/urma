use urma_core::{
    avatar::{decode_pixels, encode_pixels},
    format::{PublicRecord, RecordKind, Urma},
};

#[test]
fn avatar_uses_the_fixed_ega16_palette_and_136_byte_v0_record() {
    assert_eq!(Urma::AVATAR_SIDE, 16);
    assert_eq!(Urma::AVATAR_PIXELS, 256);
    assert_eq!(Urma::AVATAR_BYTES, 128);
    assert_eq!(
        Urma::AVATAR_PALETTE,
        [
            "#000000", "#0000AA", "#00AA00", "#00AAAA", "#AA0000", "#AA00AA", "#AA5500", "#AAAAAA",
            "#555555", "#5555FF", "#55FF55", "#55FFFF", "#FF5555", "#FF55FF", "#FFFF55", "#FFFFFF",
        ]
    );
    let record = PublicRecord::Avatar(Box::new([0xAB; 128]));
    let encoded = record.encode().unwrap();
    assert_eq!(encoded.len(), 136);
    assert_eq!(&encoded[..8], b"URMA\x00\x06\x00\x00");
    assert_eq!(&encoded[8..], &[0xAB; 128]);
    assert_eq!(RecordKind::parse(&encoded).unwrap(), RecordKind::Avatar);
    assert_eq!(PublicRecord::decode(&encoded).unwrap(), record);
}

#[test]
fn avatar_decoder_rejects_truncated_appended_and_legacy_payloads() {
    for size in [0, 127, 128, 129, 512] {
        let mut bytes = b"URMA\x00\x06\x00\x00".to_vec();
        bytes.extend(vec![0x12; size]);
        if size == 128 {
            assert_eq!(
                PublicRecord::decode(&bytes).unwrap().encode().unwrap(),
                bytes
            );
        } else {
            let error = PublicRecord::decode(&bytes).unwrap_err();
            assert!(error.to_string().contains("exactly 128"), "{error}");
        }
    }
    assert!(PublicRecord::decode(&[0x12; 128]).is_err());
    let encoded = PublicRecord::Avatar(Box::new([0; 128])).encode().unwrap();
    for offset in [0, 4, 5, 6, 7] {
        let mut bytes = encoded.clone();
        bytes[offset] = 0xFF;
        assert!(PublicRecord::decode(&bytes).is_err());
    }
}

#[test]
fn avatar_nibbles_and_row_boundaries_have_literal_known_answers() {
    let mut packed = [0; 128];
    packed[..16].copy_from_slice(&[
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32,
        0x10,
    ]);
    packed[127] = 0xA5;
    let pixels = decode_pixels(&packed);
    assert_eq!(
        &pixels[..16],
        &[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
    );
    assert_eq!(
        &pixels[16..32],
        &[15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
    );
    assert_eq!(&pixels[32..254], &[0; 222]);
    assert_eq!(&pixels[254..], &[10, 5]);
    assert_eq!(pixels[15], 15);
    assert_eq!(pixels[16], 15);
    assert_eq!(encode_pixels(&pixels).unwrap(), packed);
    for value in 0..=u8::MAX {
        packed[0] = value;
        let pixels = decode_pixels(&packed);
        assert_eq!(pixels[0], value / 16);
        assert_eq!(pixels[1], value % 16);
        assert_eq!(encode_pixels(&pixels).unwrap(), packed);
    }
}

#[test]
fn avatar_encoder_refuses_out_of_palette_indices_without_masking() {
    for at in [0, 1, 15, 16, 254, 255] {
        for value in [16, 31, u8::MAX] {
            let mut pixels = [0; 256];
            pixels[at] = value;
            assert!(encode_pixels(&pixels).is_err());
        }
    }
}
