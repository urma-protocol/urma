use serde_json::Value;
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};
use urma_core::{
    avatar::{decode_pixels, encode_pixels},
    format::{PublicRecord, Urma},
};

fn cli(workdir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_urma"))
        .current_dir(workdir)
        .env("URMA_OUTPUT", "json")
        .env("URMA_NETWORK", "bitcoin-regtest")
        .args(args)
        .output()
        .unwrap()
}

#[test]
fn avatar_cli_requires_raw_128_bytes_and_emits_the_136_byte_record() {
    let dir = tempfile::tempdir().unwrap();
    for size in [127, 128, 129, 136, 512, 520] {
        let input = if size == 136 {
            PublicRecord::Avatar(Box::new([0xAB; 128]))
                .encode()
                .unwrap()
        } else {
            vec![0xAB; size]
        };
        fs::write(dir.path().join("pixels.bin"), &input).unwrap();
        let output_name = format!("avatar-{size}.record");
        let output = cli(
            dir.path(),
            &[
                "wire",
                "expert",
                "encode",
                "--kind",
                "avatar",
                "--input",
                "pixels.bin",
                "--output",
                &output_name,
            ],
        );
        if size == 128 {
            assert!(
                output.status.success(),
                "{}",
                String::from_utf8_lossy(&output.stderr)
            );
            let report: Value = serde_json::from_slice(&output.stdout).unwrap();
            assert_eq!(report["status"], "encoded");
            assert_eq!(report["version"], 0);
            assert_eq!(report["kind"], 6);
            assert_eq!(report["bytes"], 136);
            let record = fs::read(dir.path().join(&output_name)).unwrap();
            assert_eq!(&record[..8], b"URMA\x00\x06\x00\x00");
            assert_eq!(&record[8..], &[0xAB; 128]);
            assert_eq!(record.len(), 136);
            assert_eq!(
                PublicRecord::decode(&record).unwrap().encode().unwrap(),
                record
            );
        } else {
            assert!(!output.status.success());
            let error = String::from_utf8(output.stderr).unwrap();
            assert!(error.contains("exactly 128 packed pixel bytes"), "{error}");
            assert!(!dir.path().join(&output_name).exists());
        }
        assert_eq!(fs::read(dir.path().join("pixels.bin")).unwrap(), input);
    }
}

#[test]
fn avatar_cli_prepare_refuses_wrong_lengths_before_opening_funding_or_credentials() {
    let dir = tempfile::tempdir().unwrap();
    for size in [127, 129, 512] {
        let record = [b"URMA\x00\x06\x00\x00".to_vec(), vec![0xAB; size]].concat();
        fs::write(dir.path().join("avatar.record"), &record).unwrap();
        let output = cli(
            dir.path(),
            &[
                "wire",
                "expert",
                "prepare",
                "--record",
                "avatar.record",
                "--funding",
                "missing-funding.json",
                "--chain",
                "bitcoin-regtest",
                "--fee-rate",
                "1",
                "--max-fee",
                "10000",
                "--output",
                "plan.json",
            ],
        );
        assert!(!output.status.success());
        let error = String::from_utf8(output.stderr).unwrap();
        assert!(
            error.contains("avatar body must contain exactly 128"),
            "{error}"
        );
        assert!(!dir.path().join("plan.json").exists());
        assert_eq!(fs::read(dir.path().join("avatar.record")).unwrap(), record);
    }
}

#[test]
fn independent_raw_input_corpus_accepts_png_and_urma_looking_128_bytes() {
    let vectors = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/vectors");
    let corpus: Value =
        serde_json::from_slice(&fs::read(vectors.join("manifest.json")).unwrap()).unwrap();
    let dir = tempfile::tempdir().unwrap();
    for case in corpus["avatar_inputs"].as_array().unwrap() {
        let name = case["name"].as_str().unwrap();
        let input = fs::read(vectors.join(case["pixels"]["file"].as_str().unwrap())).unwrap();
        fs::write(dir.path().join("pixels.bin"), &input).unwrap();
        let output_name = format!("{name}.record");
        let output = cli(
            dir.path(),
            &[
                "wire",
                "expert",
                "encode",
                "--kind",
                "avatar",
                "--input",
                "pixels.bin",
                "--output",
                &output_name,
            ],
        );
        if case["outcome"] == "valid" {
            assert!(
                output.status.success(),
                "{name}: {}",
                String::from_utf8_lossy(&output.stderr)
            );
            assert_eq!(input.len(), 128);
            let expected = [b"URMA\x00\x06\x00\x00".to_vec(), input].concat();
            assert_eq!(fs::read(dir.path().join(output_name)).unwrap(), expected);
        } else {
            assert!(!output.status.success(), "{name}");
            assert!(!dir.path().join(output_name).exists(), "{name}");
        }
    }
}

#[test]
fn independent_ega16_rows_and_palette_match_core_and_cli_bytes() {
    let vectors = Path::new(env!("CARGO_MANIFEST_DIR")).join("../tests/vectors");
    let oracle: Value =
        serde_json::from_slice(&fs::read(vectors.join("avatar-ega16-reference.json")).unwrap())
            .unwrap();
    let raw = fs::read(vectors.join(oracle["pixels"]["file"].as_str().unwrap())).unwrap();
    let packed: [u8; 128] = raw.as_slice().try_into().unwrap();
    let decoded = decode_pixels(&packed);
    let mut expected = [0; 256];
    for (y, row) in oracle["indices_by_row"]
        .as_array()
        .unwrap()
        .iter()
        .enumerate()
    {
        let row = row.as_str().unwrap();
        for x in 0..16 {
            expected[y * 16 + x] = u8::from_str_radix(&row[x..x + 1], 16).unwrap();
        }
    }
    assert_eq!(decoded, expected);
    assert_eq!(encode_pixels(&expected).unwrap(), packed);
    for (at, rgb) in oracle["palette_rgb"].as_array().unwrap().iter().enumerate() {
        let rgb: Vec<u8> = rgb
            .as_array()
            .unwrap()
            .iter()
            .map(|v| u8::try_from(v.as_u64().unwrap()).unwrap())
            .collect();
        assert_eq!(
            Urma::AVATAR_PALETTE[at],
            format!("#{}", hex::encode(rgb).to_uppercase())
        );
    }
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("pixels.bin"), raw).unwrap();
    let output = cli(
        dir.path(),
        &[
            "wire",
            "expert",
            "encode",
            "--kind",
            "avatar",
            "--input",
            "pixels.bin",
            "--output",
            "avatar.record",
        ],
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let record = fs::read(dir.path().join("avatar.record")).unwrap();
    assert_eq!(
        record,
        fs::read(vectors.join(oracle["record"].as_str().unwrap())).unwrap()
    );
    assert_eq!(record.len(), 136);
}
