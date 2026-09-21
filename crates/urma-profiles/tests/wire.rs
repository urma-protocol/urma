use bitcoin::{Transaction, Witness, consensus::deserialize};
use urma_profiles::wire;

const COMMIT: &[u8] = include_bytes!("../../../tests/vectors/proof-post.commit");
const REVEAL: &[u8] = include_bytes!("../../../tests/vectors/proof-post.reveal");

#[test]
fn verified_record_preserves_authenticated_bytes_and_rejects_tampering() {
    let verified = wire::verify_bytes(COMMIT, REVEAL).unwrap();
    assert_eq!(verified.raw_record(), verified.record().encode().unwrap());
    let commit: Transaction = deserialize(COMMIT).unwrap();
    let mut reveal: Transaction = deserialize(REVEAL).unwrap();
    assert_eq!(
        wire::verify(&reveal, &commit).unwrap().author(),
        verified.author()
    );
    let mut witness: Vec<Vec<u8>> = reveal.input[0].witness.iter().map(Vec::from).collect();
    let record_offset = witness[1]
        .windows(verified.raw_record().len())
        .position(|bytes| bytes == verified.raw_record())
        .unwrap();
    witness[1][record_offset + verified.raw_record().len() - 1] ^= 1;
    reveal.input[0].witness = Witness::from_slice(&witness);
    assert!(wire::verify(&reveal, &commit).is_err());
    let mut commit = commit;
    commit.output[0].value = bitcoin::Amount::from_sat(1);
    assert!(wire::verify_bytes(&bitcoin::consensus::serialize(&commit), REVEAL).is_err());
    assert!(wire::verify_bytes(&COMMIT[..COMMIT.len() - 1], REVEAL).is_err());
}
