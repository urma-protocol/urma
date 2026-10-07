use bitcoin::{
    Amount, Block, Network, OutPoint, ScriptBuf, Transaction, TxIn, TxOut, WPubkeyHash, Witness,
    absolute,
    hashes::Hash,
    secp256k1::{Keypair, Message, Secp256k1, SecretKey},
    sighash::{Prevouts, SighashCache, TapSighashType},
    taproot::{LeafVersion, TapLeafHash},
    transaction::Version,
};
use rand::{SeedableRng, rngs::StdRng};
use std::collections::BTreeMap;
use urma_core::{
    container, envelope,
    format::{ContentType, Urma},
};
use urma_runtime::{
    backend,
    bitcoin_rpc::{Prevout, emit_core_validated_records},
    error::Error,
};

const KEY: [u8; 32] = [4; 32];

fn signer(byte: u8) -> Keypair {
    Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[byte; 32]).unwrap(),
    )
}

fn records(bytes: &[u8]) -> Vec<Vec<u8>> {
    container::seal(
        &KEY,
        bytes,
        ContentType::Opaque,
        &mut StdRng::seed_from_u64(41),
    )
    .unwrap()
}

fn payout() -> ScriptBuf {
    ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([9; 20]))
}

fn pair(record: &[u8], signer: &Keypair) -> (Transaction, Transaction) {
    let (script, info) = envelope::build(record, signer).unwrap();
    let commit = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(info.output_key()),
        }],
    };
    let mut reveal = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: commit.compute_txid(),
                vout: 0,
            },
            ..TxIn::default()
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000),
            script_pubkey: payout(),
        }],
    };
    let hash = SighashCache::new(&reveal)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&commit.output),
            TapLeafHash::from_script(&script, LeafVersion::TapScript),
            TapSighashType::Default,
        )
        .unwrap();
    let signature = Secp256k1::new()
        .sign_schnorr_no_aux_rand(&Message::from_digest(hash.to_byte_array()), signer);
    reveal.input[0].witness = envelope::witness(signature.as_ref(), &script, &info).unwrap();
    (commit, reveal)
}

fn block(txdata: Vec<Transaction>) -> Block {
    let mut block = bitcoin::blockdata::constants::genesis_block(Network::Regtest);
    block.txdata = txdata;
    block
}

fn scan(
    block: &Block,
    resolve: &mut dyn FnMut(OutPoint) -> Result<Prevout, Error>,
) -> Vec<Vec<u8>> {
    let mut emitted = Vec::new();
    emit_core_validated_records(block, resolve, &mut |record| {
        emitted.push(record.to_vec());
        Ok(())
    })
    .unwrap();
    emitted
}

fn unreachable_resolver(outpoint: OutPoint) -> Result<Prevout, Error> {
    panic!("resolver consulted for in-block parent {outpoint}")
}

fn tamper(reveal: &Transaction, item: usize, index: usize) -> Transaction {
    let mut items = reveal.input[0].witness.to_vec();
    items[item][index] ^= 1;
    let mut tampered = reveal.clone();
    tampered.input[0].witness = Witness::from_slice(&items);
    tampered
}

#[test]
fn same_block_commit_proves_private_reveal_and_record_authenticates() {
    let bytes = vec![42; Urma::CHUNK_BYTES + 1];
    let records = records(&bytes);
    let (commit0, reveal0) = pair(&records[0], &signer(1));
    let (commit1, reveal1) = pair(&records[1], &signer(2));
    let mut objects = BTreeMap::new();
    let first = scan(&block(vec![commit0, reveal0]), &mut unreachable_resolver);
    assert_eq!(first, vec![records[0].clone()]);
    assert_eq!(
        backend::accept_record(&KEY, &first[0], &mut objects).unwrap(),
        0
    );
    assert!(objects.values().next().unwrap().finish().is_err());
    let second = scan(&block(vec![commit1, reveal1]), &mut unreachable_resolver);
    assert_eq!(second, vec![records[1].clone()]);
    assert_eq!(
        backend::accept_record(&KEY, &second[0], &mut objects).unwrap(),
        0
    );
    assert_eq!(objects.len(), 1);
    assert_eq!(
        objects
            .values()
            .next()
            .unwrap()
            .finish()
            .unwrap()
            .as_slice(),
        bytes
    );
}

#[test]
fn resolved_prevout_must_be_p2tr() {
    let records = records(b"private");
    let (commit, reveal) = pair(&records[0], &signer(1));
    let outpoint = reveal.input[0].previous_output;
    let value = commit.output[0].value;
    let mut asked = Vec::new();
    let rejected = scan(&block(vec![reveal.clone()]), &mut |outpoint| {
        asked.push(outpoint);
        Ok(Prevout::Found(TxOut {
            value,
            script_pubkey: payout(),
        }))
    });
    assert!(rejected.is_empty());
    assert_eq!(asked, vec![outpoint]);
    let accepted = scan(&block(vec![reveal]), &mut |_| {
        Ok(Prevout::Found(commit.output[0].clone()))
    });
    assert_eq!(accepted, vec![records[0].clone()]);
}

#[test]
fn foreign_output_key_fails_taproot_commitment() {
    let records = records(b"private");
    let (commit, reveal) = pair(&records[0], &signer(1));
    let foreign = TxOut {
        value: commit.output[0].value,
        script_pubkey: ScriptBuf::new_p2tr(
            &Secp256k1::new(),
            signer(3).x_only_public_key().0,
            None,
        ),
    };
    assert!(
        scan(&block(vec![reveal.clone()]), &mut |_| Ok(Prevout::Found(
            foreign.clone()
        )))
        .is_empty()
    );
    let (other_commit, _) = pair(&records[0], &signer(3));
    let mut swapped = reveal;
    swapped.input[0].previous_output.txid = other_commit.compute_txid();
    assert!(
        scan(
            &block(vec![other_commit, swapped]),
            &mut unreachable_resolver
        )
        .is_empty()
    );
}

#[test]
fn tampered_signature_witness_or_overspend_is_rejected() {
    let records = records(b"private");
    let (commit, reveal) = pair(&records[0], &signer(1));
    for tampered in [
        tamper(&reveal, 0, 10),
        tamper(&reveal, 1, 100),
        tamper(&reveal, 2, 5),
    ] {
        assert!(
            scan(
                &block(vec![commit.clone(), tampered]),
                &mut unreachable_resolver
            )
            .is_empty()
        );
    }
    let short = TxOut {
        value: reveal.output[0].value - Amount::ONE_SAT,
        script_pubkey: commit.output[0].script_pubkey.clone(),
    };
    assert!(
        scan(&block(vec![reveal]), &mut |_| Ok(Prevout::Found(
            short.clone()
        )))
        .is_empty()
    );
}

#[test]
fn unresolvable_parent_is_skipped_and_scan_continues() {
    let records = records(&vec![7; Urma::CHUNK_BYTES + 1]);
    let (_, orphan) = pair(&records[0], &signer(1));
    let (commit, reveal) = pair(&records[1], &signer(2));
    let emitted = scan(&block(vec![orphan.clone(), commit, reveal]), &mut |_| {
        Ok(Prevout::Missing)
    });
    assert_eq!(emitted, vec![records[1].clone()]);
    assert!(
        emit_core_validated_records(
            &block(vec![orphan]),
            &mut |_| Err(Error::Missing("node unreachable".into())),
            &mut |_| Ok(()),
        )
        .is_err()
    );
}

#[test]
fn proof_valid_reveal_with_wrong_content_mac_is_rejected_by_accept_record() {
    let records = records(b"private");
    let mut forged = records[0].clone();
    *forged.last_mut().unwrap() ^= 1;
    let (commit, reveal) = pair(&forged, &signer(1));
    let emitted = scan(&block(vec![commit, reveal]), &mut unreachable_resolver);
    assert_eq!(emitted, vec![forged.clone()]);
    let mut objects = BTreeMap::new();
    assert_eq!(
        backend::accept_record(&KEY, &forged, &mut objects).unwrap(),
        1
    );
    assert!(objects.is_empty());
}
