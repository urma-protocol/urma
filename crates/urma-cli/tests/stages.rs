pub use urma::{config, container, envelope, error, format, storage};
pub mod journal {
    include!("../../urma/src/journal.rs");
}
pub mod commitment {
    include!("../../urma/src/commitment.rs");
}
pub mod source {
    include!("../../urma/src/source.rs");
    #[cfg(test)]
    mod checks {

        use super::*;
        use bitcoin::consensus::serialize;
        use std::{
            io::{Read, Write},
            net::TcpListener,
            thread,
        };
        use urma::{container, envelope};

        fn mock(responses: Vec<(String, Vec<u8>)>) -> (String, thread::JoinHandle<()>) {
            mock_http(
                responses
                    .into_iter()
                    .map(|(path, body)| (path, 200, body))
                    .collect(),
            )
        }

        fn mock_http(responses: Vec<(String, u16, Vec<u8>)>) -> (String, thread::JoinHandle<()>) {
            let listener = TcpListener::bind("127.0.0.1:0").unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let task = thread::spawn(move || {
                for (path, status, body) in responses {
                    let (mut stream, _) = listener.accept().unwrap();
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                        .unwrap();
                    let mut request = Vec::new();
                    while !request.ends_with(b"\r\n\r\n") {
                        let mut byte = [0];
                        stream.read_exact(&mut byte).unwrap();
                        request.push(byte[0]);
                        assert!(request.len() < 16384);
                    }
                    assert!(
                        String::from_utf8(request)
                            .unwrap()
                            .starts_with(&format!("GET {path} HTTP/"))
                    );
                    write!(
                stream,
                "HTTP/1.1 {status} Response\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
                    let _ = stream.write_all(&body);
                }
            });
            (url, task)
        }

        #[test]
        fn wrong_network_is_rejected_before_other_requests() {
            let genesis =
                bitcoin::blockdata::constants::genesis_block(Network::Bitcoin).block_hash();
            let (url, task) = mock(vec![(
                "/block-height/0".into(),
                genesis.to_string().into_bytes(),
            )]);
            assert!(
                Source::connect(&url, &Network::Testnet4)
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("genesis")
            );
            task.join().unwrap();
            assert!(checked_url("http://example.com/api").is_err());
            assert!(checked_url("https://name:password@example.com/api").is_err());
            assert!(checked_url("https://example.com/api?query=1").is_err());
        }

        #[test]
        fn responses_are_bounded_before_body_allocation() {
            let (url, task) = mock(vec![("/block-height/0".into(), vec![b'0'; 129])]);
            assert!(
                Source::connect(&url, &Network::Regtest)
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("byte limit")
            );
            task.join().unwrap();
        }

        #[test]
        fn missing_raw_is_unknown_even_when_status_returns_unconfirmed() {
            let block = bitcoin::blockdata::constants::genesis_block(Network::Regtest);
            let tx = &block.txdata[0];
            let txid = tx.compute_txid();
            let status_path = format!("/tx/{txid}/status");
            let (url, task) = mock_http(vec![
                (status_path.clone(), 200, br#"{"confirmed":false}"#.to_vec()),
                (
                    format!("/tx/{txid}/raw"),
                    404,
                    b"Transaction not found".to_vec(),
                ),
            ]);
            let source = Source {
                url,
                network: Network::Regtest,
                genesis: block.block_hash(),
            };
            // Establish the real-world misleading endpoint behavior before checking
            // that observation consults /raw and does not infer pending from it.
            let misleading: TxStatus = source.json(&status_path).unwrap();
            assert!(!misleading.confirmed);
            let observation = source.observe_transaction(tx, &serialize(tx), 0).unwrap();
            assert_eq!(observation["state"], "unknown");
            assert_eq!(observation["confirmations"], 0);
            task.join().unwrap();
        }

        #[test]
        fn known_raw_with_changed_witness_is_an_error() {
            let block = bitcoin::blockdata::constants::genesis_block(Network::Regtest);
            let tx = &block.txdata[0];
            let mut changed = tx.clone();
            changed.input[0].witness = bitcoin::Witness::from_slice(&[[1; 32]]);
            assert_eq!(changed.compute_txid(), tx.compute_txid());
            let (url, task) = mock(vec![(
                format!("/tx/{}/raw", tx.compute_txid()),
                serialize(&changed),
            )]);
            let source = Source {
                url,
                network: Network::Regtest,
                genesis: block.block_hash(),
            };
            assert!(
                source
                    .observe_transaction(tx, &serialize(tx), 0)
                    .unwrap_err()
                    .to_string()
                    .contains("witness differs")
            );
            task.join().unwrap();
        }

        #[test]
        fn relay_preflight_requires_explicit_unspent_response() {
            let block = bitcoin::blockdata::constants::genesis_block(Network::Regtest);
            let txid = block.txdata[0].compute_txid();
            for (http, body, accepted) in [
                (200, r#"{"spent":false}"#, true),
                (200, r#"{"spent":true}"#, false),
                (200, r#"{"spent":"false"}"#, false),
                (200, r#"{"spent":null}"#, false),
                (200, "{}", false),
                (404, r#"{"spent":false}"#, false),
            ] {
                let (url, task) = mock_http(vec![(
                    format!("/tx/{txid}/outspend/0"),
                    http,
                    body.as_bytes().to_vec(),
                )]);
                let source = Source {
                    url,
                    network: Network::Regtest,
                    genesis: block.block_hash(),
                };
                assert_eq!(source.require_unspent(txid, 0).is_ok(), accepted);
                task.join().unwrap();
            }
        }

        #[test]
        fn funding_rejects_provider_amount_metadata() {
            let network = Network::Testnet4;
            let genesis = bitcoin::blockdata::constants::genesis_block(network).block_hash();
            let address = "tb1qs90w8ut9mruj4928uqsjvl5r8tmchprdyeyzln";
            let script = Address::from_str(address)
                .unwrap()
                .require_network(network)
                .unwrap()
                .script_pubkey();
            let tx = Transaction {
                version: bitcoin::transaction::Version::TWO,
                lock_time: bitcoin::absolute::LockTime::ZERO,
                input: vec![bitcoin::TxIn {
                    previous_output: bitcoin::OutPoint {
                        txid: Txid::all_zeros(),
                        vout: 0,
                    },
                    script_sig: bitcoin::ScriptBuf::new(),
                    sequence: bitcoin::Sequence::MAX,
                    witness: bitcoin::Witness::new(),
                }],
                output: vec![bitcoin::TxOut {
                    value: bitcoin::Amount::from_sat(1000),
                    script_pubkey: script,
                }],
            };
            let txid = tx.compute_txid();
            let utxos = json!([{"txid": txid.to_string(), "vout": 0, "value": 9000, "status": {"confirmed": false}}]);
            let (url, task) = mock(vec![
                ("/block-height/0".into(), genesis.to_string().into_bytes()),
                ("/blocks/tip/height".into(), b"0".to_vec()),
                ("/block-height/0".into(), genesis.to_string().into_bytes()),
                (
                    format!("/address/{address}/utxo"),
                    serde_json::to_vec(&utxos).unwrap(),
                ),
                (format!("/tx/{txid}/raw"), serialize(&tx)),
            ]);
            let source = Source::connect(&url, &network).unwrap();
            assert!(
                source
                    .funding(address, true)
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("amount mismatch")
            );
            task.join().unwrap();
        }

        #[test]
        fn scan_checks_raw_block_merkle_commitment() {
            let mut block = bitcoin::blockdata::constants::genesis_block(Network::Regtest);
            let hash = block.block_hash();
            block.txdata[0].output[0].value = bitcoin::Amount::ZERO;
            let (url, task) = mock(vec![
                ("/block-height/0".into(), hash.to_string().into_bytes()),
                (format!("/block/{hash}/raw"), serialize(&block)),
            ]);
            let source = Source::connect(&url, &Network::Regtest).unwrap();
            assert!(
                source
                    .block(hash)
                    .err()
                    .unwrap()
                    .to_string()
                    .contains("Merkle")
            );
            task.join().unwrap();
        }

        fn commit_for_record(record: &[u8]) -> Transaction {
            let secp = bitcoin::secp256k1::Secp256k1::new();
            let signer = bitcoin::secp256k1::Keypair::from_seckey_slice(&secp, &[3; 32]).unwrap();
            let (script, info) = envelope::build(record, &signer).unwrap();
            assert!(!script.is_empty());
            let mut tx =
                bitcoin::blockdata::constants::genesis_block(Network::Regtest).txdata[0].clone();
            tx.output = vec![bitcoin::TxOut {
                value: bitcoin::Amount::from_sat(50000),
                script_pubkey: bitcoin::ScriptBuf::new_p2tr_tweaked(info.output_key()),
            }];
            tx
        }
        fn commit_response(tx: &Transaction) -> (String, Vec<u8>) {
            let record = envelope::extract_reveal(tx).unwrap().record;
            let commit = commit_for_record(&record);
            (
                format!("/tx/{}/raw", commit.compute_txid()),
                serialize(&commit),
            )
        }
        fn signed_reveal(record: &[u8]) -> Transaction {
            let commit = commit_for_record(record);
            let secp = bitcoin::secp256k1::Secp256k1::new();
            let signer = bitcoin::secp256k1::Keypair::from_seckey_slice(&secp, &[3; 32]).unwrap();
            let (script, info) = envelope::build(record, &signer).unwrap();
            let mut tx = crate::commitment::transaction(
                bitcoin::OutPoint {
                    txid: commit.compute_txid(),
                    vout: 0,
                },
                &bitcoin::ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([9; 20])),
            );
            let hash = bitcoin::sighash::SighashCache::new(&tx)
                .taproot_script_spend_signature_hash(
                    0,
                    &bitcoin::sighash::Prevouts::All(&commit.output),
                    bitcoin::taproot::TapLeafHash::from_script(
                        &script,
                        bitcoin::taproot::LeafVersion::TapScript,
                    ),
                    bitcoin::sighash::TapSighashType::Default,
                )
                .unwrap();
            let signature = secp.sign_schnorr_no_aux_rand(
                &bitcoin::secp256k1::Message::from_digest(hash.to_byte_array()),
                &signer,
            );
            tx.input[0].witness = envelope::witness(signature.as_ref(), &script, &info).unwrap();
            tx
        }

        fn block_with_records(records: &[Vec<u8>]) -> Block {
            let mut block = bitcoin::blockdata::constants::genesis_block(Network::Regtest);
            block.header.prev_blockhash = block.block_hash();
            block.header.time += 1;
            block.txdata[0].input[0].witness = bitcoin::Witness::from_slice(&[[0u8; 32]]);
            for record in records {
                block.txdata.push(signed_reveal(record));
            }
            let commitment =
                Block::compute_witness_commitment(&block.witness_root().unwrap(), &[0; 32]);
            let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
            script.extend_from_slice(commitment.as_byte_array());
            block.txdata[0].output.push(bitcoin::TxOut {
                value: bitcoin::Amount::ZERO,
                script_pubkey: bitcoin::ScriptBuf::from_bytes(script),
            });
            block.header.merkle_root = block.compute_merkle_root().unwrap();
            block.header.nonce = 0;
            while block.header.validate_pow(block.header.target()).is_err() {
                block.header.nonce += 1;
            }
            block
        }

        #[test]
        fn source_scan_recovers_authentic_object_despite_forged_candidate() {
            let key = [8; 32];
            let original = vec![42; urma::format::Urma::CHUNK_BYTES + 19];
            let mut records =
                container::seal(&key, &original, urma::format::ContentType::Opaque).unwrap();
            let mut forged = records[0].clone();
            forged[urma::format::Urma::PRIVATE_HEADER_BYTES + 23] ^= 1;
            records.insert(0, forged);
            let block = block_with_records(&records);
            let hash = block.block_hash();
            transport::validate_block_for_network(&block, hash, Network::Regtest).unwrap();
            let genesis =
                bitcoin::blockdata::constants::genesis_block(Network::Regtest).block_hash();
            let (url, task) = mock(vec![
                ("/block-height/0".into(), genesis.to_string().into_bytes()),
                ("/blocks/tip/height".into(), b"1".to_vec()),
                ("/block-height/1".into(), hash.to_string().into_bytes()),
                ("/block-height/0".into(), genesis.to_string().into_bytes()),
                ("/block-height/1".into(), hash.to_string().into_bytes()),
                (format!("/block/{hash}/raw"), serialize(&block)),
                commit_response(&block.txdata[1]),
                commit_response(&block.txdata[2]),
                commit_response(&block.txdata[3]),
                ("/block-height/1".into(), hash.to_string().into_bytes()),
            ]);
            let source = Source::connect(&url, &Network::Regtest).unwrap();
            let scan = source.scan(&key, 1).unwrap();
            assert_eq!(scan.rejected_records, 1);
            assert_eq!(scan.objects.len(), 1);
            assert_eq!(
                scan.objects
                    .values()
                    .next()
                    .unwrap()
                    .finish()
                    .unwrap()
                    .as_slice(),
                original
            );
            task.join().unwrap();
        }

        #[test]
        fn transaction_bundle_preserves_shuffled_ciphertext_without_a_key_or_journal() {
            let key = [29; 32];
            let original = include_bytes!("../../../tests/fixtures/sample.jpg");
            let mut records =
                container::seal(&key, original, urma::format::ContentType::Opaque).unwrap();
            records.reverse();
            let block = block_with_records(&records);
            let genesis =
                bitcoin::blockdata::constants::genesis_block(Network::Regtest).block_hash();
            let mut responses = vec![("/block-height/0".into(), genesis.to_string().into_bytes())];
            let mut ids = Vec::new();
            for tx in &block.txdata[1..] {
                let id = tx.compute_txid();
                ids.push(id);
                responses.push((format!("/tx/{id}/raw"), serialize(tx)));
                responses.push((
                    format!("/tx/{id}/status"),
                    br#"{"confirmed":false}"#.to_vec(),
                ));
                responses.push(commit_response(tx));
            }
            let (url, task) = mock(responses);
            let source = Source::connect(&url, &Network::Regtest).unwrap();
            let (bundle, report) = source.transaction_bundle(&ids).unwrap();
            let fetched = container::unpack(&bundle).unwrap();
            assert_eq!(fetched, records);
            assert_eq!(
                container::open(&key, &fetched).unwrap().as_slice(),
                original
            );
            assert_eq!(report["chain_inclusion_verified"], false);
            assert_eq!(report["content_authenticated"], false);
            assert_eq!(report["evidence"], "provider_transaction_bytes");
            assert_eq!(
                report["transactions"][0]["state"],
                "provider_reported_pending"
            );
            assert_eq!(
                report["transactions"][0]["wtxid"],
                block.txdata[1].compute_wtxid().to_string()
            );
            task.join().unwrap();
        }

        #[test]
        fn transaction_bundle_does_not_confuse_fetched_ciphertext_with_authentication() {
            let key = [30; 32];
            let mut records = container::seal(
                &key,
                b"authentication is required",
                urma::format::ContentType::Opaque,
            )
            .unwrap();
            records[0][urma::format::Urma::BODY_OFFSET] ^= 1;
            let block = block_with_records(&records);
            let tx = &block.txdata[1];
            let id = tx.compute_txid();
            let (url, task) = mock(vec![
                (format!("/tx/{id}/raw"), serialize(tx)),
                (
                    format!("/tx/{id}/status"),
                    br#"{"confirmed":false}"#.to_vec(),
                ),
                commit_response(tx),
            ]);
            let source = Source {
                url,
                network: Network::Regtest,
                genesis: block.header.prev_blockhash,
            };
            let (bundle, report) = source.transaction_bundle(&[id]).unwrap();
            assert_eq!(report["content_authenticated"], false);
            assert!(container::open(&key, &container::unpack(&bundle).unwrap()).is_err());
            task.join().unwrap();
        }

        #[test]
        fn transaction_bundle_fails_on_unknown_raw_or_wrong_txid_and_bounds_requests() {
            let block = bitcoin::blockdata::constants::genesis_block(Network::Regtest);
            let tx = &block.txdata[0];
            let id = Txid::all_zeros();
            for (http, body) in [(404, b"not found".to_vec()), (200, serialize(tx))] {
                let (url, task) = mock_http(vec![(format!("/tx/{id}/raw"), http, body)]);
                let source = Source {
                    url,
                    network: Network::Regtest,
                    genesis: block.block_hash(),
                };
                assert!(source.transaction_bundle(&[id]).is_err());
                task.join().unwrap();
            }
            let source = Source {
                url: "http://127.0.0.1:1".into(),
                network: Network::Regtest,
                genesis: block.block_hash(),
            };
            assert!(
                source
                    .transaction_bundle(&[])
                    .unwrap_err()
                    .to_string()
                    .contains("1..=512")
            );
            assert!(
                source
                    .transaction_bundle(&[id; urma::config::Limits::RECORDS + 1])
                    .unwrap_err()
                    .to_string()
                    .contains("1..=512")
            );
        }

        #[test]
        fn testnet_source_rejects_regtest_difficulty_target() {
            let testnet_genesis =
                bitcoin::blockdata::constants::genesis_block(Network::Testnet4).block_hash();
            let block = bitcoin::blockdata::constants::genesis_block(Network::Regtest);
            let hash = block.block_hash();
            transport::validate_block(&block, hash).unwrap();
            let (url, task) = mock(vec![
                (
                    "/block-height/0".into(),
                    testnet_genesis.to_string().into_bytes(),
                ),
                (format!("/block/{hash}/raw"), serialize(&block)),
            ]);
            let source = Source::connect(&url, &Network::Testnet4).unwrap();
            assert!(source.block(hash).is_err());
            task.join().unwrap();
        }

        #[test]
        fn provider_transaction_bytes_need_valid_author_proof() {
            let record = container::seal(
                &[9; 32],
                b"private authentic bytes",
                urma::format::ContentType::Text,
            )
            .unwrap()
            .remove(0);
            let mut tx = signed_reveal(&record);
            let mut witness: Vec<Vec<u8>> =
                tx.input[0].witness.iter().map(<[u8]>::to_vec).collect();
            witness[0][0] ^= 1;
            tx.input[0].witness = bitcoin::Witness::from_slice(&witness);
            let id = tx.compute_txid();
            let (url, task) = mock(vec![
                (format!("/tx/{id}/raw"), serialize(&tx)),
                (
                    format!("/tx/{id}/status"),
                    br#"{"confirmed":false}"#.to_vec(),
                ),
                commit_response(&tx),
            ]);
            let source = Source {
                url,
                network: Network::Regtest,
                genesis: bitcoin::blockdata::constants::genesis_block(Network::Regtest)
                    .block_hash(),
            };
            assert!(
                source
                    .transaction_bundle(&[id])
                    .unwrap_err()
                    .to_string()
                    .contains("signature")
            );
            task.join().unwrap();
        }
    }
}

pub mod relay {
    include!("../../urma/src/relay.rs");
    #[cfg(test)]
    mod checks {

        use super::*;
        use bitcoin::{blockdata::constants::genesis_block, consensus::serialize};
        use std::{
            io::{Read, Write},
            net::TcpListener,
            thread,
        };

        #[test]
        fn explicit_network_trust_and_budget_are_required() {
            assert!(authorize(Network::Bitcoin, 100, 1000, true).is_err());
            assert!(authorize(Network::Testnet4, 100, 1000, false).is_err());
            assert!(authorize(Network::Testnet4, 1001, 1000, true).is_err());
            assert!(authorize(Network::Testnet4, 100, 500001, true).is_err());
            assert!(authorize(Network::Testnet4, 100, 0, true).is_err());
            assert!(authorize(Network::Testnet4, 100, 1000, true).is_ok());
        }

        #[test]
        fn stage_selection_never_reveals_an_unconfirmed_commit() {
            assert_eq!(
                next_step(&json!({"status":"prepared"}), false).unwrap(),
                Step::Commit
            );
            assert_eq!(
                next_step(&json!({"status":"commit_pending"}), false).unwrap(),
                Step::Wait
            );
            assert_eq!(
                next_step(&json!({"status":"confirmed"}), false).unwrap(),
                Step::Complete
            );
            let mut s = json!({"status":"awaiting_reveals", "commit_status":{"state":"pending"},
        "reveal_statuses":[{"state":"unknown"},{"state":"pending"},{"state":"confirmed"}]});
            assert!(next_step(&s, false).is_err());
            s["commit_status"]["state"] = json!("confirmed");
            assert_eq!(next_step(&s, false).unwrap(), Step::Reveals(vec![0]));
            assert!(next_step(&json!({"status":"invented"}), false).is_err());
        }

        #[test]
        fn unconfirmed_reveal_is_explicit_and_never_reposts_known_reveals() {
            let mut s = json!({"status":"commit_pending", "commit_status":{"state":"pending"},
        "reveal_statuses":[{"state":"unknown"},{"state":"pending"}]});
            assert_eq!(next_step(&s, false).unwrap(), Step::Wait);
            assert_eq!(next_step(&s, true).unwrap(), Step::Reveals(vec![0]));
            s["reveal_statuses"][0]["state"] = json!("pending");
            assert_eq!(next_step(&s, true).unwrap(), Step::Wait);
            s["commit_status"]["state"] = json!("unknown");
            assert!(next_step(&s, true).is_err());
            s["commit_status"]["state"] = json!("pending");
            s["reveal_statuses"][0]["state"] = json!("invented");
            assert!(next_step(&s, true).is_err());
            assert_eq!(
                next_step(&json!({"status":"prepared"}), true).unwrap(),
                Step::Commit
            );
        }

        #[test]
        fn post_sends_exact_hex_checks_txid_and_does_not_follow_redirects() {
            let tx = genesis_block(Network::Regtest).txdata.remove(0);
            let raw = hex::encode(serialize(&tx));
            for (code, body, valid) in [
                (200, tx.compute_txid().to_string(), true),
                (200, "0".repeat(64), false),
                (302, String::new(), false),
                (500, "relay unavailable".into(), false),
                (200, "x".repeat(1025), false),
            ] {
                let listener = TcpListener::bind("127.0.0.1:0").unwrap();
                let url = format!("http://{}", listener.local_addr().unwrap());
                let expected_body = raw.clone();
                let task = thread::spawn(move || {
                    let (mut stream, _) = listener.accept().unwrap();
                    stream
                        .set_read_timeout(Some(std::time::Duration::from_secs(5)))
                        .unwrap();
                    let mut header = Vec::new();
                    while !header.ends_with(b"\r\n\r\n") {
                        let mut b = [0];
                        stream.read_exact(&mut b).unwrap();
                        header.push(b[0]);
                    }
                    let header = String::from_utf8(header).unwrap();
                    assert!(header.starts_with("POST /tx HTTP/"));
                    let mut received = vec![0; expected_body.len()];
                    stream.read_exact(&mut received).unwrap();
                    assert_eq!(received, expected_body.as_bytes());
                    write!(stream, "HTTP/1.1 {code} Response\r\nContent-Length: {}\r\nLocation: http://127.0.0.1:1/must-not-follow\r\nConnection: close\r\n\r\n{body}", body.len()).unwrap();
                });
                assert_eq!(post_transaction(&url, &raw).is_ok(), valid);
                task.join().unwrap();
            }
        }
    }
}

pub mod transport {
    include!("../../urma/src/transport.rs");
    #[cfg(test)]
    mod checks {

        use super::*;
        use bitcoin::{
            ScriptBuf,
            secp256k1::{Keypair, Secp256k1},
        };

        #[test]
        fn easier_regtest_proof_of_work_is_rejected_for_testnet4() {
            let regtest = bitcoin::blockdata::constants::genesis_block(Network::Regtest);
            validate_block(&regtest, regtest.block_hash()).unwrap();
            validate_block_for_network(&regtest, regtest.block_hash(), Network::Regtest).unwrap();
            assert!(
                validate_block_for_network(&regtest, regtest.block_hash(), Network::Testnet4)
                    .unwrap_err()
                    .to_string()
                    .contains("network proof-of-work limit")
            );
            let testnet = bitcoin::blockdata::constants::genesis_block(Network::Testnet4);
            validate_block_for_network(&testnet, testnet.block_hash(), Network::Testnet4).unwrap();
            assert!(
                validate_block_for_network(&testnet, testnet.block_hash(), Network::Bitcoin)
                    .is_err()
            );
        }

        #[test]
        fn copied_public_header_cannot_poison_authenticated_recovery() {
            let key = [7; 32];
            let bytes = vec![42; urma::format::Urma::CHUNK_BYTES + 1];
            let records = container::seal(&key, &bytes, urma::format::ContentType::Opaque).unwrap();
            let mut forged = records[0].clone();
            forged[urma::format::Urma::PRIVATE_HEADER_BYTES] ^= 1;
            assert!(container::open(&key, &[forged.clone()]).is_err());

            // Ingestion happens after block validation; construct just its relevant witness data.
            let secp = Secp256k1::new();
            let envelope_transaction = |record: &[u8]| {
                let attacker_or_sender = Keypair::new(&secp, &mut OsRng);
                let (script, info) = envelope::build(record, &attacker_or_sender).unwrap();
                let mut transaction = transaction(
                    OutPoint::null(),
                    &ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([9; 20])),
                );
                transaction.input[0].witness = envelope::witness(&[0; 64], &script, &info).unwrap();
                transaction
            };
            let mut block = bitcoin::blockdata::constants::genesis_block(Network::Regtest);
            block.txdata = vec![envelope_transaction(&forged)];
            let mut objects = BTreeMap::new();
            assert_eq!(collect_records(&block, &key, &mut objects).unwrap(), 1);
            assert!(objects.is_empty());

            block.txdata = vec![
                envelope_transaction(&records[0]),
                envelope_transaction(&forged),
            ];
            assert_eq!(collect_records(&block, &key, &mut objects).unwrap(), 1);
            assert_eq!(objects.len(), 1);
            assert!(objects.values().next().unwrap().finish().is_err());

            block.txdata = vec![
                envelope_transaction(&forged),
                envelope_transaction(&records[1]),
            ];
            assert_eq!(collect_records(&block, &key, &mut objects).unwrap(), 1);
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
        fn witness_tampering_keeps_txid_but_fails_commitment() {
            let mut block = bitcoin::blockdata::constants::genesis_block(Network::Regtest);
            block.txdata[0].input[0].witness = Witness::from_slice(&[[0u8; 32]]);
            let mut tx = transaction(
                OutPoint::null(),
                &ScriptBuf::new_p2wpkh(&bitcoin::WPubkeyHash::from_byte_array([9; 20])),
            );
            tx.input[0].previous_output.vout = 0;
            tx.input[0].witness = Witness::from_slice(&[b"authentic witness".as_slice()]);
            block.txdata.push(tx);
            let commitment =
                Block::compute_witness_commitment(&block.witness_root().unwrap(), &[0; 32]);
            let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
            script.extend_from_slice(commitment.as_byte_array());
            block.txdata[0].output.push(TxOut {
                value: Amount::ZERO,
                script_pubkey: ScriptBuf::from_bytes(script),
            });
            block.header.merkle_root = block.compute_merkle_root().unwrap();
            block.header.nonce = 0;
            while block.header.validate_pow(block.header.target()).is_err() {
                block.header.nonce += 1;
            }
            let hash = block.block_hash();
            validate_block(&block, hash).unwrap();
            let txid = block.txdata[1].compute_txid();
            block.txdata[1].input[0].witness =
                Witness::from_slice(&[b"tampered witness".as_slice()]);
            assert_eq!(txid, block.txdata[1].compute_txid());
            assert!(block.check_merkle_root());
            assert!(
                validate_block(&block, hash)
                    .unwrap_err()
                    .to_string()
                    .contains("witness commitment")
            );
        }
    }
}

pub mod backend {
    include!("../../urma/src/backend.rs");
    #[cfg(test)]
    mod checks {

        use super::*;

        #[test]
        fn default_litecoin_does_not_silently_select_bitcoin() {
            let policy = Policy::default();
            assert_eq!(policy.preferred, Family::Litecoin);
            assert!(require_implemented(policy.preferred).is_ok());
            assert!(require_implemented(Family::Ethereum).is_err());
            assert!(require_implemented(Family::Bitcoin).is_ok());
            assert!(require_implemented(Family::Directory).is_ok());
        }

        #[test]
        fn directory_replication_and_discovery_need_no_sender_manifest() {
            let work = tempfile::tempdir().unwrap();
            let key = [42; 32];
            let bytes = include_bytes!("../../../tests/fixtures/sample.jpg");
            let records = container::seal(&key, bytes, urma::format::ContentType::Opaque).unwrap();
            let first = work.path().join("first");
            let second = work.path().join("independent");
            store_directory(&first, &records).unwrap();
            store_directory(&second, &records).unwrap();
            let mut fake = records[0].clone();
            fake[urma::format::Urma::BODY_OFFSET] ^= 1;
            storage::write_new(&second.join("forged.urma-record"), &fake).unwrap();
            let result = recover(&DirectorySource { path: &second }, &key).unwrap();
            assert_eq!(result.rejected_records, 1);
            assert_eq!(result.objects.len(), 1);
            assert_eq!(
                *result.objects.values().next().unwrap().finish().unwrap(),
                bytes
            );
            assert!(
                recover(&DirectorySource { path: &second }, &[43; 32])
                    .unwrap()
                    .objects
                    .is_empty()
            );
            assert!(store_directory(&second, &records).is_err());
            let locator = serde_json::to_vec(&result.observation.locator).unwrap();
            assert!(matches!(
                serde_json::from_slice::<Locator>(&locator).unwrap(),
                Locator::Directory { .. }
            ));
        }
    }
}
