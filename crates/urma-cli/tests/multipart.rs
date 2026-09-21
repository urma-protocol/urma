use anyhow::{Context, Result};
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, Witness, absolute,
    consensus::{deserialize, serialize},
    hashes::Hash,
    secp256k1::{Keypair, Secp256k1, SecretKey},
    transaction::Version,
};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::Command,
};
use urma_chain::observation::Chain;
use urma_core::{envelope, format::PublicRecord};
use urma_runtime::{
    container::{self, RecordMatch},
    error::Error,
    multipart::{
        ChildReference, DataPart, FetchError, Geometry, LeafManifest, MultipartRecord,
        MultipartSource, RecordRequest, RecoveryError, RecoveryLimits, RootManifest,
        VerifiedRecord, reconstruct,
    },
};
use urma_wallet::funding::Funding;

fn vectors() -> PathBuf {
    Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/../..")).join("tests/vectors/multipart")
}
fn manifest() -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read(
        vectors().join("manifest.json"),
    )?)?)
}
fn artifact(value: &Value) -> Result<Vec<u8>> {
    let bytes = fs::read(vectors().join(value["file"].as_str().context("file")?))?;
    assert_eq!(bytes.len() as u64, value["bytes"].as_u64().unwrap());
    assert_eq!(
        hex::encode(Sha256::digest(&bytes)),
        value["sha256"].as_str().unwrap()
    );
    Ok(bytes)
}

#[test]
fn independent_records_and_sparse_geometry() -> Result<()> {
    let m = manifest()?;
    for case in m["records"].as_array().unwrap() {
        let bytes = artifact(&case["record"])?;
        let result = MultipartRecord::decode(&bytes);
        if case["outcome"] == "valid" {
            assert_eq!(result?.encode()?, bytes, "{}", case["name"]);
            assert!(PublicRecord::decode(&bytes).is_err());
            assert!(matches!(
                container::open_record(&[0; 32], &bytes)?,
                RecordMatch::Unrelated
            ));
        } else {
            assert!(result.is_err(), "{}", case["name"]);
        }
    }
    for case in m["geometry"].as_array().unwrap() {
        let result = Geometry::new(case["length"].as_u64().unwrap());
        if case["outcome"] == "valid" {
            let g = result?;
            assert_eq!(u64::from(g.parts()), case["parts"].as_u64().unwrap());
            assert_eq!(u64::from(g.leaves()), case["leaves"].as_u64().unwrap());
            assert_eq!(
                g.part_length(g.parts() - 1)? as u64,
                case["last_part_bytes"].as_u64().unwrap()
            );
            assert_eq!(
                u64::from(g.leaf_entries(g.leaves() - 1)?),
                case["last_leaf_entries"].as_u64().unwrap()
            );
            assert!(g.part_length(g.parts()).is_err());
            assert!(g.leaf_entries(g.leaves()).is_err());
        } else {
            assert!(result.is_err());
        }
    }
    assert_eq!(
        Geometry::new(Geometry::MAX_OBJECT_BYTES)?.nodes(),
        Geometry::MAX_NODES
    );
    Ok(())
}

#[test]
fn independent_proofs_and_candidate_binding() -> Result<()> {
    for case in manifest()?["proofs"].as_array().unwrap() {
        let commit: Transaction = deserialize(&artifact(&case["commit"])?)?;
        let reveal: Transaction = deserialize(&artifact(&case["reveal"])?)?;
        let result =
            VerifiedRecord::verify(case["txid"].as_str().unwrap().parse()?, &reveal, &commit);
        if case["outcome"] == "valid" {
            let verified = result?;
            assert_eq!(
                verified.author().to_string(),
                case["author"].as_str().unwrap()
            );
            if case["record_outcome"] == "invalid" {
                assert!(verified.decode().is_err());
            } else {
                assert_eq!(verified.decode()?.encode()?, artifact(&case["record"])?);
            }
            assert!(VerifiedRecord::verify(Txid::all_zeros(), &reveal, &commit).is_err());
            let mut request = RecordRequest {
                reference: verified.reference(),
            };
            assert_eq!(
                request.verify(&reveal, &commit)?.reference(),
                verified.reference()
            );
            request.reference.record_hash[0] ^= 1;
            assert!(request.verify(&reveal, &commit).is_err());
        } else {
            assert!(result.is_err(), "{}", case["name"]);
        }
    }
    Ok(())
}

struct Source {
    records: HashMap<Txid, VerifiedRecord>,
    calls: usize,
}
impl MultipartSource for Source {
    fn fetch(&mut self, request: &RecordRequest) -> Result<VerifiedRecord, FetchError> {
        self.calls += 1;
        self.records
            .get(&request.reference.txid)
            .cloned()
            .ok_or(FetchError::Unavailable)
    }
}
fn limits() -> RecoveryLimits {
    RecoveryLimits {
        max_payload_bytes: 256 * 1024 * 1024,
        max_nodes: 4096,
    }
}
fn outcome(
    result: &Result<urma_runtime::multipart::RecoveredObject, RecoveryError>,
) -> &'static str {
    match result {
        Ok(_) => "complete",
        Err(RecoveryError::InvalidObject(_)) => "invalid_object",
        Err(RecoveryError::InvalidCandidate { .. }) => "invalid_candidate",
        Err(RecoveryError::Incomplete { .. }) => "incomplete",
        Err(RecoveryError::Capacity(_)) => "capacity",
        Err(RecoveryError::Source { .. }) => "source",
        Err(RecoveryError::Storage(_)) => "storage",
    }
}

#[test]
fn independent_signed_graphs_have_typed_results_and_no_partial_export() -> Result<()> {
    let m = manifest()?;
    let mut verified = HashMap::new();
    for case in m["proofs"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|p| p["outcome"] == "valid")
    {
        let commit: Transaction = deserialize(&artifact(&case["commit"])?)?;
        let reveal: Transaction = deserialize(&artifact(&case["reveal"])?)?;
        verified.insert(
            case["name"].as_str().unwrap(),
            VerifiedRecord::verify(reveal.compute_txid(), &reveal, &commit)?,
        );
    }
    let temp = tempfile::tempdir()?;
    for case in m["graphs"].as_array().unwrap() {
        let mut source = Source {
            records: HashMap::new(),
            calls: 0,
        };
        for name in case["available"].as_array().unwrap() {
            let record = &verified[name.as_str().unwrap()];
            source.records.insert(record.txid(), record.clone());
        }
        let root = &verified[case["root"].as_str().unwrap()];
        let result = reconstruct(root, &mut source, limits(), temp.path());
        assert_eq!(
            outcome(&result),
            case["outcome"].as_str().unwrap(),
            "{}",
            case["name"]
        );
        if let Ok(mut complete) = result {
            let mut bytes = Vec::new();
            complete.read_to_end(&mut bytes)?;
            assert_eq!(bytes.len() as u64, case["length"].as_u64().unwrap());
            assert_eq!(
                hex::encode(Sha256::digest(bytes)),
                case["sha256"].as_str().unwrap()
            );
            assert_eq!(complete.root(), root.txid());
            assert_eq!(complete.author(), root.author());
            assert_eq!(complete.manifest().profile, *b"opaque?!");
        }
        assert_eq!(fs::read_dir(temp.path())?.count(), 0);
    }
    Ok(())
}

fn key(value: u8) -> Result<Keypair> {
    Ok(Keypair::from_secret_key(
        &Secp256k1::new(),
        &SecretKey::from_slice(&[value; 32])?,
    ))
}
fn signed(
    record: MultipartRecord,
    author: u8,
) -> Result<(VerifiedRecord, Transaction, Transaction)> {
    let funding = Transaction {
        version: Version::TWO,
        lock_time: absolute::LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000_000),
            script_pubkey: ScriptBuf::from_bytes([vec![0, 20], vec![4; 20]].concat()),
        }],
    };
    let plan = urma_runtime::publication::prepare_multipart(
        &record,
        &key(author)?,
        Funding {
            raw_transaction: hex::encode(serialize(&funding)),
            vout: 0,
        },
        Chain::BitcoinRegtest,
        1,
    )?;
    let commit: Transaction = deserialize(&hex::decode(plan.commit)?)?;
    let reveal: Transaction = deserialize(&hex::decode(plan.reveal)?)?;
    let verified = VerifiedRecord::verify(reveal.compute_txid(), &reveal, &commit)?;
    assert_eq!(verified.decode()?, record);
    Ok((verified, reveal, commit))
}
fn sign(record: MultipartRecord) -> Result<VerifiedRecord> {
    Ok(signed(record, 3)?.0)
}

struct Graph {
    source: Source,
    root: VerifiedRecord,
    leaves: Vec<LeafManifest>,
    manifest: RootManifest,
}
impl Graph {
    fn new(parts: u32, export: Option<&Path>) -> Result<Self> {
        let mut source = Source {
            records: HashMap::new(),
            calls: 0,
        };
        let mut references = Vec::new();
        let mut digest = Sha256::new();
        for index in 0..parts {
            let payload = vec![(index % 251) as u8; Geometry::DATA_BYTES];
            digest.update(&payload);
            let (record, reveal, commit) =
                signed(MultipartRecord::Data(DataPart { index, payload }), 3)?;
            if let Some(path) = export {
                export_pair(path, &reveal, &commit)?;
            }
            references.push(record.reference());
            source.records.insert(record.txid(), record);
        }
        let mut leaves = Vec::new();
        let mut entries = Vec::new();
        for (index, refs) in references.chunks(usize::from(Geometry::FANOUT)).enumerate() {
            let leaf = LeafManifest {
                index: index as u16,
                entries: refs.to_vec(),
            };
            let (record, reveal, commit) = signed(MultipartRecord::Leaf(leaf.clone()), 3)?;
            if let Some(path) = export {
                export_pair(path, &reveal, &commit)?;
            }
            entries.push(record.reference());
            source.records.insert(record.txid(), record);
            leaves.push(leaf);
        }
        let manifest = RootManifest {
            length: u64::from(parts) * Geometry::DATA_BYTES as u64,
            payload_hash: digest.finalize().into(),
            profile: *b"unknown!",
            entries,
        };
        let (root, reveal, commit) = signed(MultipartRecord::Root(manifest.clone()), 3)?;
        if let Some(path) = export {
            export_pair(path, &reveal, &commit)?;
        }
        Ok(Self {
            source,
            root,
            leaves,
            manifest,
        })
    }
    fn refresh(&mut self) -> Result<()> {
        self.manifest.entries.clear();
        for leaf in &self.leaves {
            let record = sign(MultipartRecord::Leaf(leaf.clone()))?;
            self.manifest.entries.push(record.reference());
            self.source.records.insert(record.txid(), record);
        }
        self.root = sign(MultipartRecord::Root(self.manifest.clone()))?;
        Ok(())
    }
}
fn export_pair(path: &Path, reveal: &Transaction, commit: &Transaction) -> Result<()> {
    fs::create_dir_all(path.join("tx"))?;
    for tx in [reveal, commit] {
        fs::write(
            path.join("tx").join(format!("{}.bin", tx.compute_txid())),
            serialize(tx),
        )?;
    }
    Ok(())
}

#[test]
fn multiple_leaves_stream_exact_bytes_and_reject_order_duplicates_and_missing() -> Result<()> {
    let temp = tempfile::tempdir()?;
    let export = tempfile::tempdir()?;
    let mut graph = Graph::new(512, Some(export.path()))?;
    assert_eq!(graph.leaves[0].entries.len(), 511);
    assert_eq!(graph.leaves[1].entries.len(), 1);
    let mut recovered = reconstruct(&graph.root, &mut graph.source, limits(), temp.path())?;
    let mut buffer = vec![0; Geometry::DATA_BYTES];
    for index in 0..512 {
        recovered.read_exact(&mut buffer)?;
        assert!(buffer.iter().all(|b| *b == (index % 251) as u8));
    }
    assert_eq!(recovered.read(&mut buffer)?, 0);
    let output = Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../scripts/read-multipart.py"
        ))
        .arg("--directory")
        .arg(export.path())
        .arg("--root")
        .arg(graph.root.txid().to_string())
        .arg("--output")
        .arg(export.path().join("object.bin"))
        .arg("--max-bytes")
        .arg(limits().max_payload_bytes.to_string())
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout)?;
    assert_eq!(report["length"], graph.manifest.length);
    assert_eq!(report["sha256"], hex::encode(graph.manifest.payload_hash));
    let mut independent = fs::File::open(export.path().join("object.bin"))?;
    for index in 0..512 {
        independent.read_exact(&mut buffer)?;
        assert!(buffer.iter().all(|b| *b == (index % 251) as u8));
    }
    assert_eq!(independent.read(&mut buffer)?, 0);
    let canonical = graph.root.clone();
    graph.manifest.entries.swap(0, 1);
    graph.root = sign(MultipartRecord::Root(graph.manifest.clone()))?;
    assert_eq!(
        outcome(&reconstruct(
            &graph.root,
            &mut graph.source,
            limits(),
            temp.path()
        )),
        "invalid_object"
    );
    graph.manifest.entries[1] = graph.manifest.entries[0];
    graph.root = sign(MultipartRecord::Root(graph.manifest.clone()))?;
    assert_eq!(
        outcome(&reconstruct(
            &graph.root,
            &mut graph.source,
            limits(),
            temp.path()
        )),
        "invalid_object"
    );
    graph.leaves[1].entries[0] = graph.leaves[0].entries[0];
    graph.refresh()?;
    assert_eq!(
        outcome(&reconstruct(
            &graph.root,
            &mut graph.source,
            limits(),
            temp.path()
        )),
        "invalid_object"
    );
    let missing = graph.leaves[0].entries[0].txid;
    let retained = graph.source.records.remove(&missing).unwrap();
    assert_eq!(
        outcome(&reconstruct(
            &canonical,
            &mut graph.source,
            limits(),
            temp.path()
        )),
        "incomplete"
    );
    graph.source.records.insert(missing, retained);
    assert!(reconstruct(&canonical, &mut graph.source, limits(), temp.path()).is_ok());
    Ok(())
}

#[test]
fn source_failures_capacity_and_invalid_candidates_do_not_poison_retries() -> Result<()> {
    let mut graph = Graph::new(2, None)?;
    let temp = tempfile::tempdir()?;
    let limited = RecoveryLimits {
        max_payload_bytes: 1,
        max_nodes: 4096,
    };
    assert_eq!(
        outcome(&reconstruct(
            &graph.root,
            &mut graph.source,
            limited,
            temp.path()
        )),
        "capacity"
    );
    assert_eq!(graph.source.calls, 0);
    let limited = RecoveryLimits {
        max_payload_bytes: 256 * 1024 * 1024,
        max_nodes: 3,
    };
    assert_eq!(
        outcome(&reconstruct(
            &graph.root,
            &mut graph.source,
            limited,
            temp.path()
        )),
        "capacity"
    );
    assert_eq!(graph.source.calls, 0);
    struct Failing;
    impl MultipartSource for Failing {
        fn fetch(&mut self, _: &RecordRequest) -> Result<VerifiedRecord, FetchError> {
            Err(FetchError::Source(Error::Io(
                std::io::ErrorKind::TimedOut.into(),
            )))
        }
    }
    assert_eq!(
        outcome(&reconstruct(
            &graph.root,
            &mut Failing,
            limits(),
            temp.path()
        )),
        "source"
    );
    let target = graph.manifest.entries[0].txid;
    let good = graph
        .source
        .records
        .insert(target, graph.root.clone())
        .unwrap();
    assert_eq!(
        outcome(&reconstruct(
            &graph.root,
            &mut graph.source,
            limits(),
            temp.path()
        )),
        "invalid_candidate"
    );
    graph.source.records.insert(target, good);
    assert!(reconstruct(&graph.root, &mut graph.source, limits(), temp.path()).is_ok());
    for entry in graph.leaves[0]
        .entries
        .clone()
        .into_iter()
        .chain(graph.manifest.entries.clone())
    {
        let good = graph.source.records.remove(&entry.txid).unwrap();
        assert_eq!(
            outcome(&reconstruct(
                &graph.root,
                &mut graph.source,
                limits(),
                temp.path()
            )),
            "incomplete"
        );
        graph.source.records.insert(entry.txid, good);
    }
    assert!(reconstruct(&graph.root, &mut graph.source, limits(), temp.path()).is_ok());
    Ok(())
}

#[test]
fn invalid_reference_types_and_contextual_counts() -> Result<()> {
    let mut graph = Graph::new(2, None)?;
    let temp = tempfile::tempdir()?;
    let mut nested = graph.leaves[0].clone();
    nested.index = 1;
    let nested = sign(MultipartRecord::Leaf(nested))?;
    graph.leaves[0].entries[0] = nested.reference();
    graph.source.records.insert(nested.txid(), nested);
    graph.refresh()?;
    assert_eq!(
        outcome(&reconstruct(
            &graph.root,
            &mut graph.source,
            limits(),
            temp.path()
        )),
        "invalid_object"
    );
    graph.leaves[0].entries.pop();
    graph.refresh()?;
    assert_eq!(
        outcome(&reconstruct(
            &graph.root,
            &mut graph.source,
            limits(),
            temp.path()
        )),
        "invalid_object"
    );
    let part = sign(MultipartRecord::Data(DataPart {
        index: 0,
        payload: vec![],
    }))?;
    assert_eq!(
        outcome(&reconstruct(
            &part,
            &mut graph.source,
            limits(),
            temp.path()
        )),
        "invalid_object"
    );
    Ok(())
}

#[test]
fn multipart_proofs_reject_transaction_prevout_witness_and_signature_mutations() -> Result<()> {
    let record = MultipartRecord::Data(DataPart {
        index: 0,
        payload: vec![0; Geometry::DATA_BYTES],
    });
    let (_, original, commit) = signed(record, 3)?;
    let stack: Vec<Vec<u8>> = original.input[0]
        .witness
        .iter()
        .map(<[u8]>::to_vec)
        .collect();
    for mutation in 0..10 {
        let mut parts = stack.clone();
        match mutation {
            0 => parts[0][0] ^= 1,
            1 => parts[0].push(0),
            2 => parts[2][0] ^= 1,
            3 => parts[2][1] ^= 1,
            4 => parts[2].extend_from_slice(&[0; 32]),
            5 => parts.push(vec![0x50]),
            6 => parts[1][33] = 0x75,
            7 => parts[2][0] = 0xc2,
            8 => parts[1].push(0),
            9 => {
                parts.remove(0);
            }
            _ => unreachable!(),
        }
        let mut tx = original.clone();
        tx.input[0].witness = Witness::from_slice(&parts);
        assert!(
            VerifiedRecord::verify(tx.compute_txid(), &tx, &commit).is_err(),
            "mutation {mutation}"
        );
    }
    let mut prevout = commit.output[0].clone();
    prevout.value += Amount::from_sat(1);
    assert!(envelope::verify_prevout(&original, &prevout).is_err());
    prevout = commit.output[0].clone();
    prevout.script_pubkey = ScriptBuf::new();
    assert!(envelope::verify_prevout(&original, &prevout).is_err());
    let mut wrong_commit = commit.clone();
    wrong_commit.output[0].value += Amount::from_sat(1);
    assert!(VerifiedRecord::verify(original.compute_txid(), &original, &wrong_commit).is_err());
    Ok(())
}

#[test]
fn independent_python_reader_checks_the_entire_corpus() -> Result<()> {
    let result = Command::new("python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../scripts/read-multipart.py"
        ))
        .arg("--corpus")
        .arg(vectors())
        .output()?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(())
}

#[test]
fn constructors_refuse_out_of_range_data_and_manifest_fields() -> Result<()> {
    let reference = ChildReference {
        txid: Txid::all_zeros(),
        record_hash: [0; 32],
    };
    for part in [
        DataPart {
            index: Geometry::MAX_PARTS,
            payload: vec![],
        },
        DataPart {
            index: 0,
            payload: vec![0; Geometry::DATA_BYTES + 1],
        },
    ] {
        assert!(MultipartRecord::Data(part).encode().is_err());
    }
    for leaf in [
        LeafManifest {
            index: 511,
            entries: vec![reference],
        },
        LeafManifest {
            index: 0,
            entries: vec![],
        },
        LeafManifest {
            index: 0,
            entries: vec![reference; 512],
        },
    ] {
        assert!(MultipartRecord::Leaf(leaf).encode().is_err());
    }
    let root = RootManifest {
        length: u64::MAX,
        payload_hash: [0; 32],
        profile: [0; 8],
        entries: vec![reference],
    };
    assert!(MultipartRecord::Root(root).encode().is_err());
    Ok(())
}

#[test]
fn detached_plan_inventory_rejects_cycles_before_io_and_does_not_claim_proofs() -> Result<()> {
    use urma_runtime::multipart::ManifestInventory;
    let root_id = Txid::from_byte_array([1; 32]);
    let leaf_id = Txid::from_byte_array([2; 32]);
    let data_id = Txid::from_byte_array([3; 32]);
    let reference = |txid| ChildReference {
        txid,
        record_hash: [0; 32],
    };
    let mut manifest = RootManifest {
        length: 0,
        payload_hash: Sha256::digest([]).into(),
        profile: [0; 8],
        entries: vec![reference(leaf_id)],
    };
    for target in [root_id, leaf_id] {
        let mut inventory = ManifestInventory::new(root_id, &manifest)?;
        let mut leaf = LeafManifest {
            index: 0,
            entries: vec![reference(target)],
        };
        assert!(inventory.accept_leaf(&leaf).is_err());
        assert!(!inventory.is_complete());
        leaf.entries[0] = reference(data_id);
        inventory.accept_leaf(&leaf)?;
        assert!(inventory.is_complete());
        assert!(inventory.accept_leaf(&leaf).is_err());
    }
    manifest.entries[0] = reference(root_id);
    assert!(ManifestInventory::new(root_id, &manifest).is_err());
    Ok(())
}

#[test]
fn multipart_256k_boundary_keeps_atomic_public_cap() -> Result<()> {
    use urma_core::format::Urma;
    assert_eq!(Geometry::RECORD_BYTES, 262144);
    assert_eq!(Geometry::DATA_BYTES, 262132);
    assert_eq!(Urma::MAX_PUBLIC_BYTES, 32768);
    let maximum = Geometry::new(8_553_279_476)?;
    assert_eq!(
        (maximum.parts(), maximum.leaves(), maximum.nodes()),
        (32630, 64, 32695)
    );
    assert_eq!(maximum.part_length(32629)?, 174448);
    assert!(Geometry::new(8_553_279_477).is_err());
    assert!(Geometry::new(Geometry::DATA_BYTES as u64 * 511 * 511).is_err());
    let full = MultipartRecord::Data(DataPart {
        index: 0,
        payload: vec![0xa5; Geometry::DATA_BYTES],
    });
    let (record, reveal, commit) = signed(full, 3)?;
    assert_eq!(record.record_bytes().len(), Geometry::RECORD_BYTES);
    assert_eq!(reveal.weight().to_wu(), 264134);
    assert_eq!(reveal.vsize(), 66034);
    assert!(envelope::verify_reveal(&reveal, &commit).is_ok());
    let mut oversized = record.record_bytes().to_vec();
    oversized.push(0);
    assert!(MultipartRecord::decode(&oversized).is_err());
    let mut atomic = urma_core::format::RecordKind::Post.prefix().to_vec();
    atomic.resize(32768, b'x');
    assert!(PublicRecord::decode(&atomic).is_ok());
    atomic.push(b'x');
    assert!(PublicRecord::decode(&atomic).is_err());
    Ok(())
}
