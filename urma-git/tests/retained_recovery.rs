//! Caller-owned local PACKs and genuinely signed multipart transaction graphs.
//! No Node, provider, socket, user state, chain membership or UTXO validity claim.
use anyhow::{Result, ensure};
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Txid, WPubkeyHash, Witness,
    absolute::LockTime,
    consensus::{deserialize, serialize},
    hashes::Hash,
    secp256k1::{Keypair, Secp256k1, SecretKey},
    transaction::Version,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::Read,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};
use urma_chain::observation::Chain;
use urma_core::multipart::{
    DataPart, Geometry, LeafManifest, MultipartRecord, RootManifest, VerifiedRecord,
};
use urma_git::{
    config::CloneDestination,
    descriptor::Descriptor,
    inventory::Limits,
    proofs::Locator,
    snapshot::{self, SnapshotReport},
    workflows,
};
use urma_runtime::publication;

struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

// No pipes can fill while waiting. Every child has a deadline and kill/reap
// ownership from spawn, including assertion unwind. All config/HOME is owned.
fn git(directory: &Path, args: &[&str]) -> Result<String> {
    let mut output = tempfile::tempfile_in(directory)?;
    let mut errors = tempfile::tempfile_in(directory)?;
    let mut child = OwnedChild(
        Command::new("git")
            .env_clear()
            .env("PATH", "/usr/bin:/bin")
            .env("HOME", directory)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_NO_REPLACE_OBJECTS", "1")
            .env("GIT_NO_LAZY_FETCH", "1")
            .env("GIT_TERMINAL_PROMPT", "0")
            .env("GIT_AUTHOR_NAME", "Public Fixture")
            .env("GIT_AUTHOR_EMAIL", "fixture@example.invalid")
            .env("GIT_COMMITTER_NAME", "Public Fixture")
            .env("GIT_COMMITTER_EMAIL", "fixture@example.invalid")
            .env("GIT_AUTHOR_DATE", "2000-01-01T00:00:00Z")
            .env("GIT_COMMITTER_DATE", "2000-01-01T00:00:00Z")
            .arg("-C")
            .arg(directory)
            .args([
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "commit.gpgSign=false",
                "-c",
                "core.fsmonitor=false",
                "-c",
                "protocol.allow=never",
            ])
            .args(args)
            .stdin(Stdio::null())
            .stdout(output.try_clone()?)
            .stderr(errors.try_clone()?)
            .spawn()?,
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.0.try_wait()? {
            break status;
        }
        ensure!(Instant::now() < deadline, "owned Git child deadline");
        thread::sleep(Duration::from_millis(5));
    };
    use std::io::Seek;
    output.rewind()?;
    errors.rewind()?;
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    output.take(32 * 1024 + 1).read_to_end(&mut stdout)?;
    errors.take(32 * 1024 + 1).read_to_end(&mut stderr)?;
    ensure!(
        stdout.len() <= 32 * 1024 && stderr.len() <= 32 * 1024,
        "Git fixture output bound"
    );
    ensure!(
        status.success(),
        "local Git fixture: {}",
        String::from_utf8_lossy(&stderr)
    );
    Ok(String::from_utf8(stdout)?.trim().into())
}

fn signed(
    record: &MultipartRecord,
    directory: &Path,
    evidence: &mut BTreeMap<String, Vec<u8>>,
) -> Result<VerifiedRecord> {
    let seed = u8::try_from(evidence.len() + 1)?;
    let funding = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([seed; 32]),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(1_000_000),
            script_pubkey: ScriptBuf::new_p2wpkh(&WPubkeyHash::from_byte_array([seed; 20])),
        }],
    };
    let author = Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[3; 32])?);
    // Reuse the existing public Funding serde shape, with its type inferred from
    // publication. This needs no new direct dependency on the wallet crate.
    let plan = publication::prepare_multipart(
        record,
        &author,
        vec![serde_json::from_value(
            json!({"raw_transaction":hex::encode(serialize(&funding)),"vout":0}),
        )?],
        &funding.output[0].script_pubkey,
        Chain::BitcoinRegtest,
        1,
    )?;
    let commit: Transaction = deserialize(&hex::decode(&plan.commit)?)?;
    let reveal: Transaction = deserialize(&hex::decode(&plan.reveal)?)?;
    let verified = VerifiedRecord::verify(reveal.compute_txid(), &reveal, &commit)?;
    ensure!(verified.decode()? == *record);
    for transaction in [&commit, &reveal] {
        let name = format!("{}.bin", transaction.compute_txid());
        let raw = serialize(transaction);
        fs::write(directory.join("tx").join(&name), &raw)?;
        ensure!(evidence.insert(name, raw).is_none());
    }
    Ok(verified)
}

struct Graph {
    evidence: BTreeMap<String, Vec<u8>>,
    locator: Locator,
    root: RootManifest,
    part: Txid,
}

fn graph(directory: &Path, payload: &[u8], profile: [u8; 8]) -> Result<Graph> {
    snapshot::create_private_directory(directory)?;
    snapshot::create_private_directory(&directory.join("tx"))?;
    let mut evidence = BTreeMap::new();
    let mut parts = Vec::new();
    for (index, bytes) in payload.chunks(Geometry::DATA_BYTES).enumerate() {
        let verified = signed(
            &MultipartRecord::Data(DataPart {
                index: u32::try_from(index)?,
                payload: bytes.to_vec(),
            }),
            directory,
            &mut evidence,
        )?;
        parts.push(verified.reference());
    }
    ensure!(
        parts.len() >= 2,
        "fixture must exercise multiple actual signed data parts"
    );
    let part = parts[0].txid;
    let leaf = signed(
        &MultipartRecord::Leaf(LeafManifest {
            index: 0,
            entries: parts,
        }),
        directory,
        &mut evidence,
    )?;
    let root = RootManifest {
        length: u64::try_from(payload.len())?,
        payload_hash: Sha256::digest(payload).into(),
        profile,
        entries: vec![leaf.reference()],
    };
    let verified = signed(
        &MultipartRecord::Root(root.clone()),
        directory,
        &mut evidence,
    )?;
    let locator = Locator {
        schema: 1,
        chain: Chain::BitcoinRegtest,
        genesis: Chain::BitcoinRegtest.genesis()?.0.to_string(),
        root: verified.txid(),
    };
    fs::write(
        directory.join("locator.json"),
        serde_json::to_vec_pretty(&locator)?,
    )?;
    Ok(Graph {
        evidence,
        locator,
        root,
        part,
    })
}

struct Fixture {
    lab: tempfile::TempDir,
    directory: PathBuf,
    payload: Vec<u8>,
    head: String,
    expected: SnapshotReport,
    graph: Graph,
}

impl Fixture {
    fn new(format: &str) -> Result<Self> {
        let lab = tempfile::tempdir()?;
        let repository = lab.path().join("source");
        snapshot::create_private_directory(&repository)?;
        git(
            &repository,
            &[
                "init",
                "--template=",
                &format!("--object-format={format}"),
                "--initial-branch=main",
            ],
        )?;
        fs::write(
            repository.join("README.txt"),
            b"public retained recovery fixture\n",
        )?;
        let mut random = 17u64;
        let bytes: Vec<_> = (0..300_001)
            .map(|_| {
                random ^= random << 13;
                random ^= random >> 7;
                random ^= random << 17;
                random as u8
            })
            .collect();
        fs::write(repository.join("data.bin"), bytes)?;
        git(&repository, &["add", "."])?;
        git(&repository, &["commit", "-m", "public fixture"])?;
        let head = git(&repository, &["rev-parse", "HEAD"])?;
        let prepared = lab.path().join("prepared");
        let expected = snapshot::prepare_named(
            &repository,
            &prepared,
            &Limits::default(),
            "retained-project",
        )?;
        let payload = fs::read(prepared.join("object.bin"))?;
        let directory = lab.path().join("retained");
        let graph = graph(&directory, &payload, expected.descriptor.profile())?;
        Ok(Self {
            lab,
            directory,
            payload,
            head,
            expected,
            graph,
        })
    }

    fn copied(&self, name: &str, cache: bool) -> Result<PathBuf> {
        let directory = self.lab.path().join(name);
        snapshot::create_private_directory(&directory)?;
        snapshot::create_private_directory(&directory.join("tx"))?;
        fs::copy(
            self.directory.join("locator.json"),
            directory.join("locator.json"),
        )?;
        for (name, raw) in &self.graph.evidence {
            fs::write(directory.join("tx").join(name), raw)?;
        }
        if cache {
            fs::write(directory.join("object.bin"), &self.payload)?;
        }
        Ok(directory)
    }

    fn assert_evidence(&self, directory: &Path) -> Result<()> {
        ensure!(
            fs::read(directory.join("locator.json"))?
                == fs::read(self.directory.join("locator.json"))?
        );
        ensure!(fs::read_dir(directory.join("tx"))?.count() == self.graph.evidence.len());
        for (name, raw) in &self.graph.evidence {
            ensure!(fs::read(directory.join("tx").join(name))? == *raw);
        }
        Ok(())
    }
}

#[test]
fn retained_recovery_reconstructs_both_git_formats_and_exact_artifacts() -> Result<()> {
    for format in ["sha1", "sha256"] {
        let fixture = Fixture::new(format)?;
        // The reader provides only locator + canonical tx projections, no payload.
        ensure!(!fixture.directory.join("object.bin").exists());
        let report = workflows::recover_retained(&fixture.directory, &Limits::default())?;
        ensure!(report.chain_inclusion == "not_checked");
        ensure!(
            report.content == "complete"
                && report.author_proof == "verified"
                && report.git_profile == "verified"
        );
        ensure!(report.locator.root == fixture.graph.locator.root);
        ensure!(
            serde_json::to_value(&report.snapshot.descriptor)?
                == serde_json::to_value(&fixture.expected.descriptor)?
        );
        ensure!(
            serde_json::to_value(&report.snapshot.inventory)?
                == serde_json::to_value(&fixture.expected.inventory)?
        );
        ensure!(
            serde_json::to_value(&report.snapshot.scan)?
                == serde_json::to_value(&fixture.expected.scan)?
        );
        ensure!(fs::read(fixture.directory.join("object.bin"))? == fixture.payload);
        ensure!(
            fs::read(fixture.directory.join("snapshot.pack"))?
                == fs::read(fixture.lab.path().join("prepared/snapshot.pack"))?
        );
        let stored: workflows::RecoveredReport =
            serde_json::from_slice(&fs::read(fixture.directory.join("recovery.json"))?)?;
        ensure!(serde_json::to_value(&stored)? == serde_json::to_value(&report)?);
        fixture.assert_evidence(&fixture.directory)?;
        // A second invocation still reconstructs, even with all generated caches.
        let again = workflows::recover_retained(&fixture.directory, &Limits::default())?;
        ensure!(serde_json::to_value(again)? == serde_json::to_value(report)?);
    }
    Ok(())
}

#[test]
fn recover_then_clone_revalidates_and_installs_retained_proofs_without_membership_claim()
-> Result<()> {
    let fixture = Fixture::new("sha1")?;
    let first = workflows::recover_retained(&fixture.directory, &Limits::default())?;
    let destination = fixture.lab.path().join("clone");
    let (report, installed) = workflows::clone_retained_named(
        &fixture.directory,
        CloneDestination(Some(destination.clone())),
        &Limits::default(),
    )?;
    ensure!(installed == destination);
    ensure!(report.chain_inclusion == "not_checked");
    ensure!(serde_json::to_value(&report)? == serde_json::to_value(first)?);
    ensure!(git(&destination, &["rev-parse", "HEAD"])? == fixture.head);
    ensure!(
        git(
            &destination,
            &["status", "--porcelain=v1", "--untracked-files=all"]
        )?
        .is_empty()
    );
    ensure!(fs::read(destination.join("README.txt"))? == b"public retained recovery fixture\n");
    let retained = destination.join(".git/urma");
    fixture.assert_evidence(&retained)?;
    ensure!(fs::read(retained.join("object.bin"))? == fixture.payload);
    ensure!(!retained.join("recovery.json").exists());
    let verified = workflows::verify(&retained, &Limits::default())?;
    ensure!(verified.chain_inclusion == "not_checked" && verified.author == report.author);
    fs::write(destination.join("owned-marker"), b"keep")?;
    ensure!(
        workflows::clone_retained_named(
            &fixture.directory,
            CloneDestination(Some(destination.clone())),
            &Limits::default()
        )
        .is_err()
    );
    ensure!(fs::read(destination.join("owned-marker"))? == b"keep");
    Ok(())
}

#[test]
fn cached_payload_never_bypasses_missing_or_invalid_signed_transaction_graph() -> Result<()> {
    let fixture = Fixture::new("sha1")?;
    for corruption in ["missing-part", "bad-signature", "wrong-locator"] {
        let directory = fixture.copied(corruption, true)?;
        let part = directory
            .join("tx")
            .join(format!("{}.bin", fixture.graph.part));
        match corruption {
            "missing-part" => fs::remove_file(part)?,
            "bad-signature" => {
                let mut reveal: Transaction = deserialize(&fs::read(&part)?)?;
                let mut items = reveal.input[0].witness.to_vec();
                items[0][0] ^= 1;
                reveal.input[0].witness = Witness::from_slice(&items);
                ensure!(reveal.compute_txid() == fixture.graph.part);
                fs::write(part, serialize(&reveal))?;
            }
            _ => {
                let mut locator = fixture.graph.locator.clone();
                locator.genesis = "00".repeat(32);
                fs::write(
                    directory.join("locator.json"),
                    serde_json::to_vec(&locator)?,
                )?;
            }
        }
        ensure!(workflows::recover_retained(&directory, &Limits::default()).is_err());
        let destination = fixture.lab.path().join(format!("{corruption}-clone"));
        ensure!(
            workflows::clone_retained_named(
                &directory,
                CloneDestination(Some(destination.clone())),
                &Limits::default()
            )
            .is_err()
        );
        ensure!(!destination.exists());
        ensure!(fs::read(directory.join("object.bin"))? == fixture.payload);
        ensure!(
            !directory.join("snapshot.pack").exists() && !directory.join("recovery.json").exists()
        );
    }
    Ok(())
}

#[test]
fn mismatching_cache_is_refused_without_replacing_it_or_publishing_checkout() -> Result<()> {
    let fixture = Fixture::new("sha1")?;
    let directory = fixture.copied("mismatching-cache", true)?;
    let cached = directory.join("object.bin");
    fs::write(&cached, b"another payload")?;
    let error = workflows::recover_retained(&directory, &Limits::default())
        .err()
        .unwrap();
    ensure!(
        error
            .to_string()
            .contains("cached payload differs from verified transaction proofs")
    );
    let destination = fixture.lab.path().join("cache-clone");
    ensure!(
        workflows::clone_retained_named(
            &directory,
            CloneDestination(Some(destination.clone())),
            &Limits::default()
        )
        .is_err()
    );
    ensure!(fs::read(cached)? == b"another payload");
    ensure!(!destination.exists());
    ensure!(!directory.join("snapshot.pack").exists() && !directory.join("recovery.json").exists());
    fixture.assert_evidence(&directory)?;
    Ok(())
}

#[test]
fn genuine_signed_graph_still_requires_matching_git_profile_pack_and_limits() -> Result<()> {
    let fixture = Fixture::new("sha1")?;
    // The root remains genuinely authenticated; only its supported Git profile
    // disagrees with the named payload descriptor. No forged VerifiedRecord.
    let directory = fixture.copied("wrong-profile", true)?;
    let mut evidence = fixture.graph.evidence.clone();
    let mut root = fixture.graph.root.clone();
    root.profile = Descriptor::UNNAMED_PROFILE;
    let verified = signed(&MultipartRecord::Root(root), &directory, &mut evidence)?;
    let mut locator = fixture.graph.locator.clone();
    locator.root = verified.txid();
    fs::write(
        directory.join("locator.json"),
        serde_json::to_vec(&locator)?,
    )?;
    let error = workflows::recover_retained(&directory, &Limits::default())
        .err()
        .unwrap();
    ensure!(
        error
            .to_string()
            .contains("Git profile and descriptor revision disagree")
    );
    ensure!(!directory.join("recovery.json").exists());

    // Correct signatures, multipart references and final digest cannot turn
    // corrupted PACK bytes into a valid Git snapshot.
    let directory = fixture.lab.path().join("bad-pack");
    let mut payload = fixture.payload.clone();
    *payload.last_mut().unwrap() ^= 1;
    graph(&directory, &payload, Descriptor::PROFILE)?;
    let destination = fixture.lab.path().join("bad-pack-clone");
    ensure!(
        workflows::clone_retained_named(
            &directory,
            CloneDestination(Some(destination.clone())),
            &Limits::default()
        )
        .is_err()
    );
    ensure!(!destination.exists() && !directory.join("object.bin").exists());

    let directory = fixture.copied("capacity", false)?;
    let limits = Limits {
        max_pack_bytes: 8,
        ..Limits::default()
    };
    ensure!(workflows::recover_retained(&directory, &limits).is_err());
    ensure!(!directory.join("object.bin").exists());
    Ok(())
}
