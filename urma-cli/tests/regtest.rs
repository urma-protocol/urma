//! Real Bitcoin Core integration. Run with --ignored --nocapture.
use anyhow::{Context, Result, ensure};
use bitcoin::{
    Transaction,
    consensus::{deserialize, serialize},
};
use bitcoincore_rpc::{Auth, Client, RpcApi};
use serde_json::{Value, json};
use std::{
    fs,
    net::TcpListener,
    path::{Path, PathBuf},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};
use urma_chain::observation::Chain;
use urma_runtime::journal::{Plan, validate_plan};
use urma_runtime::storage;
use urma_wallet::funding::Funding;

struct Daemon {
    child: Option<Child>,
    dir: PathBuf,
    rpc_port: u16,
    p2p_port: u16,
    peer: Option<u16>,
}

impl Daemon {
    fn start(dir: PathBuf, peer: Option<u16>) -> Result<Self> {
        fs::create_dir(&dir)?;
        let rpc = TcpListener::bind("127.0.0.1:0")?;
        let p2p = TcpListener::bind("127.0.0.1:0")?;
        let mut daemon = Self {
            child: None,
            dir,
            rpc_port: rpc.local_addr()?.port(),
            p2p_port: p2p.local_addr()?.port(),
            peer,
        };
        drop((rpc, p2p));
        daemon.restart()?;
        Ok(daemon)
    }

    fn url(&self) -> String {
        format!("http://127.0.0.1:{}", self.rpc_port)
    }
    fn cookie(&self) -> PathBuf {
        self.dir.join("regtest/.cookie")
    }

    fn client(&self) -> Result<Client> {
        Ok(Client::new(&self.url(), Auth::CookieFile(self.cookie()))?)
    }

    fn call(&self, method: &str, args: &[Value]) -> Result<Value> {
        Ok(self.client()?.call(method, args)?)
    }

    fn restart(&mut self) -> Result<()> {
        let log = fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(self.dir.join("process.log"))?;
        let mut command = Command::new("bitcoind");
        command
            .args([
                "-regtest",
                "-server=1",
                "-dnsseed=0",
                "-discover=0",
                "-listenonion=0",
                "-acceptnonstdtxn=0",
                "-fallbackfee=0.00001",
                "-dbcache=32",
                "-prune=0",
                "-persistmempool=0",
                "-txindex=1",
                "-printtoconsole=0",
                "-rpcbind=127.0.0.1",
                "-rpcallowip=127.0.0.1",
            ])
            .arg(format!("-datadir={}", self.dir.display()))
            .arg(format!("-rpcport={}", self.rpc_port))
            .arg(format!("-port={}", self.p2p_port))
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log));
        if let Some(peer) = self.peer {
            command
                .args(["-disablewallet=1", "-listen=0"])
                .arg(format!("-connect=127.0.0.1:{peer}"));
        } else {
            command.args(["-listen=1", "-bind=127.0.0.1", "-connect=0"]);
        }
        self.child = Some(
            command
                .spawn()
                .context("start bitcoind; install bitcoin-daemon")?,
        );
        wait_until(|| Ok(self.call("getblockchaininfo", &[]).is_ok())).with_context(|| {
            format!(
                "start node; inspect {}",
                self.dir.join("process.log").display()
            )
        })
    }

    fn stop(&mut self) -> Result<()> {
        if let Some(mut child) = self.child.take() {
            let _ = self.call("stop", &[]);
            let deadline = Instant::now() + Duration::from_secs(15);
            while child.try_wait()?.is_none() {
                if Instant::now() >= deadline {
                    child.kill()?;
                    child.wait()?;
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }
        }
        Ok(())
    }
}

impl Drop for Daemon {
    fn drop(&mut self) {
        let _ = self.stop();
    }
}

fn wait_until(mut condition: impl FnMut() -> Result<bool>) -> Result<()> {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if condition()? {
            return Ok(());
        }
        ensure!(Instant::now() < deadline, "condition timed out");
        thread::sleep(Duration::from_millis(100));
    }
}

fn cli(workdir: &Path, args: &[&str], node: Option<(&str, &Path)>) -> Result<Output> {
    let mut command = Command::new(env!("CARGO_BIN_EXE_urma"));
    command
        .current_dir(workdir)
        .env("URMA_OUTPUT", "json")
        .env("URMA_NETWORK", "bitcoin-regtest");
    if let Some((url, auth)) = node {
        command
            .env("URMA_RPC_URL", url)
            .env("URMA_NODE_AUTH_FILE", auth);
    }
    if args.first() == Some(&"keygen") {
        command.args(["key", "recovery-generate"]).args(&args[1..]);
    } else {
        command.arg("expert").args(args);
    }
    Ok(command.output()?)
}

fn successful(output: Output) -> Result<Value> {
    ensure!(
        output.status.success(),
        "CLI failed: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}

fn sync(sender: &Daemon, receiver: &Daemon) -> Result<()> {
    let tip = sender.call("getbestblockhash", &[])?;
    // Reconnect promptly after the sender restart, without public peers.
    let _ = receiver.call(
        "addnode",
        &[
            json!(format!("127.0.0.1:{}", sender.p2p_port)),
            json!("onetry"),
        ],
    );
    wait_until(|| Ok(receiver.call("getbestblockhash", &[])? == tip))
}

fn recover(workdir: &Path, receiver: &Daemon, key: &str, dir: &str) -> Result<Output> {
    cli(
        workdir,
        &[
            "recover",
            "--key",
            key,
            "--start-height",
            "0",
            "--output-dir",
            dir,
        ],
        Some((
            &receiver.url(),
            Path::new(receiver.cookie().to_str().unwrap()),
        )),
    )
}

#[test]
#[ignore = "requires bitcoind; starts two loopback-only regtest nodes"]
fn independent_recovery_interruption_restart_and_reorg() -> Result<()> {
    let root = tempfile::Builder::new().prefix("urma-regtest-").tempdir()?;
    let workdir = root.path();
    let mut sender = Daemon::start(workdir.join("publisher"), None)?;
    let receiver = Daemon::start(workdir.join("receiver"), Some(sender.p2p_port))?;
    sender.call("createwallet", &[json!("publisher")])?;
    let wallet = Client::new(
        &format!("{}/wallet/publisher", sender.url()),
        Auth::CookieFile(sender.cookie()),
    )?;
    let mining_address: Value = wallet.call("getnewaddress", &[])?;
    sender.call("generatetoaddress", &[json!(101), mining_address])?;
    sync(&sender, &receiver)?;

    let jpeg = include_bytes!("../../tests/fixtures/sample.jpg");
    ensure!(
        jpeg.len() > urma_core::format::Urma::CHUNK_BYTES,
        "JPEG fixture must exercise multiple chunks"
    );
    storage::write_new(&workdir.join("photo.jpg"), jpeg)?;
    successful(cli(workdir, &["keygen", "--key", "photo.key"], None)?)?;
    let photo = successful(cli(
        workdir,
        &[
            "publish",
            "--wallet",
            "publisher",
            "--mine",
            "--key",
            "photo.key",
            "--input",
            "photo.jpg",
            "--journal",
            "photo.journal",
        ],
        Some((&sender.url(), Path::new(sender.cookie().to_str().unwrap()))),
    )?)?;
    ensure!(photo["status"] == "confirmed", "photo was not confirmed");

    let binary: Vec<u8> = (0..100_000).map(|i| ((i * 37) % 251) as u8).collect();
    storage::write_new(&workdir.join("interrupted.bin"), &binary)?;
    successful(cli(workdir, &["keygen", "--key", "partial.key"], None)?)?;
    successful(cli(workdir, &["keygen", "--key", "wrong.key"], None)?)?;
    let interrupted = successful(cli(
        workdir,
        &[
            "publish",
            "--wallet",
            "publisher",
            "--mine",
            "--stop-after-chunks",
            "1",
            "--key",
            "partial.key",
            "--input",
            "interrupted.bin",
            "--journal",
            "partial.journal",
        ],
        Some((&sender.url(), Path::new(sender.cookie().to_str().unwrap()))),
    )?)?;
    ensure!(
        interrupted["status"] == "interrupted",
        "fault injection did not interrupt"
    );
    sync(&sender, &receiver)?;
    let incomplete = recover(workdir, &receiver, "partial.key", "partial-output")?;
    ensure!(
        !incomplete.status.success(),
        "partial recovery falsely succeeded"
    );
    let report: Value = serde_json::from_slice(&incomplete.stdout)?;
    ensure!(
        report["objects"][0]["received"] == 1 && report["objects"][0]["expected"] == 4,
        "wrong partial chunk report"
    );
    ensure!(
        !workdir.join("partial-output").exists(),
        "incomplete plaintext was exported"
    );

    let wrong = recover(workdir, &receiver, "wrong.key", "wrong-output")?;
    ensure!(
        !wrong.status.success() && !workdir.join("wrong-output").exists(),
        "wrong key recovered data"
    );

    // Restart loses mempool and process state; the signed journal is sufficient to resume.
    sender.stop()?;
    sender.restart()?;
    sender.call("loadwallet", &[json!("publisher")])?;
    let resumed = successful(cli(
        workdir,
        &[
            "resume",
            "--wallet",
            "publisher",
            "--mine",
            "--journal",
            "partial.journal",
        ],
        Some((&sender.url(), Path::new(sender.cookie().to_str().unwrap()))),
    )?)?;
    ensure!(resumed["status"] == "confirmed", "resume failed");
    let tip_before = sender.call("getbestblockhash", &[])?;
    successful(cli(
        workdir,
        &[
            "resume",
            "--wallet",
            "publisher",
            "--mine",
            "--journal",
            "partial.journal",
        ],
        Some((&sender.url(), Path::new(sender.cookie().to_str().unwrap()))),
    )?)?;
    ensure!(
        sender.call("getbestblockhash", &[])? == tip_before,
        "idempotent resume mined another block"
    );
    sync(&sender, &receiver)?;

    // Recovery source is a separately synced node with wallets disabled.
    // Stop and move all sender state and inputs out of the recovery working directory.
    sender.stop()?;
    fs::rename(workdir.join("publisher"), workdir.join("publisher-offline"))?;
    let clean = workdir.join("clean-recovery");
    fs::create_dir(&clean)?;
    fs::rename(workdir.join("photo.key"), clean.join("photo.key"))?;
    fs::rename(workdir.join("partial.key"), clean.join("partial.key"))?;
    let recovered_photo = successful(recover(&clean, &receiver, "photo.key", "photos")?)?;
    let recovered_path = clean.join("photos").join(format!(
        "{}.bin",
        recovered_photo["objects"][0]["id"].as_str().unwrap()
    ));
    ensure!(
        fs::read(&recovered_path)? == jpeg,
        "JPEG changed during recovery"
    );
    let recovered_binary = successful(recover(&clean, &receiver, "partial.key", "binary")?)?;
    let binary_path = clean.join("binary").join(format!(
        "{}.bin",
        recovered_binary["objects"][0]["id"].as_str().unwrap()
    ));
    ensure!(
        fs::read(&binary_path)? == binary,
        "resumed file changed during recovery"
    );

    // Reorg the receiver after the publisher has disappeared: old success must not be cached.
    receiver.call("invalidateblock", std::slice::from_ref(&tip_before))?;
    let reorg = recover(&clean, &receiver, "partial.key", "after-reorg")?;
    ensure!(
        !reorg.status.success(),
        "reorg falsely reported complete recovery"
    );
    let reorg_report: Value = serde_json::from_slice(&reorg.stdout)?;
    ensure!(
        reorg_report["status"] == "partial" && reorg_report["objects"][0]["status"] == "incomplete",
        "reorg was not detected as incomplete"
    );
    receiver.call("reconsiderblock", &[tip_before])?;
    successful(recover(
        &clean,
        &receiver,
        "partial.key",
        "after-reconsider",
    )?)?;

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "bitcoin_version": receiver.call("getnetworkinfo", &[])?["subversion"],
            "jpeg_bytes": jpeg.len(), "jpeg_chunks": photo["total_chunks"],
            "jpeg_fee_sats": photo["planned_fee_sats"],
            "binary_bytes": binary.len(), "binary_fee_sats": resumed["planned_fee_sats"],
            "recovery_scanned_bytes": recovered_photo["scanned_bytes"],
            "checks": ["JPEG byte identity", "independent walletless receiver", "sender stopped",
                "partial upload fails closed", "wrong key fails closed", "journal resume after daemon restart",
                "idempotent resume", "reorg invalidates completeness", "reconsider restores recovery"]
        }))?
    );
    Ok(())
}

#[test]
#[ignore = "requires bitcoind; tests offline signing and staged publication"]
fn offline_prepare_and_staged_broadcast() -> Result<()> {
    let root = tempfile::Builder::new().prefix("urma-offline-").tempdir()?;
    let workdir = root.path();
    let online = Daemon::start(workdir.join("online"), None)?;
    let cold = Daemon::start(workdir.join("cold"), None)?;
    online.call("createwallet", &[json!("miner")])?;
    cold.call("createwallet", &[json!("cold")])?;
    let miner = Client::new(
        &format!("{}/wallet/miner", online.url()),
        Auth::CookieFile(online.cookie()),
    )?;
    let signer = Client::new(
        &format!("{}/wallet/cold", cold.url()),
        Auth::CookieFile(cold.cookie()),
    )?;
    let mining_address: Value = miner.call("getnewaddress", &[])?;
    online.call("generatetoaddress", &[json!(101), mining_address.clone()])?;
    let funding_address: Value = signer.call(
        "getnewaddress",
        &[json!("external-funding"), json!("bech32")],
    )?;
    let funding_id: Value = miner.call("sendtoaddress", &[funding_address.clone(), json!(0.01)])?;
    online.call("generatetoaddress", &[json!(1), mining_address])?;
    let previous: Value = miner.call("gettransaction", std::slice::from_ref(&funding_id))?;
    let raw_transaction = previous["hex"]
        .as_str()
        .context("funding raw tx missing")?
        .to_owned();
    let decoded: Value = online.call("decoderawtransaction", &[json!(raw_transaction)])?;
    let vout = decoded["vout"]
        .as_array()
        .context("missing outputs")?
        .iter()
        .position(|out| out["scriptPubKey"]["address"] == funding_address)
        .context("missing funding output")? as u32;
    storage::write_new(
        &workdir.join("funding.json"),
        &serde_json::to_vec(&Funding {
            raw_transaction,
            vout,
        })?,
    )?;
    storage::write_new(
        &workdir.join("sample.jpg"),
        include_bytes!("../../tests/fixtures/sample.jpg"),
    )?;
    successful(cli(workdir, &["keygen", "--key", "media.key"], None)?)?;
    let prepared = successful(cli(
        workdir,
        &[
            "prepare",
            "--wallet",
            "cold",
            "--key",
            "media.key",
            "--input",
            "sample.jpg",
            "--journal",
            "plan.json",
            "--funding",
            "funding.json",
        ],
        Some((&cold.url(), Path::new(cold.cookie().to_str().unwrap()))),
    )?)?;
    ensure!(
        prepared["status"] == "prepared" && prepared["broadcast"] == false,
        "prepare status incorrect"
    );
    ensure!(
        cold.call("getblockcount", &[])? == 0,
        "offline signer downloaded blocks"
    );
    ensure!(
        online.call("getrawmempool", &[])? == json!([]),
        "prepare broadcast a transaction"
    );
    let plan: Plan = serde_json::from_slice(&fs::read(workdir.join("plan.json"))?)?;
    validate_plan(&plan)?;
    successful(cli(workdir, &["inspect", "--journal", "plan.json"], None)?)?;

    let mismatch = cli(
        workdir,
        &[
            "prepare",
            "--network",
            "testnet4",
            "--wallet",
            "cold",
            "--key",
            "media.key",
            "--input",
            "sample.jpg",
            "--journal",
            "wrong-network.json",
            "--funding",
            "funding.json",
        ],
        Some((&cold.url(), Path::new(cold.cookie().to_str().unwrap()))),
    )?;
    ensure!(
        !mismatch.status.success() && !workdir.join("wrong-network.json").exists(),
        "network mismatch accepted"
    );

    let mut bad = plan.clone();
    bad.fee_sats += 1;
    ensure!(validate_plan(&bad).is_err(), "fee tampering accepted");
    let mut bad = plan.clone();
    bad.network = "bitcoin".into();
    ensure!(validate_plan(&bad).is_err(), "mainnet journal accepted");
    let mut bad = plan.clone();
    bad.funding.vout = u32::MAX;
    ensure!(
        validate_plan(&bad).is_err(),
        "wrong funding outpoint accepted"
    );
    let mut bad = plan.clone();
    bad.reveals[1] = bad.reveals[0].clone();
    ensure!(validate_plan(&bad).is_err(), "duplicate reveal accepted");
    let mut bad = plan.clone();
    let mut tx: Transaction = deserialize(&hex::decode(&bad.reveals[0])?)?;
    let mut witness: Vec<Vec<u8>> = tx.input[0].witness.iter().map(|v| v.to_vec()).collect();
    witness[1][150] ^= 1;
    tx.input[0].witness = bitcoin::Witness::from_slice(&witness);
    bad.reveals[0] = hex::encode(serialize(&tx));
    ensure!(
        validate_plan(&bad).is_err(),
        "changed reveal witness accepted"
    );
    let mut bad = plan.clone();
    let different_address: Value = signer.call("getnewaddress", &[])?;
    bad.mining_address = different_address.as_str().unwrap().to_owned();
    ensure!(validate_plan(&bad).is_err(), "changed payout accepted");

    // Only now sync the isolated signer to the PRIVATE lab chain, for broadcast tests.
    cold.call(
        "addnode",
        &[
            json!(format!("127.0.0.1:{}", online.p2p_port)),
            json!("onetry"),
        ],
    )?;
    sync(&online, &cold)?;
    let before = cold.call("getblockcount", &[])?;
    let first = successful(cli(
        workdir,
        &["broadcast", "--wallet", "cold", "--journal", "plan.json"],
        Some((&cold.url(), Path::new(cold.cookie().to_str().unwrap()))),
    )?)?;
    ensure!(
        first["status"] == "commit_pending",
        "first broadcast failed to stop at commit"
    );
    ensure!(
        cold.call("getblockcount", &[])? == before,
        "broadcast mined a block"
    );
    ensure!(
        cold.call("getrawmempool", &[])?.as_array().unwrap().len() == 1,
        "reveals broadcast before commit confirmation"
    );
    cold.call("generatetoaddress", &[json!(1), json!(plan.mining_address)])?;
    let second = successful(cli(
        workdir,
        &["broadcast", "--wallet", "cold", "--journal", "plan.json"],
        Some((&cold.url(), Path::new(cold.cookie().to_str().unwrap()))),
    )?)?;
    ensure!(
        second["status"] == "reveals_pending",
        "second broadcast failed to submit reveals"
    );
    ensure!(
        cold.call("getrawmempool", &[])?.as_array().unwrap().len() == plan.reveals.len(),
        "wrong reveal count"
    );
    cold.call("generatetoaddress", &[json!(1), json!(plan.mining_address)])?;
    let status = successful(cli(
        workdir,
        &["status", "--wallet", "cold", "--journal", "plan.json"],
        Some((&cold.url(), Path::new(cold.cookie().to_str().unwrap()))),
    )?)?;
    ensure!(
        status["status"] == "confirmed",
        "confirmed plan not reported confirmed"
    );
    sync(&cold, &online)?;
    let recovered = successful(recover(workdir, &online, "media.key", "recovered")?)?;
    let file = workdir.join("recovered").join(format!(
        "{}.bin",
        recovered["objects"][0]["id"].as_str().unwrap()
    ));
    ensure!(
        fs::read(file)? == include_bytes!("../../tests/fixtures/sample.jpg"),
        "offline-funded JPEG changed"
    );
    println!(
        "{}",
        json!({"offline_signer_blocks_at_prepare":0, "funding_sats":1_000_000,
        "fee_sats":plan.fee_sats, "chunks":plan.reveals.len(), "broadcast_in_prepare":false,
        "staged_broadcast":"passed", "journal_mutation_checks":"passed"})
    );
    Ok(())
}

#[test]
#[ignore = "requires bitcoind; publishes all public kinds on loopback regtest only"]
fn public_kinds_are_accepted_and_verified_on_a_separate_node() -> Result<()> {
    use bitcoin::{
        hashes::Hash,
        secp256k1::{Keypair, Secp256k1},
    };
    use urma_core::format::PublicRecord;
    let root = tempfile::Builder::new()
        .prefix("urma-public-regtest-")
        .tempdir()?;
    let sender = Daemon::start(root.path().join("publisher"), None)?;
    let receiver = Daemon::start(root.path().join("receiver"), Some(sender.p2p_port))?;
    sender.call("createwallet", &[json!("public")])?;
    let wallet = Client::new(
        &format!("{}/wallet/public", sender.url()),
        Auth::CookieFile(sender.cookie()),
    )?;
    let address: Value =
        wallet.call("getnewaddress", &[json!("public-funding"), json!("bech32")])?;
    sender.call("generatetoaddress", &[json!(101), address.clone()])?;
    let author = Keypair::from_seckey_slice(&Secp256k1::new(), &[31; 32])?;
    let mut reports = Vec::new();
    for record in [
        PublicRecord::Post("știre\0\r\n".into()),
        PublicRecord::Reply {
            target: bitcoin::Txid::from_byte_array([21; 32]),
            text: "reply".into(),
        },
        PublicRecord::Profile("pseudonim".into()),
        PublicRecord::Avatar(Box::new([0x12; 512])),
        PublicRecord::Post("x".repeat(32760)),
        PublicRecord::Post(format!("{}\u{1}", "x".repeat(512))),
        PublicRecord::ProfileRecord {
            profile: *b"URMANAM1",
            payload: b"opaque \xff\xc0".to_vec(),
        },
    ] {
        let funding_id: Value = wallet.call("sendtoaddress", &[address.clone(), json!(0.01)])?;
        sender.call("generatetoaddress", &[json!(1), address.clone()])?;
        let previous: Value = wallet.call("gettransaction", std::slice::from_ref(&funding_id))?;
        let raw = previous["hex"].as_str().context("funding hex")?;
        let funding: Transaction = deserialize(&hex::decode(raw)?)?;
        let parsed = address
            .as_str()
            .context("funding address")?
            .parse::<bitcoin::Address<_>>()?
            .assume_checked();
        let vout = u32::try_from(
            funding
                .output
                .iter()
                .position(|out| out.script_pubkey == parsed.script_pubkey())
                .context("funding output")?,
        )?;
        let plan = urma_runtime::publication::prepare(
            &record,
            &author,
            Funding {
                raw_transaction: raw.into(),
                vout,
            },
            Chain::BitcoinRegtest,
            1,
        )?;
        let signed: Value = wallet.call("signrawtransactionwithwallet", &[json!(plan.commit)])?;
        ensure!(signed["complete"] == true, "commit incomplete");
        let commit_raw = hex::decode(signed["hex"].as_str().context("signed commit")?)?;
        let commit_id = sender.call("sendrawtransaction", &[signed["hex"].clone()])?;
        sender.call("generatetoaddress", &[json!(1), address.clone()])?;
        let reveal_id = sender.call("sendrawtransaction", &[json!(plan.reveal)])?;
        let mined = sender.call("generatetoaddress", &[json!(1), address.clone()])?;
        sync(&sender, &receiver)?;
        let fetched = receiver.call("getblock", &[mined[0].clone(), json!(0)])?;
        let block: bitcoin::Block = deserialize(&hex::decode(fetched.as_str().context("block")?)?)?;
        urma_runtime::bitcoin_rpc::validate_block_for_network(
            &block,
            block.block_hash(),
            bitcoin::Network::Regtest,
        )?;
        let reveal = block
            .txdata
            .iter()
            .find(|tx| json!(tx.compute_txid().to_string()) == reveal_id)
            .context("reveal absent from independent block")?;
        let proof = urma_profiles::wire::verify_bytes(&commit_raw, &serialize(reveal))?;
        ensure!(
            proof.record() == &record && proof.author().0 == author.x_only_public_key().0,
            "public recovery mismatch"
        );
        reports.push(json!({"kind":record.kind().byte(),"record_bytes":record.encode()?.len(),"commit":commit_id,
            "reveal":reveal_id,"block":block.block_hash().to_string(),"author":proof.author().0.to_string()}));
    }
    println!(
        "{}",
        json!({"network":"regtest","public_records":reports,"independent_receiver":true,"public_network":false})
    );
    Ok(())
}

#[test]
#[ignore = "requires bitcoind; multipart consensus/policy on isolated loopback regtest"]
fn multipart_root_only_recovery_after_publisher_shutdown() -> Result<()> {
    use bitcoin::{
        Txid,
        secp256k1::{Keypair, Secp256k1},
    };
    use sha2::{Digest, Sha256};
    use std::{collections::HashMap, io::Read};
    use urma_runtime::multipart::{
        DataPart, FetchError, Geometry, LeafManifest, MultipartRecord, MultipartSource,
        RecordRequest, RecoveryLimits, RootManifest, VerifiedRecord, reconstruct,
    };
    let temp = tempfile::tempdir()?;
    let mut sender = Daemon::start(temp.path().join("sender"), None)?;
    let receiver = Daemon::start(temp.path().join("receiver"), Some(sender.p2p_port))?;
    sender.call("createwallet", &[json!("multipart")])?;
    let wallet = Client::new(
        &format!("{}/wallet/multipart", sender.url()),
        Auth::CookieFile(sender.cookie()),
    )?;
    let address: Value = wallet.call("getnewaddress", &[json!("funding"), json!("bech32")])?;
    sender.call("generatetoaddress", &[json!(101), address.clone()])?;
    let author = Keypair::from_seckey_slice(&Secp256k1::new(), &[37; 32])?;
    let mut receipts = Vec::new();
    let mut publish = |record: MultipartRecord| -> Result<VerifiedRecord> {
        let funding_id: Value = wallet.call("sendtoaddress", &[address.clone(), json!(0.01)])?;
        sender.call("generatetoaddress", &[json!(1), address.clone()])?;
        let previous: Value = wallet.call("gettransaction", &[funding_id])?;
        let raw = previous["hex"].as_str().context("funding hex")?;
        let funding: Transaction = deserialize(&hex::decode(raw)?)?;
        let parsed = address
            .as_str()
            .unwrap()
            .parse::<bitcoin::Address<_>>()?
            .assume_checked();
        let vout = u32::try_from(
            funding
                .output
                .iter()
                .position(|o| o.script_pubkey == parsed.script_pubkey())
                .context("funding output")?,
        )?;
        let plan = urma_runtime::publication::prepare_multipart(
            &record,
            &author,
            Funding {
                raw_transaction: raw.into(),
                vout,
            },
            Chain::BitcoinRegtest,
            1,
        )?;
        let signed: Value = wallet.call("signrawtransactionwithwallet", &[json!(plan.commit)])?;
        ensure!(signed["complete"] == true, "commit signature");
        let commit: Transaction = deserialize(&hex::decode(signed["hex"].as_str().unwrap())?)?;
        sender.call("sendrawtransaction", &[signed["hex"].clone()])?;
        sender.call("generatetoaddress", &[json!(1), address.clone()])?;
        let reveal: Transaction = deserialize(&hex::decode(&plan.reveal)?)?;
        sender.call("sendrawtransaction", &[json!(plan.reveal)])?;
        let blocks = sender.call("generatetoaddress", &[json!(1), address.clone()])?;
        receipts.push(json!({"kind":record.kind().byte(),"record_bytes":record.encode()?.len(),"commit":commit.compute_txid(),"reveal":reveal.compute_txid(),"block":blocks[0]}));
        Ok(VerifiedRecord::verify(
            reveal.compute_txid(),
            &reveal,
            &commit,
        )?)
    };
    let payload = vec![0xa5; Geometry::DATA_BYTES + 1];
    let mut parts = Vec::new();
    for (index, bytes) in payload.chunks(Geometry::DATA_BYTES).enumerate() {
        parts.push(
            publish(MultipartRecord::Data(DataPart {
                index: index as u32,
                payload: bytes.to_vec(),
            }))?
            .reference(),
        );
    }
    let leaf = publish(MultipartRecord::Leaf(LeafManifest {
        index: 0,
        entries: parts,
    }))?;
    let root = publish(MultipartRecord::Root(RootManifest {
        length: payload.len() as u64,
        payload_hash: Sha256::digest(&payload).into(),
        profile: *b"regtest!",
        entries: vec![leaf.reference()],
    }))?;
    sync(&sender, &receiver)?;
    sender.stop()?;
    struct Blocks(HashMap<Txid, Transaction>);
    impl MultipartSource for Blocks {
        fn fetch(&mut self, request: &RecordRequest) -> Result<VerifiedRecord, FetchError> {
            let reveal = self
                .0
                .get(&request.reference.txid)
                .ok_or(FetchError::Unavailable)?;
            let commit = self
                .0
                .get(&reveal.input[0].previous_output.txid)
                .ok_or(FetchError::Unavailable)?;
            request.verify(reveal, commit).map_err(FetchError::Rejected)
        }
    }
    let tip = receiver.call("getblockcount", &[])?.as_u64().unwrap();
    let mut source = Blocks(HashMap::new());
    for height in 0..=tip {
        let hash = receiver.call("getblockhash", &[json!(height)])?;
        let raw = receiver.call("getblock", &[hash, json!(0)])?;
        let block: bitcoin::Block = deserialize(&hex::decode(raw.as_str().unwrap())?)?;
        urma_runtime::bitcoin_rpc::validate_block_for_network(
            &block,
            block.block_hash(),
            bitcoin::Network::Regtest,
        )?;
        for tx in block.txdata {
            source.0.insert(tx.compute_txid(), tx);
        }
    }
    let reveal = &source.0[&root.txid()];
    let verified = VerifiedRecord::verify(
        root.txid(),
        reveal,
        &source.0[&reveal.input[0].previous_output.txid],
    )?;
    let mut recovered = reconstruct(
        &verified,
        &mut source,
        RecoveryLimits {
            max_payload_bytes: 1_000_000,
            max_nodes: 100,
        },
        temp.path(),
    )?;
    let mut actual = Vec::new();
    recovered.read_to_end(&mut actual)?;
    ensure!(actual == payload, "cold exact reconstruction");
    println!(
        "{}",
        json!({"network":"regtest","public_network":false,"publisher_stopped":true,"root":root.txid(),"author":root.author().to_string(),"payload_bytes":payload.len(),"sha256":hex::encode(Sha256::digest(payload)),"records":receipts,"receiver_scanned_from_genesis":true})
    );
    Ok(())
}

fn names_cli(
    workdir: &Path,
    node: &Daemon,
    vault: &Path,
    pass: &Path,
    args: &[&str],
) -> Result<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_urma"))
        .current_dir(workdir)
        .env("URMA_OUTPUT", "json")
        .env("URMA_NETWORK", "bitcoin-regtest")
        .env("URMA_RPC_URL", node.url())
        .env("URMA_NODE_AUTH_FILE", node.cookie())
        .env("URMA_VAULT", vault)
        .env("URMA_UNLOCK_FILE", pass)
        .env("URMA_CONFIG", workdir.join("absent-config"))
        .args(args)
        .output()?)
}

fn mempool(node: &Daemon) -> Result<Vec<String>> {
    Ok(node
        .call("getrawmempool", &[])?
        .as_array()
        .context("mempool")?
        .iter()
        .map(|txid| txid.as_str().unwrap_or_default().to_owned())
        .collect())
}

#[allow(clippy::too_many_arguments)]
fn publish_names_record(
    workdir: &Path,
    node: &Daemon,
    vault: &Path,
    pass: &Path,
    mining: &Value,
    record: &str,
    plan: &str,
    journal: &str,
) -> Result<(String, u64)> {
    successful(names_cli(
        workdir,
        node,
        vault,
        pass,
        &["names", "plan", "--record", record, "--output", plan],
    )?)?;
    ensure!(mempool(node)?.is_empty(), "plan broadcast something");
    let publish = [
        "names",
        "publish",
        "--plan",
        plan,
        "--journal",
        journal,
        "--yes",
    ];
    let paused = names_cli(workdir, node, vault, pass, &publish)?;
    ensure!(
        !paused.status.success(),
        "publish completed without a block"
    );
    let pool = mempool(node)?;
    ensure!(
        pool.len() == 1,
        "commit alone must wait in the mempool: {pool:?}"
    );
    let commit_txid = pool[0].clone();
    node.call("generatetoaddress", &[json!(1), mining.clone()])?;
    ensure!(
        mempool(node)?.is_empty(),
        "reveal broadcast before the commit's block"
    );
    let resume = [
        "names",
        "resume",
        "--plan",
        plan,
        "--journal",
        journal,
        "--yes",
    ];
    let paused = names_cli(workdir, node, vault, pass, &resume)?;
    ensure!(
        !paused.status.success(),
        "resume completed without the reveal's block"
    );
    let pool = mempool(node)?;
    ensure!(
        pool.len() == 1 && pool[0] != commit_txid,
        "reveal must follow the commit's block: {pool:?}"
    );
    let reveal_txid = pool[0].clone();
    node.call("generatetoaddress", &[json!(1), mining.clone()])?;
    successful(names_cli(workdir, node, vault, pass, &resume)?)?;
    let verbose = node.call("getrawtransaction", &[json!(reveal_txid), json!(true)])?;
    let header = node.call("getblockheader", &[verbose["blockhash"].clone()])?;
    let height = header["height"].as_u64().context("reveal height")?;
    Ok((reveal_txid, height))
}

#[test]
#[ignore = "requires bitcoind; names registry genesis, claim, scan and resolve on loopback regtest only"]
fn names_registry_publishes_scans_and_resolves_on_regtest() -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let root = tempfile::Builder::new()
        .prefix("urma-names-regtest-")
        .tempdir()?;
    let workdir = root.path();
    let node = Daemon::start(workdir.join("node"), None)?;
    node.call("createwallet", &[json!("miner")])?;
    let miner = Client::new(
        &format!("{}/wallet/miner", node.url()),
        Auth::CookieFile(node.cookie()),
    )?;
    let mining: Value = miner.call("getnewaddress", &[])?;
    node.call("generatetoaddress", &[json!(101), mining.clone()])?;
    let vault = workdir.join("identity.vault");
    let pass = workdir.join("password");
    let phrase = workdir.join("recovery");
    fs::write(&pass, "names regtest password")?;
    fs::set_permissions(&pass, fs::Permissions::from_mode(0o600))?;
    successful(names_cli(
        workdir,
        &node,
        &vault,
        &pass,
        &[
            "key",
            "create",
            "--vault",
            vault.to_str().context("vault path")?,
            "--password-file",
            pass.to_str().context("password path")?,
            "--recovery-out",
            phrase.to_str().context("phrase path")?,
            "--name",
            "registrar",
        ],
    )?)?;
    let identities = successful(names_cli(workdir, &node, &vault, &pass, &["key", "list"])?)?;
    let author = identities["identities"][0]["author"]
        .as_str()
        .context("author")?
        .to_owned();
    let address = successful(names_cli(
        workdir,
        &node,
        &vault,
        &pass,
        &["wallet", "address"],
    )?)?;
    let receiving = address["receive_address"].as_str().context("address")?;
    for _ in 0..4 {
        miner.call::<Value>("sendtoaddress", &[json!(receiving), json!(0.01)])?;
    }
    node.call("generatetoaddress", &[json!(1), mining.clone()])?;
    successful(names_cli(
        workdir,
        &node,
        &vault,
        &pass,
        &[
            "names",
            "encode",
            "genesis",
            "--mode",
            "open",
            "--expiry-blocks",
            "5000",
            "--reveal-max-blocks",
            "144",
            "--output",
            "genesis.record",
        ],
    )?)?;
    let (genesis, genesis_height) = publish_names_record(
        workdir,
        &node,
        &vault,
        &pass,
        &mining,
        "genesis.record",
        "genesis-plan.json",
        "genesis-progress.json",
    )?;
    let scan = |max_blocks: &str| -> Result<Value> {
        successful(names_cli(
            workdir,
            &node,
            &vault,
            &pass,
            &[
                "names",
                "scan",
                "--genesis",
                &genesis,
                "--genesis-height",
                &genesis_height.to_string(),
                "--index",
                "names-index.json",
                "--max-blocks",
                max_blocks,
            ],
        )?)
    };
    let report = scan("1000")?;
    ensure!(
        report["complete_to_tip"] == true && report["names"] == 0 && report["genesis"] == genesis,
        "initial scan: {report}"
    );
    successful(names_cli(
        workdir,
        &node,
        &vault,
        &pass,
        &[
            "names",
            "encode",
            "claim",
            "--registry",
            &genesis,
            "--name",
            "Atelier",
            "--target",
            &genesis,
            "--output",
            "claim.record",
        ],
    )?)?;
    let (claim, claim_height) = publish_names_record(
        workdir,
        &node,
        &vault,
        &pass,
        &mining,
        "claim.record",
        "claim-plan.json",
        "claim-progress.json",
    )?;
    let report = scan("1000")?;
    ensure!(
        report["complete_to_tip"] == true && report["names"] == 1,
        "claim scan: {report}"
    );
    let applied = report["records"]
        .as_array()
        .context("records")?
        .iter()
        .any(|row| {
            row["txid"] == claim && row["verdict"] == "Applied" && row["height"] == claim_height
        });
    ensure!(applied, "claim verdict: {report}");
    let resolved = successful(names_cli(
        workdir,
        &node,
        &vault,
        &pass,
        &[
            "names",
            "resolve",
            "--network",
            "bitcoin-regtest",
            "--index",
            "names-index.json",
            "ATELIER",
        ],
    )?)?;
    let bound = &resolved["resolution"]["Bound"];
    ensure!(
        resolved["name"] == "atelier"
            && bound["owner"] == author
            && bound["target"]["Publication"] == genesis
            && bound["claim_txid"] == claim
            && bound["expiry"] == claim_height + 5000
            && resolved["height"] == report["height"],
        "resolution: {resolved}"
    );
    let pending = successful(names_cli(
        workdir,
        &node,
        &vault,
        &pass,
        &[
            "names",
            "pending",
            "--network",
            "bitcoin-regtest",
            "--index",
            "names-index.json",
        ],
    )?)?;
    ensure!(
        pending["pending"].as_array().context("pending")?.is_empty(),
        "pending: {pending}"
    );
    let again = scan("1000")?;
    ensure!(
        again["scanned"] == 0 && again["rolled_back"] == 0,
        "idempotent scan: {again}"
    );
    println!(
        "{}",
        json!({"network":"regtest","genesis":genesis,"genesis_height":genesis_height,"claim":claim,"claim_height":claim_height,"owner":author,"public_network":false})
    );
    Ok(())
}

struct Identity {
    node: Daemon,
    mining: Value,
    vault: PathBuf,
    pass: PathBuf,
    author: String,
}

impl Identity {
    fn cli(&self, workdir: &Path, args: &[&str]) -> Result<Output> {
        names_cli(workdir, &self.node, &self.vault, &self.pass, args)
    }

    fn mine(&self, blocks: u64) -> Result<()> {
        self.node
            .call("generatetoaddress", &[json!(blocks), self.mining.clone()])?;
        Ok(())
    }
}

fn regtest_identity(workdir: &Path, funding_outputs: u32) -> Result<Identity> {
    use std::os::unix::fs::PermissionsExt;
    let node = Daemon::start(workdir.join("node"), None)?;
    node.call("createwallet", &[json!("miner")])?;
    let miner = Client::new(
        &format!("{}/wallet/miner", node.url()),
        Auth::CookieFile(node.cookie()),
    )?;
    let mining: Value = miner.call("getnewaddress", &[])?;
    node.call("generatetoaddress", &[json!(101), mining.clone()])?;
    let vault = workdir.join("identity.vault");
    let pass = workdir.join("password");
    let phrase = workdir.join("recovery");
    fs::write(&pass, "regtest identity password")?;
    fs::set_permissions(&pass, fs::Permissions::from_mode(0o600))?;
    successful(names_cli(
        workdir,
        &node,
        &vault,
        &pass,
        &[
            "key",
            "create",
            "--vault",
            vault.to_str().context("vault path")?,
            "--password-file",
            pass.to_str().context("password path")?,
            "--recovery-out",
            phrase.to_str().context("phrase path")?,
            "--name",
            "publisher",
        ],
    )?)?;
    let identities = successful(names_cli(workdir, &node, &vault, &pass, &["key", "list"])?)?;
    let author = identities["identities"][0]["author"]
        .as_str()
        .context("author")?
        .to_owned();
    let address = successful(names_cli(
        workdir,
        &node,
        &vault,
        &pass,
        &["wallet", "address"],
    )?)?;
    let receiving = address["receive_address"].as_str().context("address")?;
    for _ in 0..funding_outputs {
        miner.call::<Value>("sendtoaddress", &[json!(receiving), json!(0.05)])?;
    }
    node.call("generatetoaddress", &[json!(1), mining.clone()])?;
    Ok(Identity {
        node,
        mining,
        vault,
        pass,
        author,
    })
}

fn publish_until_complete(
    identity: &Identity,
    workdir: &Path,
    group: &str,
    plan: &str,
    journal: &str,
) -> Result<()> {
    let mut output = identity.cli(
        workdir,
        &[
            group,
            "publish",
            "--plan",
            plan,
            "--journal",
            journal,
            "--yes",
        ],
    )?;
    for _round in 0..16 {
        if output.status.success() {
            return Ok(());
        }
        identity.mine(1)?;
        output = identity.cli(
            workdir,
            &[
                group,
                "resume",
                "--plan",
                plan,
                "--journal",
                journal,
                "--yes",
            ],
        )?;
    }
    ensure!(
        output.status.success(),
        "publication did not complete: {}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

fn get_resource(
    identity: &Identity,
    workdir: &Path,
    root: &str,
    path: &str,
    output: &str,
) -> Result<Output> {
    identity.cli(
        workdir,
        &[
            "web",
            "get",
            "--store",
            "web-store",
            "--network",
            "bitcoin-regtest",
            "--root",
            root,
            "--path",
            path,
            "--output",
            output,
        ],
    )
}

#[test]
#[ignore = "requires bitcoind; web package publication, verified store, pinned object and naming on loopback regtest only"]
fn web_publications_are_fetched_into_the_store_pinned_and_named_on_regtest() -> Result<()> {
    let root = tempfile::Builder::new()
        .prefix("urma-web-regtest-")
        .tempdir()?;
    let workdir = root.path();
    let id = regtest_identity(workdir, 12)?;
    let site = workdir.join("site");
    fs::create_dir_all(site.join("sub"))?;
    let index = b"<!doctype html><meta charset=utf-8><title>demo</title><link rel=stylesheet href=style.css><script src=app.js></script><p>salut</p>";
    fs::write(site.join("index.html"), index)?;
    fs::write(site.join("style.css"), "body{margin:0}")?;
    fs::write(site.join("app.js"), "document.title='ok'")?;
    fs::write(site.join("sub/page.html"), "<p>sub</p>")?;
    let packed = successful(id.cli(
        workdir,
        &[
            "web",
            "pack",
            "--dir",
            "site",
            "--entry",
            "index.html",
            "--label",
            "demo site",
            "--output",
            "site.package",
        ],
    )?)?;
    ensure!(
        packed["files"].as_array().context("files")?.len() == 4,
        "{packed}"
    );
    let inspected = successful(id.cli(workdir, &["web", "inspect", "--package", "site.package"])?)?;
    ensure!(
        inspected["status"] == "valid" && inspected["payload_sha256"] == packed["payload_sha256"],
        "{inspected}"
    );
    let planned = successful(id.cli(
        workdir,
        &[
            "web",
            "plan",
            "--package",
            "site.package",
            "--max-fee",
            "100000",
            "--output",
            "web-plan",
        ],
    )?)?;
    let root1 = planned["root_txid"].as_str().context("root")?.to_owned();
    ensure!(
        planned["records"] == 3 && planned["broadcast"] == false,
        "{planned}"
    );
    ensure!(mempool(&id.node)?.is_empty(), "plan broadcast something");
    publish_until_complete(&id, workdir, "web", "web-plan", "web-progress.json")?;
    let journal: Value =
        serde_json::from_slice(&std::fs::read(workdir.join("web-progress.json"))?)?;
    let mut heights = Vec::new();
    for transaction in journal["transactions"].as_array().context("transactions")? {
        heights.push(transaction["presence"]["height"].as_u64().context("height")?);
    }
    let first = *heights.iter().min().context("min")?;
    let last = *heights.iter().max().context("max")?;
    ensure!(
        heights.len() == 6 && last - first == 1,
        "buffered path must publish three records in two blocks: {heights:?}"
    );
    let fetched = successful(id.cli(
        workdir,
        &["web", "fetch", "--root", &root1, "--store", "web-store"],
    )?)?;
    let publication = &fetched["publication"];
    ensure!(
        publication["files"].as_array().context("files")?.len() == 4,
        "files: {fetched}"
    );
    ensure!(
        publication["pinned"]
            .as_array()
            .context("pinned")?
            .is_empty(),
        "pinned: {fetched}"
    );
    ensure!(publication["author"] == id.author, "author: {fetched}");
    ensure!(
        publication["network"] == "bitcoin-regtest",
        "network: {fetched}"
    );
    ensure!(
        publication["payload_sha256"] == packed["payload_sha256"],
        "payload: {fetched}"
    );
    let got = successful(get_resource(&id, workdir, &root1, "/", "index.out")?)?;
    ensure!(
        got["mime"] == "text/html" && fs::read(workdir.join("index.out"))? == index,
        "{got}"
    );
    successful(get_resource(
        &id,
        workdir,
        &root1,
        "/sub/page.html",
        "page.out",
    )?)?;
    ensure!(fs::read(workdir.join("page.out"))? == b"<p>sub</p>");
    ensure!(
        !get_resource(&id, workdir, &root1, "/missing", "missing.out")?
            .status
            .success()
    );
    ensure!(
        !get_resource(&id, workdir, &root1, "/sub/", "sub.out")?
            .status
            .success()
    );
    ensure!(!workdir.join("missing.out").exists() && !workdir.join("sub.out").exists());
    let payload_sha = packed["payload_sha256"]
        .as_str()
        .context("payload sha")?
        .to_owned();
    let site2 = workdir.join("site2");
    fs::create_dir_all(&site2)?;
    fs::write(
        site2.join("index.html"),
        "<!doctype html><a download href=downloads/site1.bin>site1</a>",
    )?;
    let pin = format!("downloads/site1.bin:application/octet-stream:{root1}:{payload_sha}");
    let packed2 = successful(id.cli(
        workdir,
        &[
            "web",
            "pack",
            "--dir",
            "site2",
            "--label",
            "pinned",
            "--pin",
            &pin,
            "--output",
            "site2.package",
        ],
    )?)?;
    ensure!(
        packed2["pinned"].as_array().context("pinned")?.len() == 1,
        "{packed2}"
    );
    let planned2 = successful(id.cli(
        workdir,
        &[
            "web",
            "plan",
            "--package",
            "site2.package",
            "--max-fee",
            "100000",
            "--output",
            "web2-plan",
        ],
    )?)?;
    let root2 = planned2["root_txid"].as_str().context("root2")?.to_owned();
    publish_until_complete(&id, workdir, "web", "web2-plan", "web2-progress.json")?;
    let fetched2 = successful(id.cli(
        workdir,
        &["web", "fetch", "--root", &root2, "--store", "web-store"],
    )?)?;
    ensure!(
        fetched2["publication"]["pinned"]
            .as_array()
            .context("pinned")?
            .len()
            == 1
            && fetched2["publication"]["files"]
                .as_array()
                .context("files")?
                .len()
                == 1,
        "{fetched2}"
    );
    let pinned_get = successful(get_resource(
        &id,
        workdir,
        &root2,
        "/downloads/site1.bin",
        "site1.out",
    )?)?;
    ensure!(
        pinned_get["mime"] == "application/octet-stream"
            && fs::read(workdir.join("site1.out"))? == fs::read(workdir.join("site.package"))?,
        "{pinned_get}"
    );
    let manifest = successful(id.cli(
        workdir,
        &[
            "web",
            "manifest",
            "--store",
            "web-store",
            "--network",
            "bitcoin-regtest",
            "--root",
            &root2,
        ],
    )?)?;
    ensure!(
        manifest["author"] == id.author
            && manifest["pinned"][0]["root_txid"] == root1
            && manifest["entry"] == "index.html",
        "{manifest}"
    );
    let store_objects = workdir.join("web-store").join("objects");
    let payload_sha = fetched2["publication"]["payload_sha256"]
        .as_str()
        .context("payload")?
        .to_owned();
    let original = fs::read(store_objects.join(&payload_sha))?;
    fs::write(
        store_objects.join(&payload_sha),
        b"<!doctype html><p>forged</p>",
    )?;
    ensure!(
        !get_resource(&id, workdir, &root2, "/", "forged.out")?
            .status
            .success(),
        "forged package served"
    );
    fs::write(store_objects.join(&payload_sha), &original)?;
    let pin_sha = fetched2["publication"]["pinned"][0]["sha256"]
        .as_str()
        .context("pin sha")?
        .to_owned();
    fs::remove_file(store_objects.join(&pin_sha))?;
    let missing_pin = get_resource(&id, workdir, &root2, "/", "incomplete.out")?;
    ensure!(
        !missing_pin.status.success(),
        "publication served with a missing pinned object"
    );
    ensure!(
        String::from_utf8_lossy(&missing_pin.stderr).contains("declared set incomplete"),
        "{}",
        String::from_utf8_lossy(&missing_pin.stderr)
    );
    successful(id.cli(
        workdir,
        &["web", "fetch", "--root", &root2, "--store", "web-store"],
    )?)?;
    successful(get_resource(&id, workdir, &root2, "/", "restored.out")?)?;
    let bad_pin = format!(
        "downloads/site1.bin:application/octet-stream:{root1}:{}",
        "00".repeat(32)
    );
    successful(id.cli(
        workdir,
        &[
            "web",
            "pack",
            "--dir",
            "site2",
            "--label",
            "bad pin",
            "--pin",
            &bad_pin,
            "--output",
            "site3.package",
        ],
    )?)?;
    let planned3 = successful(id.cli(
        workdir,
        &[
            "web",
            "plan",
            "--package",
            "site3.package",
            "--max-fee",
            "100000",
            "--output",
            "web3-plan",
        ],
    )?)?;
    let root3 = planned3["root_txid"].as_str().context("root3")?.to_owned();
    publish_until_complete(&id, workdir, "web", "web3-plan", "web3-progress.json")?;
    let rejected = id.cli(
        workdir,
        &["web", "fetch", "--root", &root3, "--store", "web-store"],
    )?;
    ensure!(!rejected.status.success(), "a wrong pin was stored");
    ensure!(
        !id.cli(
            workdir,
            &[
                "web",
                "manifest",
                "--store",
                "web-store",
                "--network",
                "bitcoin-regtest",
                "--root",
                &root3
            ],
        )?
        .status
        .success()
    );
    successful(id.cli(
        workdir,
        &[
            "names",
            "encode",
            "genesis",
            "--mode",
            "open",
            "--expiry-blocks",
            "5000",
            "--reveal-max-blocks",
            "144",
            "--output",
            "genesis.record",
        ],
    )?)?;
    let (genesis, genesis_height) = publish_names_record(
        workdir,
        &id.node,
        &id.vault,
        &id.pass,
        &id.mining,
        "genesis.record",
        "genesis-plan.json",
        "genesis-progress.json",
    )?;
    successful(id.cli(
        workdir,
        &[
            "names",
            "encode",
            "claim",
            "--registry",
            &genesis,
            "--name",
            "atelier",
            "--target",
            &root2,
            "--output",
            "claim.record",
        ],
    )?)?;
    let (claim, _claim_height) = publish_names_record(
        workdir,
        &id.node,
        &id.vault,
        &id.pass,
        &id.mining,
        "claim.record",
        "claim-plan.json",
        "claim-progress.json",
    )?;
    successful(id.cli(
        workdir,
        &[
            "names",
            "scan",
            "--genesis",
            &genesis,
            "--genesis-height",
            &genesis_height.to_string(),
            "--index",
            "names-index.json",
        ],
    )?)?;
    let resolved = successful(id.cli(
        workdir,
        &[
            "names",
            "resolve",
            "--network",
            "bitcoin-regtest",
            "--index",
            "names-index.json",
            "atelier",
        ],
    )?)?;
    ensure!(
        resolved["resolution"]["Bound"]["target"]["Publication"] == root2
            && resolved["resolution"]["Bound"]["claim_txid"] == claim,
        "{resolved}"
    );
    println!(
        "{}",
        json!({"network":"regtest","site":root1,"pinned_site":root2,"rejected_pin_site":root3,"genesis":genesis,"claim":claim,"author":id.author,"public_network":false})
    );
    Ok(())
}

struct Signer {
    vault: PathBuf,
    pass: PathBuf,
    author: String,
}

fn extra_identity(
    workdir: &Path,
    node: &Daemon,
    miner: &Client,
    mining: &Value,
    label: &str,
    outputs: u32,
) -> Result<Signer> {
    use std::os::unix::fs::PermissionsExt;
    let vault = workdir.join(format!("{label}.vault"));
    let pass = workdir.join(format!("{label}.password"));
    let phrase = workdir.join(format!("{label}.recovery"));
    fs::write(&pass, format!("{label} regtest password"))?;
    fs::set_permissions(&pass, fs::Permissions::from_mode(0o600))?;
    successful(names_cli(
        workdir,
        node,
        &vault,
        &pass,
        &[
            "key",
            "create",
            "--vault",
            vault.to_str().context("vault path")?,
            "--password-file",
            pass.to_str().context("password path")?,
            "--recovery-out",
            phrase.to_str().context("phrase path")?,
            "--name",
            label,
        ],
    )?)?;
    let identities = successful(names_cli(workdir, node, &vault, &pass, &["key", "list"])?)?;
    let author = identities["identities"][0]["author"]
        .as_str()
        .context("author")?
        .to_owned();
    let address = successful(names_cli(
        workdir,
        node,
        &vault,
        &pass,
        &["wallet", "address"],
    )?)?;
    let receiving = address["receive_address"].as_str().context("address")?;
    for _ in 0..outputs {
        miner.call::<Value>("sendtoaddress", &[json!(receiving), json!(0.01)])?;
    }
    node.call("generatetoaddress", &[json!(1), mining.clone()])?;
    Ok(Signer {
        vault,
        pass,
        author,
    })
}

fn publish_site(owner: &Identity, workdir: &Path, tag: &str, body: &str) -> Result<String> {
    let dir = workdir.join(tag);
    fs::create_dir_all(&dir)?;
    fs::write(dir.join("index.html"), body)?;
    let package = format!("{tag}.package");
    let plan = format!("{tag}-plan");
    successful(owner.cli(
        workdir,
        &[
            "web",
            "pack",
            "--dir",
            tag,
            "--entry",
            "index.html",
            "--label",
            tag,
            "--output",
            &package,
        ],
    )?)?;
    let planned = successful(owner.cli(
        workdir,
        &[
            "web",
            "plan",
            "--package",
            &package,
            "--max-fee",
            "100000",
            "--output",
            &plan,
        ],
    )?)?;
    let root = planned["root_txid"].as_str().context("root")?.to_owned();
    publish_until_complete(owner, workdir, "web", &plan, &format!("{tag}-progress.json"))?;
    Ok(root)
}

fn verdict_of(report: &Value, txid: &str) -> Result<Value> {
    report["records"]
        .as_array()
        .context("records")?
        .iter()
        .find(|row| row["txid"] == txid)
        .map(|row| row["verdict"].clone())
        .context("record missing from the scan report")
}

#[test]
#[ignore = "requires bitcoind; administered names registry with approvals, update, renew, suspend, restore and expiry on loopback regtest only"]
fn administered_registry_approves_updates_renews_suspends_restores_and_expires_on_regtest()
-> Result<()> {
    let root = tempfile::Builder::new()
        .prefix("urma-names-administered-")
        .tempdir()?;
    let workdir = root.path();
    let owner = regtest_identity(workdir, 16)?;
    let node = &owner.node;
    let mining = owner.mining.clone();
    let miner = Client::new(
        &format!("{}/wallet/miner", node.url()),
        Auth::CookieFile(node.cookie()),
    )?;
    let one = extra_identity(workdir, node, &miner, &mining, "approver-one", 10)?;
    let two = extra_identity(workdir, node, &miner, &mining, "approver-two", 8)?;
    let three = extra_identity(workdir, node, &miner, &mining, "approver-three", 6)?;
    let owner_signer = Signer {
        vault: owner.vault.clone(),
        pass: owner.pass.clone(),
        author: owner.author.clone(),
    };
    let encode = |signer: &Signer, args: &[&str]| -> Result<()> {
        let mut full = vec!["names", "encode"];
        full.extend_from_slice(args);
        successful(names_cli(workdir, node, &signer.vault, &signer.pass, &full)?)?;
        Ok(())
    };
    let publish = |signer: &Signer, record: &str, tag: &str| -> Result<(String, u64)> {
        publish_names_record(
            workdir,
            node,
            &signer.vault,
            &signer.pass,
            &mining,
            record,
            &format!("{tag}-plan.json"),
            &format!("{tag}-progress.json"),
        )
    };
    let site_one = publish_site(&owner, workdir, "site-one", "<!doctype html><p>one</p>")?;
    let site_two = publish_site(&owner, workdir, "site-two", "<!doctype html><p>two</p>")?;
    encode(
        &owner_signer,
        &[
            "genesis",
            "--mode",
            "administered",
            "--expiry-blocks",
            "60",
            "--reveal-max-blocks",
            "20",
            "--threshold",
            "2",
            "--approver",
            &one.author,
            "--approver",
            &two.author,
            "--approver",
            &three.author,
            "--output",
            "genesis.record",
        ],
    )?;
    let (genesis, genesis_height) = publish(&owner_signer, "genesis.record", "genesis")?;
    let scan = || -> Result<Value> {
        successful(names_cli(
            workdir,
            node,
            &owner.vault,
            &owner.pass,
            &[
                "names",
                "scan",
                "--genesis",
                &genesis,
                "--genesis-height",
                &genesis_height.to_string(),
                "--index",
                "names-index.json",
                "--max-blocks",
                "1000",
            ],
        )?)
    };
    let resolve = || -> Result<Value> {
        Ok(successful(names_cli(
            workdir,
            node,
            &owner.vault,
            &owner.pass,
            &[
                "names",
                "resolve",
                "--network",
                "bitcoin-regtest",
                "--index",
                "names-index.json",
                "atelier",
            ],
        )?)?["resolution"]
            .clone())
    };
    let open_pending = || -> Result<Vec<Value>> {
        let pending = successful(names_cli(
            workdir,
            node,
            &owner.vault,
            &owner.pass,
            &[
                "names",
                "pending",
                "--network",
                "bitcoin-regtest",
                "--index",
                "names-index.json",
            ],
        )?)?;
        Ok(pending["pending"]
            .as_array()
            .context("pending")?
            .iter()
            .filter(|row| row["record"]["completed"] == false)
            .cloned()
            .collect())
    };
    let report = scan()?;
    ensure!(
        report["complete_to_tip"] == true && report["names"] == 0,
        "genesis scan: {report}"
    );
    encode(
        &owner_signer,
        &[
            "claim",
            "--registry",
            &genesis,
            "--name",
            "Atelier",
            "--target",
            &site_one,
            "--output",
            "request.record",
        ],
    )?;
    let (request, _) = publish(&owner_signer, "request.record", "request")?;
    let report = scan()?;
    ensure!(verdict_of(&report, &request)? == "Pending", "{report}");
    let pending = open_pending()?;
    ensure!(
        pending.len() == 1
            && pending[0]["txid"] == request
            && pending[0]["record"]["kind"] == "Request"
            && pending[0]["record"]["approvals"].as_array().context("approvals")?.is_empty(),
        "pending before approvals: {pending:?}"
    );
    ensure!(resolve()? == "Unbound", "request alone must not bind");
    let approve = |signer: &Signer, record_txid: &str, record: &str, tag: &str| -> Result<String> {
        let output = format!("{tag}.record");
        encode(
            signer,
            &[
                "approve",
                "--registry",
                &genesis,
                "--record-txid",
                record_txid,
                "--record",
                record,
                "--output",
                &output,
            ],
        )?;
        Ok(publish(signer, &output, tag)?.0)
    };
    let first = approve(&one, &request, "request.record", "approve-one")?;
    let report = scan()?;
    ensure!(verdict_of(&report, &first)? == "Applied", "{report}");
    ensure!(resolve()? == "Unbound", "one approval of two must not bind");
    let pending = open_pending()?;
    ensure!(
        pending.len() == 1 && pending[0]["record"]["approvals"] == json!([one.author]),
        "pending after one approval: {pending:?}"
    );
    let repeated = approve(&one, &request, "request.record", "approve-one-again")?;
    let report = scan()?;
    ensure!(
        verdict_of(&report, &repeated)? == json!({"Inert": "Repeated"}),
        "{report}"
    );
    let outsider = approve(&owner_signer, &request, "request.record", "approve-owner")?;
    let report = scan()?;
    ensure!(
        verdict_of(&report, &outsider)? == json!({"Invalid": "NotApprover"}),
        "{report}"
    );
    ensure!(resolve()? == "Unbound", "repeated and foreign approvals must not bind");
    let second = approve(&two, &request, "request.record", "approve-two")?;
    let report = scan()?;
    ensure!(verdict_of(&report, &second)? == "Applied", "{report}");
    let second_height = report["height"].as_u64().context("height")?;
    let bound = resolve()?;
    ensure!(
        bound["Bound"]["owner"] == owner.author
            && bound["Bound"]["target"]["Publication"] == site_one
            && bound["Bound"]["claim_txid"] == request
            && bound["Bound"]["expiry"] == second_height + 60,
        "activation at the threshold: {bound}"
    );
    ensure!(open_pending()?.is_empty(), "completed request still pending");
    let late = approve(&three, &request, "request.record", "approve-three-late")?;
    let report = scan()?;
    ensure!(
        verdict_of(&report, &late)? == json!({"Inert": "Completed"}),
        "{report}"
    );
    encode(
        &owner_signer,
        &[
            "update",
            "--registry",
            &genesis,
            "--name",
            "atelier",
            "--target",
            &site_two,
            "--output",
            "update.record",
        ],
    )?;
    let (update, _) = publish(&owner_signer, "update.record", "update")?;
    let report = scan()?;
    ensure!(verdict_of(&report, &update)? == "Pending", "{report}");
    ensure!(
        resolve()?["Bound"]["target"]["Publication"] == site_one,
        "pending update must not change the served target"
    );
    let pending = open_pending()?;
    ensure!(
        pending.len() == 1 && pending[0]["record"]["kind"] == "Update",
        "pending update: {pending:?}"
    );
    approve(&one, &update, "update.record", "approve-update-one")?;
    scan()?;
    ensure!(
        resolve()?["Bound"]["target"]["Publication"] == site_one,
        "one approval of two must not move the target"
    );
    let completing = approve(&two, &update, "update.record", "approve-update-two")?;
    scan()?;
    let bound = resolve()?;
    ensure!(
        bound["Bound"]["target"]["Publication"] == site_two
            && bound["Bound"]["last_txid"] == completing
            && bound["Bound"]["expiry"] == second_height + 60,
        "update completion: {bound}"
    );
    encode(
        &owner_signer,
        &[
            "renew",
            "--registry",
            &genesis,
            "--name",
            "atelier",
            "--target",
            &site_one,
            "--output",
            "renew-wrong.record",
        ],
    )?;
    let (wrong, _) = publish(&owner_signer, "renew-wrong.record", "renew-wrong")?;
    let report = scan()?;
    ensure!(
        verdict_of(&report, &wrong)? == json!({"Invalid": "TargetChanged"}),
        "{report}"
    );
    encode(
        &owner_signer,
        &[
            "renew",
            "--registry",
            &genesis,
            "--name",
            "atelier",
            "--target",
            &site_two,
            "--output",
            "renew.record",
        ],
    )?;
    let (renew, renew_height) = publish(&owner_signer, "renew.record", "renew")?;
    let report = scan()?;
    ensure!(verdict_of(&report, &renew)? == "Applied", "{report}");
    ensure!(
        resolve()?["Bound"]["expiry"] == renew_height + 60,
        "renewal must restart the term at the renewal block"
    );
    let name_op = |signer: &Signer, op: &str, tag: &str| -> Result<String> {
        let output = format!("{tag}.record");
        encode(
            signer,
            &[op, "--registry", &genesis, "--name", "atelier", "--output", &output],
        )?;
        Ok(publish(signer, &output, tag)?.0)
    };
    let suspend_one = name_op(&one, "suspend", "suspend-one")?;
    let report = scan()?;
    ensure!(verdict_of(&report, &suspend_one)? == "Applied", "{report}");
    ensure!(
        resolve()?["Bound"]["target"]["Publication"] == site_two,
        "one suspend vote of two must keep serving"
    );
    let suspend_owner = name_op(&owner_signer, "suspend", "suspend-owner")?;
    let report = scan()?;
    ensure!(
        verdict_of(&report, &suspend_owner)? == json!({"Invalid": "NotApprover"}),
        "{report}"
    );
    name_op(&two, "suspend", "suspend-two")?;
    scan()?;
    ensure!(resolve()? == "Suspended", "two suspend votes must suspend");
    let suspend_three = name_op(&three, "suspend", "suspend-three")?;
    let report = scan()?;
    ensure!(
        verdict_of(&report, &suspend_three)? == json!({"Inert": "WrongPhase"}),
        "{report}"
    );
    encode(
        &owner_signer,
        &[
            "renew",
            "--registry",
            &genesis,
            "--name",
            "atelier",
            "--target",
            &site_two,
            "--output",
            "renew-suspended.record",
        ],
    )?;
    let (renew_suspended, renew_suspended_height) =
        publish(&owner_signer, "renew-suspended.record", "renew-suspended")?;
    let report = scan()?;
    ensure!(
        verdict_of(&report, &renew_suspended)? == "Applied",
        "{report}"
    );
    ensure!(resolve()? == "Suspended", "renewal must not lift a suspension");
    name_op(&one, "restore", "restore-one")?;
    scan()?;
    ensure!(resolve()? == "Suspended", "one restore vote of two must not restore");
    let restore_again = name_op(&one, "restore", "restore-one-again")?;
    let report = scan()?;
    ensure!(
        verdict_of(&report, &restore_again)? == json!({"Inert": "Repeated"}),
        "{report}"
    );
    name_op(&two, "restore", "restore-two")?;
    scan()?;
    let bound = resolve()?;
    ensure!(
        bound["Bound"]["target"]["Publication"] == site_two
            && bound["Bound"]["expiry"] == renew_suspended_height + 60,
        "restore must serve the target renewed while suspended: {bound}"
    );
    let expiry = bound["Bound"]["expiry"].as_u64().context("expiry")?;
    let tip = node.call("getblockcount", &[])?.as_u64().context("tip")?;
    ensure!(tip < expiry, "term already over before the expiry check");
    node.call("generatetoaddress", &[json!(expiry - tip), mining.clone()])?;
    let report = scan()?;
    ensure!(report["height"] == expiry, "scan to the expiry block: {report}");
    ensure!(resolve()? == "Unbound", "name must be unbound at its expiry height");
    encode(
        &three,
        &[
            "claim",
            "--registry",
            &genesis,
            "--name",
            "atelier",
            "--target",
            &site_one,
            "--output",
            "reclaim.record",
        ],
    )?;
    let (reclaim, _) = publish(&three, "reclaim.record", "reclaim")?;
    approve(&one, &reclaim, "reclaim.record", "approve-reclaim-one")?;
    approve(&two, &reclaim, "reclaim.record", "approve-reclaim-two")?;
    scan()?;
    let bound = resolve()?;
    ensure!(
        bound["Bound"]["owner"] == three.author
            && bound["Bound"]["target"]["Publication"] == site_one
            && bound["Bound"]["claim_txid"] == reclaim,
        "reclaim after expiry: {bound}"
    );
    let again = scan()?;
    ensure!(
        again["scanned"] == 0 && again["rolled_back"] == 0,
        "idempotent scan: {again}"
    );
    println!(
        "{}",
        json!({"network":"regtest","genesis":genesis,"genesis_height":genesis_height,"request":request,"update":update,"renew":renew,"reclaim":reclaim,"owner":owner.author,"approvers":[one.author,two.author,three.author],"public_network":false})
    );
    Ok(())
}
