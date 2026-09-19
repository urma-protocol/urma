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
use urma::storage;
use urma::transport::{Funding, Plan, validate_plan};

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

    let jpeg = include_bytes!("../../../tests/fixtures/sample.jpg");
    ensure!(
        jpeg.len() > urma::format::Urma::CHUNK_BYTES,
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
        include_bytes!("../../../tests/fixtures/sample.jpg"),
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
        fs::read(file)? == include_bytes!("../../../tests/fixtures/sample.jpg"),
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
    use urma::{
        format::PublicRecord,
        publication::{self, Chain},
    };
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
        let plan = publication::prepare(
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
        urma::transport::validate_block_for_network(
            &block,
            block.block_hash(),
            bitcoin::Network::Regtest,
        )?;
        let reveal = block
            .txdata
            .iter()
            .find(|tx| json!(tx.compute_txid().to_string()) == reveal_id)
            .context("reveal absent from independent block")?;
        let (found, proof) = publication::verify(&commit_raw, &serialize(reveal))?;
        ensure!(
            found == record && proof.author == author.x_only_public_key().0,
            "public recovery mismatch"
        );
        reports.push(json!({"kind":record.kind().byte(),"record_bytes":record.encode()?.len(),"commit":commit_id,
            "reveal":reveal_id,"block":block.block_hash().to_string(),"author":proof.author.to_string()}));
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
    use urma::{
        multipart::{
            DataPart, FetchError, Geometry, LeafManifest, MultipartRecord, MultipartSource,
            RecordRequest, RecoveryLimits, RootManifest, VerifiedRecord, reconstruct,
        },
        publication::{self, Chain},
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
        let plan = publication::prepare_multipart(
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
        urma::transport::validate_block_for_network(
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
