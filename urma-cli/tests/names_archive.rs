//! CLI consumer compatibility against explicitly trusted local operator DTOs.
//! These fixtures test projection/transport behavior, not signatures or inclusion.
#![cfg(unix)]
use bitcoin::{Txid, XOnlyPublicKey};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    fs::{self, File},
    io::{Read, Write},
    net::{SocketAddr, TcpListener},
    os::unix::fs::PermissionsExt,
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};
use urma_chain::observation::Chain;
use urma_names::{
    engine::Registry,
    index::{Checkpoint, NamesIndex},
    name::Name,
    payload::{Genesis, Mode},
    state::{Binding, Bound, NameState, PendingKind, PendingRecord, Target},
};
use urma_node_client::{
    model::ChainPoint,
    names::{NamesCursor, NamesEntry, NamesPage, NamesStatus},
    projection::IndexSnapshot,
};

const TOKEN: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const NETWORK: &str = "bitcoin-regtest";
fn id(n: u8) -> Txid {
    format!("{n:02x}").repeat(32).parse().unwrap()
}

struct Fixture {
    temp: tempfile::TempDir,
    index: NamesIndex,
    entries: Vec<NamesEntry>,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let author: XOnlyPublicKey =
            "986514fb8d4da75550980a77764dfd1dcadf76ca374192560e0b690183fcf251"
                .parse()
                .unwrap();
        let rules = Genesis {
            mode: Mode::Administered,
            expiry_blocks: 1000,
            reveal_max_blocks: 144,
            threshold: 1,
            approvers: vec![author],
        };
        let mut names = BTreeMap::new();
        names.insert(Name::parse("alpha").unwrap(), NameState::unbound());
        for (name, suspended) in [("atelier", false), ("beta", true)] {
            names.insert(
                Name::parse(name).unwrap(),
                NameState {
                    binding: Binding::Bound(Bound {
                        owner: author,
                        target: Target::Publication(id(8)),
                        expiry: 500,
                        claim_txid: id(7),
                        last_txid: id(9),
                    }),
                    suspended,
                    suspend_votes: Default::default(),
                    restore_votes: Default::default(),
                },
            );
        }
        let mut pending = BTreeMap::new();
        for (key, completed) in [
            (format!("01{}", "00".repeat(31)), true),
            (format!("{}02", "00".repeat(31)), false),
        ] {
            pending.insert(
                key.parse().unwrap(),
                PendingRecord {
                    kind: PendingKind::Request,
                    name: Name::parse("atelier").unwrap(),
                    author,
                    target: id(8),
                    sha256: [7; 32],
                    height: 150,
                    approvals: [author].into_iter().collect(),
                    completed,
                },
            );
        }
        let mut entries: Vec<_> = names
            .iter()
            .map(|(name, state)| NamesEntry::Name {
                name: name.clone(),
                state: state.clone(),
            })
            .chain(pending.iter().map(|(txid, record)| NamesEntry::Pending {
                txid: *txid,
                record: record.clone(),
            }))
            .collect();
        entries.sort_by_key(|e| e.key().order_key());
        let registry =
            Registry::from_parts(id(1), 100, rules, 200, names, pending, vec![]).unwrap();
        let mut index = NamesIndex::new(
            NETWORK,
            Chain::BitcoinRegtest.genesis().unwrap().0.to_string(),
            "03".repeat(32),
            registry,
        );
        index.blocks.push(Checkpoint {
            height: 200,
            hash: "04".repeat(32),
        });
        index.persist(&temp.path().join("index.json")).unwrap();
        fs::write(temp.path().join("token"), TOKEN).unwrap();
        fs::set_permissions(temp.path().join("token"), fs::Permissions::from_mode(0o600)).unwrap();
        Self {
            temp,
            index,
            entries,
        }
    }
    fn page(&self, entries: Vec<NamesEntry>, more: bool) -> NamesPage {
        let snapshot = IndexSnapshot {
            instance: "ab".repeat(16),
            revision: 12,
        };
        let next = more.then(|| NamesCursor {
            genesis: id(1),
            snapshot: snapshot.clone(),
            after: entries.last().unwrap().key(),
        });
        let projected = ChainPoint {
            height: 200,
            hash: "04".repeat(32).parse().unwrap(),
        };
        NamesPage {
            snapshot,
            chain_genesis: Chain::BitcoinRegtest.genesis().unwrap().0,
            status: NamesStatus {
                genesis: id(1),
                genesis_block: ChainPoint {
                    height: 100,
                    hash: "03".repeat(32).parse().unwrap(),
                },
                projected,
                generation: 2,
                selected_tip: Some(projected),
                complete_to_tip: true,
            },
            rules: self.index.registry.rules().clone(),
            entries,
            next,
        }
    }
    fn pages(&self) -> Vec<(u16, Value)> {
        self.entries
            .chunks(2)
            .enumerate()
            .map(|(i, rows)| {
                (
                    200,
                    json!(self.page(rows.to_vec(), (i + 1) * 2 < self.entries.len())),
                )
            })
            .collect()
    }
    fn config(&self, endpoint: Option<SocketAddr>, token: &Path) {
        let value = endpoint
            .map(|endpoint| json!({"archive":{"endpoint":endpoint,"token_file":token}}))
            .unwrap_or(json!({}));
        fs::write(
            self.temp.path().join("config.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
    }
    fn invoke(
        &self,
        command: &str,
        name: Option<&str>,
        registry: Option<Txid>,
    ) -> (bool, Value, String) {
        let out = self.temp.path().join("stdout");
        let err = self.temp.path().join("stderr");
        let rpc = Server::new(vec![]);
        let cookie = self.temp.path().join("rpc-cookie");
        fs::write(&cookie, "fixture:fixture").unwrap();
        fs::set_permissions(&cookie, fs::Permissions::from_mode(0o600)).unwrap();
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_urma"));
        cmd.env_clear()
            .current_dir(self.temp.path())
            .env("HOME", self.temp.path())
            .env("TMPDIR", self.temp.path())
            .env("URMA_CONFIG", self.temp.path().join("config.json"))
            .env("URMA_OUTPUT", "json")
            .env("URMA_LOG_OUTPUT", "stderr")
            .env("URMA_RPC_URL", format!("http://{}/", rpc.addr))
            .env("URMA_NODE_AUTH_FILE", cookie)
            .args(["names", command, "--network", NETWORK, "--index"])
            .arg(self.temp.path().join("index.json"));
        if let Some(registry) = registry {
            cmd.arg("--registry").arg(registry.to_string());
        }
        if let Some(name) = name {
            cmd.arg(name);
        }
        let mut child = OwnedChild(Some(
            cmd.stdin(Stdio::null())
                .stdout(File::create(&out).unwrap())
                .stderr(File::create(&err).unwrap())
                .spawn()
                .unwrap(),
        ));
        let deadline = Instant::now() + Duration::from_secs(12);
        let status = loop {
            if let Some(status) = child.0.as_mut().unwrap().try_wait().unwrap() {
                child.0.take();
                break status;
            }
            assert!(Instant::now() < deadline, "CLI deadline");
            thread::sleep(Duration::from_millis(5));
        };
        assert!(fs::metadata(&out).unwrap().len() < 1024 * 1024);
        assert!(fs::metadata(&err).unwrap().len() < 1024 * 1024);
        let stderr = fs::read_to_string(err).unwrap();
        let stdout = fs::read(out).unwrap();
        assert!(rpc.finish().is_empty(), "Names read contacted chain RPC");
        (
            status.success(),
            serde_json::from_slice(&stdout).unwrap_or(Value::Null),
            stderr,
        )
    }
}
struct OwnedChild(Option<Child>);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let end = Instant::now() + Duration::from_secs(3);
            loop {
                if child.try_wait().unwrap().is_some() {
                    break;
                }
                if Instant::now() >= end {
                    eprintln!("owned CLI not reaped");
                    break;
                }
                thread::sleep(Duration::from_millis(5));
            }
        }
    }
}
struct Server {
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
    worker: Option<JoinHandle<Vec<String>>>,
}
impl Server {
    fn new(replies: Vec<(u16, Value)>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let flag = stop.clone();
        let worker = thread::spawn(move || {
            let end = Instant::now() + Duration::from_secs(15);
            let mut requests = Vec::new();
            while !flag.load(Ordering::Acquire) && Instant::now() < end {
                let (mut stream, _) = match listener.accept() {
                    Ok(v) => v,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                        continue;
                    }
                    Err(e) => panic!("accept {e}"),
                };
                stream
                    .set_read_timeout(Some(Duration::from_millis(500)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(1)))
                    .unwrap();
                let mut bytes = Vec::new();
                let request_end = Instant::now() + Duration::from_secs(2);
                while !bytes.ends_with(b"\r\n\r\n") {
                    assert!(
                        bytes.len() < 8192
                            && Instant::now() < request_end
                            && !flag.load(Ordering::Acquire),
                        "request bound"
                    );
                    let mut b = [0];
                    if stream.read(&mut b).unwrap() == 0 {
                        break;
                    }
                    bytes.push(b[0]);
                }
                let request = String::from_utf8(bytes).unwrap();
                assert!(request.contains(&format!("Authorization: Bearer {TOKEN}\r\n")));
                let response = replies
                    .get(requests.len())
                    .cloned()
                    .unwrap_or((500, json!({"error":"unexpected retry"})));
                requests.push(request);
                let body = serde_json::to_vec(&response.1).unwrap();
                let header = format!(
                    "HTTP/1.1 {} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.0,
                    body.len()
                );
                stream.write_all(header.as_bytes()).unwrap();
                stream.write_all(&body).unwrap();
            }
            requests
        });
        Self {
            addr,
            stop,
            worker: Some(worker),
        }
    }
    fn finish(mut self) -> Vec<String> {
        self.stop.store(true, Ordering::Release);
        let end = Instant::now() + Duration::from_secs(3);
        while !self.worker.as_ref().unwrap().is_finished() {
            assert!(Instant::now() < end, "mock join deadline");
            thread::sleep(Duration::from_millis(5));
        }
        self.worker.take().unwrap().join().unwrap()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let end = Instant::now() + Duration::from_secs(3);
            while !worker.is_finished() && Instant::now() < end {
                thread::sleep(Duration::from_millis(5));
            }
            if worker.is_finished() {
                let _ = worker.join();
            }
        }
    }
}

#[test]
fn complete_operator_view_matches_legacy_resolve_pending_without_scanning_or_index_writes() {
    let f = Fixture::new();
    let original = fs::read(f.temp.path().join("index.json")).unwrap();
    for (command, name) in [
        ("resolve", Some("Atelier")),
        ("resolve", Some("BETA")),
        ("resolve", Some("alpha")),
        ("resolve", Some("absent")),
        ("pending", None),
    ] {
        f.config(None, &f.temp.path().join("token"));
        let (ok, expected, _) = f.invoke(command, name, Some(id(1)));
        assert!(ok);
        let server = Server::new(f.pages());
        f.config(Some(server.addr), &f.temp.path().join("token"));
        // A healthy archive view must not even require an existing local index.
        fs::rename(
            f.temp.path().join("index.json"),
            f.temp.path().join("index.saved"),
        )
        .unwrap();
        let (ok, actual, err) = f.invoke(command, name, Some(id(1)));
        assert!(ok, "{err}");
        assert_eq!(actual, expected);
        let requests = server.finish();
        assert_eq!(requests.len(), 3);
        assert!(requests[0].starts_with(&format!(
            "GET /v1/names/{}/view?limit=128 HTTP/1.1\r\n",
            id(1)
        )));
        assert!(requests[1..].iter().all(|r| r.contains("&cursor=")));
        assert!(!f.temp.path().join("index.json").exists());
        fs::rename(
            f.temp.path().join("index.saved"),
            f.temp.path().join("index.json"),
        )
        .unwrap();
    }
    assert_eq!(
        fs::read(f.temp.path().join("index.json")).unwrap(),
        original
    );
    assert!(!f.temp.path().join(".local/share/urma").exists());
}

#[test]
fn partial_or_changed_operator_traversal_falls_back_atomically_without_retry_or_token_reflection() {
    let f = Fixture::new();
    f.config(None, &f.temp.path().join("token"));
    let (ok, expected, _) = f.invoke("pending", None, Some(id(1)));
    assert!(ok);
    let original = fs::read(f.temp.path().join("index.json")).unwrap();
    for failure in 0..8 {
        let mut pages = f.pages();
        match failure {
            0 => pages[1] = (409, json!({"error":"changed"})),
            1 => pages[1] = (500, json!({"error":TOKEN})),
            2 => pages[1] = (200, json!(TOKEN)),
            3 => pages[1].1["chain_genesis"] = json!(Chain::LitecoinTestnet.genesis().unwrap().0),
            4 => pages[1].1["status"]["generation"] = json!(3),
            5 => pages[1].1["rules"]["expiry_blocks"] = json!(2000),
            6 => pages[1] = (404, json!({"error":"unregistered"})),
            _ => pages[1] = (422, json!({"error":"unregistered"})),
        }
        let server = Server::new(pages);
        f.config(Some(server.addr), &f.temp.path().join("token"));
        let (ok, value, err) = f.invoke("pending", None, Some(id(1)));
        assert!(ok, "{err}");
        assert_eq!(value, expected);
        assert!(err.contains("optional Names archive unavailable"));
        assert!(!err.contains(TOKEN));
        assert!(!err.contains("Authorization"));
        assert_eq!(server.finish().len(), 2);
        assert_eq!(
            fs::read(f.temp.path().join("index.json")).unwrap(),
            original
        );
    }
}

#[test]
fn disabled_unusable_token_and_missing_registry_remain_load_only_and_reject_wrong_fallback_registry()
 {
    let f = Fixture::new();
    let token = f.temp.path().join("token");
    for mode in 0..6 {
        let server = Server::new(vec![]);
        let mut registry = Some(id(1));
        fs::write(&token, TOKEN).unwrap();
        fs::set_permissions(&token, fs::Permissions::from_mode(0o600)).unwrap();
        let selected = if mode == 1 {
            f.temp.path().join("missing")
        } else {
            token.clone()
        };
        if mode == 2 {
            fs::set_permissions(&token, fs::Permissions::from_mode(0o644)).unwrap();
        }
        if mode == 3 {
            fs::write(&token, format!("{TOKEN}{}", " ".repeat(193))).unwrap();
        }
        if mode == 4 {
            registry = None;
        }
        f.config(if mode == 0 { None } else { Some(server.addr) }, &selected);
        if mode == 5 {
            registry = Some(id(2));
            f.config(None, &selected);
        }
        let (ok, value, err) = f.invoke("resolve", Some("atelier"), registry);
        assert_eq!(ok, mode != 5, "{err}");
        if ok {
            assert_eq!(value["name"], "atelier");
        } else {
            assert!(err.contains("another registry"));
        }
        assert!(server.finish().is_empty());
    }
}

#[test]
fn genesis_only_service_view_reports_its_actual_block_without_claiming_tip_completion() {
    let f = Fixture::new();
    let mut page = f.page(vec![], false);
    page.status.projected = page.status.genesis_block;
    page.status.complete_to_tip = false;
    let server = Server::new(vec![(200, json!(page))]);
    f.config(Some(server.addr), &f.temp.path().join("token"));
    fs::remove_file(f.temp.path().join("index.json")).unwrap();
    let (ok, value, err) = f.invoke("resolve", Some("Absent"), Some(id(1)));
    assert!(ok, "{err}");
    assert_eq!(value["height"], 100);
    assert_eq!(value["block_hash"], "03".repeat(32));
    assert_eq!(value["name"], "absent");
    assert_eq!(value["resolution"], "Unbound");
    assert_eq!(value["pending"], json!([]));
    assert_eq!(server.finish().len(), 1);
    assert!(!f.temp.path().join("index.json").exists());
}
