use super::*;
use bitcoin::Block;
use bitcoin::consensus::encode::{deserialize, serialize};
use std::sync::mpsc::Receiver;
use urma_chain::pow::check_header_pow;

#[allow(dead_code)]
#[path = "../../tests/support/mock_peer.rs"]
mod mock_peer;

// A command-channel worker double: no sockets, DNS, or live chain access.
fn mock_source(
    chain: Chain,
    height: u64,
    header: Header,
    next_hash: BlockHash,
) -> (P2pProvider, Receiver<Command>, tempfile::TempDir) {
    let dir = tempfile::tempdir().unwrap();
    let provider = P2pProvider::with_peers(
        chain,
        dir.path(),
        Anchor {
            height,
            header,
            next_hash,
        },
        Vec::new(),
    )
    .unwrap();
    let (sender, receiver) = mpsc::sync_channel(1);
    *locked(&provider.engine, "engine") = Engine::Running(sender);
    *locked(&provider.shared.status, "status") = Status {
        peers: 1,
        target: height,
        synced: true,
        refreshed: Freshness::At(Instant::now()),
    };
    (provider, receiver, dir)
}

fn regtest_source() -> (
    P2pProvider,
    Receiver<Command>,
    tempfile::TempDir,
    Vec<Block>,
) {
    let blocks = mock_peer::regtest_chain(4);
    let (provider, commands, dir) = mock_source(
        Chain::BitcoinRegtest,
        0,
        blocks[0].header,
        blocks[1].block_hash(),
    );
    let headers: Vec<_> = blocks[1..].iter().map(|block| block.header).collect();
    locked(&provider.shared.headers, "headers")
        .extend(&headers, blocks[3].header.time + 100)
        .unwrap();
    (provider, commands, dir, blocks)
}

fn reply_block(commands: Receiver<Command>, expected: BlockHash, raw: Vec<u8>) {
    match commands.recv_timeout(Duration::from_secs(2)).unwrap() {
        Command::Block { hash, reply } => {
            assert_eq!(hash, expected, "fetch must use the captured header hash");
            reply.send(Ok(raw)).unwrap();
        }
        Command::Refresh { .. } => panic!("fresh source should not refresh"),
    }
}

#[test]
fn typed_source_returns_tip_header_and_original_block() {
    let (provider, commands, _dir, blocks) = regtest_source();
    assert_eq!(provider.verified_tip().unwrap(), (3, blocks[3].header));
    assert_eq!(provider.verified_header(2).unwrap(), blocks[2].header);
    let expected = blocks[2].clone();
    let raw = serialize(&expected);
    let original = raw.clone();
    let worker = std::thread::spawn(move || reply_block(commands, expected.block_hash(), raw));
    let result = provider.verified_block(2).unwrap();
    worker.join().unwrap();
    assert_eq!(result.height(), 2);
    assert_eq!(result.header(), &blocks[2].header);
    assert_eq!(result.block(), &blocks[2]);
    assert_eq!(result.raw(), original);
}

#[test]
fn typed_refresh_preserves_local_context_error_without_freshening_status() {
    let (provider, commands, _dir, _blocks) = regtest_source();
    locked(&provider.shared.status, "status").refreshed = Freshness::Never;
    let worker =
        std::thread::spawn(
            move || match commands.recv_timeout(Duration::from_secs(2)).unwrap() {
                Command::Refresh { reply } => reply
                    .send(Err(Error::HeaderContext(
                        urma_chain::pow::PowError::ShortWindow {
                            needed: 2017,
                            got: 2,
                        },
                    )))
                    .unwrap(),
                Command::Block { .. } => {
                    panic!("missing context must stop before body acquisition")
                }
            },
        );
    let error = provider.verified_tip().unwrap_err();
    worker.join().unwrap();
    assert!(matches!(
        error,
        Error::HeaderContext(urma_chain::pow::PowError::ShortWindow {
            needed: 2017,
            got: 2
        })
    ));
    let status = locked(&provider.shared.status, "status");
    assert!(matches!(status.refreshed, Freshness::Never));
    assert_eq!(status.peers, 1);
}

#[test]
fn typed_source_rejects_block_header_and_merkle_mismatches() {
    for header_mismatch in [true, false] {
        let (provider, commands, _dir, blocks) = regtest_source();
        let mut wrong = blocks[2].clone();
        if header_mismatch {
            wrong.header.nonce ^= 1;
        } else {
            wrong.txdata[0].output[0].value = bitcoin::Amount::ZERO;
        }
        let expected_hash = blocks[2].block_hash();
        let worker = std::thread::spawn(move || {
            reply_block(commands, expected_hash, serialize(&wrong));
        });
        let error = provider.verified_block(2).unwrap_err();
        worker.join().unwrap();
        assert!(
            error.to_string().contains(if header_mismatch {
                "block hash mismatch"
            } else {
                "Merkle root mismatch"
            }),
            "{error}"
        );
    }
}

fn fork_header(previous: Header) -> Header {
    let mut header = previous;
    header.prev_blockhash = previous.block_hash();
    header.time += 601;
    header.nonce = 0;
    while check_header_pow(&header, Chain::BitcoinRegtest).is_err() {
        header.nonce += 1;
    }
    header
}

#[test]
fn typed_source_refuses_a_block_reorganized_during_fetch() {
    let (provider, commands, _dir, blocks) = regtest_source();
    let shared = provider.shared.clone();
    let expected_hash = blocks[2].block_hash();
    let raw = serialize(&blocks[2]);
    let a = fork_header(blocks[1].header);
    let b = fork_header(a);
    let c = fork_header(b);
    let worker =
        std::thread::spawn(
            move || match commands.recv_timeout(Duration::from_secs(2)).unwrap() {
                Command::Block { hash, reply } => {
                    assert_eq!(hash, expected_hash);
                    let outcome = locked(&shared.headers, "headers")
                        .extend(&[a, b, c], c.time + 100)
                        .unwrap();
                    assert!(matches!(
                        outcome,
                        crate::p2p::headers::Extension::Reorganized { fork_height: 1, .. }
                    ));
                    reply.send(Ok(raw)).unwrap();
                }
                Command::Refresh { .. } => panic!("unexpected refresh"),
            },
        );
    let error = provider.verified_block(2).unwrap_err();
    worker.join().unwrap();
    assert!(error.to_string().contains("changed during block fetch"));
    assert_eq!(provider.verified_header(2).unwrap(), a);
}

#[test]
fn typed_source_accepts_an_unchanged_header_when_tip_advances() {
    let (provider, commands, _dir, blocks) = regtest_source();
    let shared = provider.shared.clone();
    let expected_hash = blocks[2].block_hash();
    let raw = serialize(&blocks[2]);
    let next = fork_header(blocks[3].header);
    let worker =
        std::thread::spawn(
            move || match commands.recv_timeout(Duration::from_secs(2)).unwrap() {
                Command::Block { hash, reply } => {
                    assert_eq!(hash, expected_hash);
                    locked(&shared.headers, "headers")
                        .extend(&[next], next.time + 100)
                        .unwrap();
                    reply.send(Ok(raw)).unwrap();
                }
                Command::Refresh { .. } => panic!("unexpected refresh"),
            },
        );
    assert_eq!(
        provider.verified_block(2).unwrap().header(),
        &blocks[2].header
    );
    worker.join().unwrap();
    assert_eq!(provider.verified_tip().unwrap(), (4, next));
}

#[test]
fn typed_source_refreshes_stale_tip_before_capturing_header() {
    let (provider, commands, _dir, blocks) = regtest_source();
    locked(&provider.shared.status, "status").refreshed = Freshness::Never;
    let shared = provider.shared.clone();
    let next = fork_header(blocks[3].header);
    let worker =
        std::thread::spawn(
            move || match commands.recv_timeout(Duration::from_secs(2)).unwrap() {
                Command::Refresh { reply } => {
                    locked(&shared.headers, "headers")
                        .extend(&[next], next.time + 100)
                        .unwrap();
                    locked(&shared.status, "status").refreshed = Freshness::At(Instant::now());
                    reply.send(Ok(())).unwrap();
                }
                Command::Block { .. } => panic!("tip read should not fetch a block"),
            },
        );
    assert_eq!(provider.verified_tip().unwrap(), (4, next));
    worker.join().unwrap();
}

#[test]
fn typed_source_not_ready_or_out_of_range_does_not_enqueue() {
    let (provider, commands, _dir, _blocks) = regtest_source();
    for (synced, peers) in [(false, 1), (true, 0)] {
        let mut status = locked(&provider.shared.status, "status");
        status.synced = synced;
        status.peers = peers;
        drop(status);
        let started = Instant::now();
        assert!(
            provider
                .verified_tip()
                .unwrap_err()
                .to_string()
                .contains("not ready")
        );
        assert!(provider.verified_header(2).is_err());
        assert!(provider.verified_block(2).is_err());
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(matches!(
            commands.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
    }
    let mut status = locked(&provider.shared.status, "status");
    status.synced = true;
    status.peers = 1;
    drop(status);
    assert!(provider.verified_header(4).is_err());
    assert!(provider.verified_block(4).is_err());
    assert!(matches!(
        commands.try_recv(),
        Err(mpsc::TryRecvError::Empty)
    ));
}

#[test]
fn typed_source_full_or_disconnected_queue_fails_fast() {
    let (provider, commands, _dir, _blocks) = regtest_source();
    let (reply, _answer) = mpsc::sync_channel(1);
    provider.command(Command::Refresh { reply }).unwrap();
    let started = Instant::now();
    assert!(matches!(
        provider.verified_block(2),
        Err(Error::Capacity(_))
    ));
    locked(&provider.shared.status, "status").refreshed = Freshness::Never;
    assert!(matches!(provider.verified_tip(), Err(Error::Capacity(_))));
    assert!(matches!(
        provider.verified_header(2),
        Err(Error::Capacity(_))
    ));
    assert!(started.elapsed() < Duration::from_secs(1));
    drop(commands);
    assert!(
        provider
            .verified_tip()
            .unwrap_err()
            .to_string()
            .contains("worker stopped")
    );
}

#[test]
fn typed_source_reports_missing_reply_and_worker_failure() {
    for disconnect in [true, false] {
        let (provider, commands, _dir, _blocks) = regtest_source();
        let worker = std::thread::spawn(move || {
            match commands.recv_timeout(Duration::from_secs(2)).unwrap() {
                Command::Block { reply, .. } => {
                    if disconnect {
                        drop(reply);
                    } else {
                        reply
                            .send(Err(Error::Unsupported("mock unavailable".into())))
                            .unwrap();
                    }
                }
                Command::Refresh { .. } => panic!("unexpected refresh"),
            }
        });
        let error = provider.verified_block(2).unwrap_err();
        worker.join().unwrap();
        assert!(error.to_string().contains(if disconnect {
            "block fetch did not complete"
        } else {
            "mock unavailable"
        }));
    }
}

#[test]
fn typed_source_preserves_litecoin_bytes_and_checks_witness() {
    let original = include_bytes!("../../../tests/vectors/litecoin-mweb/block-4892705.bin");
    let header: Header = deserialize(&original[..Header::SIZE]).unwrap();
    for corrupt in [false, true] {
        let (provider, commands, _dir) = mock_source(
            Chain::LitecoinTestnet,
            4_892_705,
            header,
            header.block_hash(),
        );
        let mut raw = original.to_vec();
        if corrupt {
            raw[214] ^= 1;
        }
        let worker = std::thread::spawn(move || reply_block(commands, header.block_hash(), raw));
        let result = provider.verified_block(4_892_705);
        worker.join().unwrap();
        if corrupt {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("witness commitment mismatch")
            );
        } else {
            let block = result.unwrap();
            assert_eq!(block.height(), 4_892_705);
            assert_eq!(block.header(), &header);
            assert_eq!(block.raw(), original);
            assert_ne!(serialize(block.block()), original);
            assert!(provider.verified_header(4_892_704).is_err());
        }
    }
}
