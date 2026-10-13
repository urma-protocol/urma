use bitcoin::{BlockHash, Txid, Wtxid, hashes::Hash};
use libp2p::{
    Multiaddr, StreamProtocol,
    futures::{
        executor::block_on,
        io::{AsyncRead, AsyncWrite, Cursor},
    },
    identity::Keypair,
    request_response::Codec as _,
};
use serde_json::json;
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use urma_chain::inclusion::{MerklePath, TransactionProof};
use urma_node::{
    model::{ChainPoint, RecordPackage},
    peer_codec::Codec,
    peer_protocol::{
        GossipPeer, INVENTORY_ENTRIES, INVENTORY_LIMIT, INVENTORY_SPAN, InventoryPage, Kind,
        PARENT_LIMIT, PEERS_LIMIT, PEERS_MAX, PROTOCOL, Placement, REQUEST_LIMIT, RESPONSE_LIMIT,
        Reply, Request, Response, VERSION,
    },
};

fn request() -> Request {
    // Deliberately not a supported version/network: semantic filtering belongs
    // to transport, and must not be introduced by this framing codec.
    Request {
        version: 99,
        chain_genesis: BlockHash::from_byte_array([1; 32]),
        kind: Kind::Record {
            txid: Txid::from_byte_array([2; 32]),
        },
    }
}
fn parent_request() -> Request {
    Request {
        kind: Kind::Parent {
            txid: Txid::from_byte_array([2; 32]),
        },
        ..request()
    }
}
fn inventory_request() -> Request {
    let after = page(1).entries[0];
    Request {
        kind: Kind::Inventory {
            from_height: 5,
            to_height: 5 + INVENTORY_SPAN,
            after: Some(after),
            limit: INVENTORY_ENTRIES,
        },
        ..request()
    }
}
// Maximal-width placement fields: every hash is a full 32-byte value.
fn page(entries: u32) -> InventoryPage {
    InventoryPage {
        scanned_through: Some(u64::MAX),
        entries: (0..entries)
            .map(|position| Placement {
                height: u64::MAX,
                block_hash: BlockHash::from_byte_array([0xff; 32]),
                position: u32::MAX - position,
                txid: Txid::from_byte_array([0xee; 32]),
                wtxid: Wtxid::from_byte_array([0xdd; 32]),
            })
            .collect(),
        more: true,
    }
}
fn package() -> RecordPackage {
    let path = MerklePath {
        index: 0,
        tx_count: 1,
        siblings: vec![],
    };
    RecordPackage {
        version: 99,
        chain_genesis: request().chain_genesis,
        block: ChainPoint {
            height: 5,
            hash: BlockHash::from_byte_array([3; 32]),
        },
        commit: vec![],
        reveal: TransactionProof {
            transaction: vec![1],
            coinbase: vec![2],
            txid_path: path.clone(),
            coinbase_path: path.clone(),
            witness_path: path.clone(),
            coinbase_witness_path: path,
        },
    }
}
fn response(result: Reply) -> Response {
    Response {
        version: 99,
        chain_genesis: request().chain_genesis,
        kind: request().kind,
        result,
    }
}
fn frame(body: &[u8]) -> Vec<u8> {
    let mut raw = (body.len() as u32).to_be_bytes().to_vec();
    raw.extend_from_slice(body);
    raw
}

// Immediately-ready, bounded in-memory I/O, including short reads/writes and
// explicit close observation. No sockets, Tokio runtime, sleeps or crypto.
struct Stream {
    input: Cursor<Vec<u8>>,
    output: Vec<u8>,
    chunk: usize,
    read_polls: usize,
    write_polls: usize,
    closed: bool,
    output_limit: usize,
}
impl Stream {
    fn new(input: Vec<u8>) -> Self {
        Self {
            input: Cursor::new(input),
            output: vec![],
            chunk: 3,
            read_polls: 0,
            write_polls: 0,
            closed: false,
            output_limit: RESPONSE_LIMIT + 4,
        }
    }
}
impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        self.read_polls += 1;
        let count = buffer.len().min(self.chunk);
        Pin::new(&mut self.input).poll_read(cx, &mut buffer[..count])
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.write_polls += 1;
        assert!(!self.closed);
        let count = bytes.len().min(self.chunk);
        assert!(count <= self.output_limit - self.output.len());
        self.output.extend_from_slice(&bytes[..count]);
        Poll::Ready(Ok(count))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_close(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closed = true;
        Poll::Ready(Ok(()))
    }
}

struct PrefixOnly {
    prefix: [u8; 4],
    read: usize,
}
impl AsyncRead for PrefixOnly {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        buffer: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        assert!(
            self.read < 4,
            "invalid announced length must not read the body or EOF"
        );
        buffer[0] = self.prefix[self.read];
        self.read += 1;
        Poll::Ready(Ok(1))
    }
}

#[test]
fn request_and_all_response_variants_round_trip_and_close_with_exact_prefix() {
    block_on(async {
        let protocol = StreamProtocol::new(PROTOCOL);
        let mut codec = Codec::default().clone();
        for (value, kind) in [
            (request(), "record"),
            (parent_request(), "parent"),
            (inventory_request(), "inventory"),
        ] {
            // Kind is internally tagged: {"kind":{"kind":"record","txid":…}}.
            assert_eq!(serde_json::to_value(&value).unwrap()["kind"]["kind"], kind);
            let expected = serde_json::to_vec(&value).unwrap();
            let mut wire = Stream::new(vec![]);
            codec
                .write_request(&protocol, &mut wire, value)
                .await
                .unwrap();
            assert!(wire.closed);
            assert_eq!(wire.output, frame(&expected));
            let decoded = codec
                .read_request(&protocol, &mut Stream::new(wire.output))
                .await
                .unwrap();
            assert_eq!(serde_json::to_vec(&decoded).unwrap(), expected);
        }
        let parent = serde_json::to_value(response(Reply::Parent("0001ff".into()))).unwrap();
        assert_eq!(
            parent["result"],
            serde_json::json!({"status":"parent","package":"0001ff"})
        );
        for result in [
            Reply::Record(Box::new(package())),
            Reply::Parent("0001ff".into()),
            Reply::Missing,
            Reply::WrongNetwork,
            Reply::UnsupportedVersion,
            Reply::Busy,
            Reply::TooLarge,
            Reply::Refused,
            Reply::Inventory(page(3)),
        ] {
            let value = response(result);
            let expected = serde_json::to_vec(&value).unwrap();
            let mut wire = Stream::new(vec![]);
            codec
                .write_response(&protocol, &mut wire, value)
                .await
                .unwrap();
            assert!(wire.closed);
            assert_eq!(wire.output, frame(&expected));
            let decoded = codec
                .read_response(&protocol, &mut Stream::new(wire.output))
                .await
                .unwrap();
            assert_eq!(serde_json::to_vec(&decoded).unwrap(), expected);
        }
    });
}

#[test]
fn zero_and_oversized_prefixes_are_rejected_without_body_reads() {
    block_on(async {
        let protocol = StreamProtocol::new(PROTOCOL);
        for length in [0, REQUEST_LIMIT as u32 + 1, u32::MAX] {
            let mut wire = PrefixOnly {
                prefix: length.to_be_bytes(),
                read: 0,
            };
            assert_eq!(
                Codec
                    .read_request(&protocol, &mut wire)
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(wire.read, 4);
        }
        for length in [0, RESPONSE_LIMIT as u32 + 1, u32::MAX] {
            let mut wire = PrefixOnly {
                prefix: length.to_be_bytes(),
                read: 0,
            };
            assert_eq!(
                Codec
                    .read_response(&protocol, &mut wire)
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
            assert_eq!(wire.read, 4);
        }
    });
}

#[test]
fn exact_request_and_response_byte_limits_are_accepted() {
    block_on(async {
        let protocol = StreamProtocol::new(PROTOCOL);
        let expected = serde_json::to_vec(&request()).unwrap();
        let mut body = expected.clone();
        body.resize(REQUEST_LIMIT, b' '); // Whitespace is inside the announced JSON frame.
        let decoded = Codec
            .read_request(&protocol, &mut Cursor::new(frame(&body)))
            .await
            .unwrap();
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), expected);
        let expected = serde_json::to_vec(&response(Reply::Missing)).unwrap();
        let mut body = expected.clone();
        body.resize(RESPONSE_LIMIT, b' ');
        let decoded = Codec
            .read_response(&protocol, &mut Cursor::new(frame(&body)))
            .await
            .unwrap();
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), expected);
    });
}

#[test]
fn truncated_prefix_body_and_trailing_bytes_are_rejected() {
    block_on(async {
        let protocol = StreamProtocol::new(PROTOCOL);
        let request = frame(&serde_json::to_vec(&request()).unwrap());
        let response = frame(&serde_json::to_vec(&response(Reply::Missing)).unwrap());
        for (is_request, raw) in [(true, &request), (false, &response)] {
            for prefix_length in 0..4 {
                let mut wire = Cursor::new(raw[..prefix_length].to_vec());
                let error = if is_request {
                    Codec.read_request(&protocol, &mut wire).await.unwrap_err()
                } else {
                    Codec.read_response(&protocol, &mut wire).await.unwrap_err()
                };
                assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
            }
            let mut wire = Cursor::new(raw[..raw.len() - 1].to_vec());
            let error = if is_request {
                Codec.read_request(&protocol, &mut wire).await.unwrap_err()
            } else {
                Codec.read_response(&protocol, &mut wire).await.unwrap_err()
            };
            assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
            for suffix in [vec![0], vec![b' '], raw.to_vec()] {
                let mut joined = raw.clone();
                joined.extend(suffix);
                let mut wire = Cursor::new(joined);
                let error = if is_request {
                    Codec.read_request(&protocol, &mut wire).await.unwrap_err()
                } else {
                    Codec.read_response(&protocol, &mut wire).await.unwrap_err()
                };
                assert_eq!(error.kind(), io::ErrorKind::InvalidData);
            }
        }
    });
}

#[test]
fn malformed_json_unknown_fields_and_wrong_protocol_are_rejected() {
    block_on(async {
        let protocol = StreamProtocol::new(PROTOCOL);
        let mut unknown_request = serde_json::to_value(request()).unwrap();
        unknown_request["extra"] = true.into();
        for body in [
            b"{".to_vec(),
            b"{}".to_vec(),
            b"null".to_vec(),
            serde_json::to_vec(&unknown_request).unwrap(),
        ] {
            assert_eq!(
                Codec
                    .read_request(&protocol, &mut Cursor::new(frame(&body)))
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
        let mut unknown_response = serde_json::to_value(response(Reply::Missing)).unwrap();
        unknown_response["extra"] = true.into();
        let mut unknown_package =
            serde_json::to_value(response(Reply::Record(Box::new(package())))).unwrap();
        unknown_package["result"]["package"]["extra"] = true.into();
        for body in [
            b"[".to_vec(),
            b"{}".to_vec(),
            serde_json::to_vec(&unknown_response).unwrap(),
            serde_json::to_vec(&unknown_package).unwrap(),
        ] {
            assert_eq!(
                Codec
                    .read_response(&protocol, &mut Cursor::new(frame(&body)))
                    .await
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::InvalidData
            );
        }
        let wrong = StreamProtocol::new("/urma/node/record/1");
        let mut wire = Stream::new(vec![]);
        assert!(Codec.read_request(&wrong, &mut wire).await.is_err());
        assert!(Codec.read_response(&wrong, &mut wire).await.is_err());
        assert!(
            Codec
                .write_request(&wrong, &mut wire, request())
                .await
                .is_err()
        );
        assert!(
            Codec
                .write_response(&wrong, &mut wire, response(Reply::Missing))
                .await
                .is_err()
        );
        assert_eq!(wire.read_polls, 0);
        assert_eq!(wire.write_polls, 0);
        assert!(!wire.closed);
    });
}

#[test]
fn exact_outbound_response_byte_limit_is_accepted_and_closed() {
    block_on(async {
        let mut value = package();
        let empty_length = serde_json::to_vec(&response(Reply::Record(Box::new(value.clone()))))
            .unwrap()
            .len();
        let delta = RESPONSE_LIMIT - empty_length;
        // Replacing [] with n zeros adds 2*n-1 JSON bytes. A final 10
        // supplies the extra byte when delta is even, without padding JSON.
        value.commit = vec![0; (delta + 1) / 2];
        if delta % 2 == 0 {
            *value.commit.last_mut().unwrap() = 10;
        }
        let mut wire = Stream::new(vec![]);
        wire.chunk = 64 * 1024;
        Codec
            .write_response(
                &StreamProtocol::new(PROTOCOL),
                &mut wire,
                response(Reply::Record(Box::new(value))),
            )
            .await
            .unwrap();
        assert!(wire.closed);
        assert_eq!(wire.output.len(), RESPONSE_LIMIT + 4);
        assert_eq!(&wire.output[..4], &(RESPONSE_LIMIT as u32).to_be_bytes());
    });
}

#[test]
fn oversized_outbound_response_hits_bounded_serializer_before_any_async_io() {
    block_on(async {
        let mut oversized = package();
        // Each 255 occupies four JSON bytes including separators. The bounded
        // writer must abort before creating the full serialized JSON value.
        oversized.commit = vec![255; RESPONSE_LIMIT / 4 + 1];
        let mut wire = Stream::new(vec![]);
        wire.output_limit = 0;
        let error = Codec
            .write_response(
                &StreamProtocol::new(PROTOCOL),
                &mut wire,
                response(Reply::Record(Box::new(oversized))),
            )
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(wire.write_polls, 0);
        assert!(wire.output.is_empty());
        assert!(!wire.closed);
    });
}

// The server's TooLarge branch for a retained parent over PARENT_LIMIT is not
// reachable end to end: genuine transactions decode under an 8,000,000-byte
// cap, below PARENT_LIMIT. This checks the limit relation instead: a maximal
// parent's hex frame fits RESPONSE_LIMIT and survives the codec unchanged.
// The client's pre-decode hex length check is exercised over the network in
// peer_parent.rs.
#[test]
fn maximal_parent_hex_fits_the_response_frame_and_round_trips() {
    block_on(async {
        let maximal = "ff".repeat(PARENT_LIMIT);
        let value = response(Reply::Parent(maximal));
        let expected = serde_json::to_vec(&value).unwrap();
        assert!(expected.len() <= RESPONSE_LIMIT);
        let protocol = StreamProtocol::new(PROTOCOL);
        let mut wire = Stream::new(vec![]);
        wire.chunk = 64 * 1024;
        Codec
            .write_response(&protocol, &mut wire, value)
            .await
            .unwrap();
        assert!(wire.closed);
        let mut input = Stream::new(wire.output);
        input.chunk = 64 * 1024;
        let decoded = Codec.read_response(&protocol, &mut input).await.unwrap();
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), expected);
    });
}

// A full page of maximal placements fits INVENTORY_LIMIT; an inventory frame
// above it is refused by the writer before I/O and by the reader after
// framing, even though it is far below RESPONSE_LIMIT.
#[test]
fn inventory_frames_have_their_own_smaller_bound_on_both_sides() {
    block_on(async {
        let protocol = StreamProtocol::new(PROTOCOL);
        let full = response(Reply::Inventory(page(INVENTORY_ENTRIES)));
        let expected = serde_json::to_vec(&full).unwrap();
        assert!(expected.len() <= INVENTORY_LIMIT, "{}", expected.len());
        let mut wire = Stream::new(vec![]);
        wire.chunk = 64 * 1024;
        Codec
            .write_response(&protocol, &mut wire, full)
            .await
            .unwrap();
        let decoded = Codec
            .read_response(&protocol, &mut Cursor::new(wire.output))
            .await
            .unwrap();
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), expected);
        let oversized = response(Reply::Inventory(page(4 * INVENTORY_ENTRIES)));
        let body = serde_json::to_vec(&oversized).unwrap();
        assert!(body.len() > INVENTORY_LIMIT && body.len() < RESPONSE_LIMIT);
        let mut wire = Stream::new(vec![]);
        let error = Codec
            .write_response(&protocol, &mut wire, oversized)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(wire.write_polls, 0);
        let error = Codec
            .read_response(&protocol, &mut Cursor::new(frame(&body)))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        // Whitespace padding past the bound is refused just the same.
        let mut padded = serde_json::to_vec(&response(Reply::Inventory(page(1)))).unwrap();
        padded.resize(INVENTORY_LIMIT + 1, b' ');
        let error = Codec
            .read_response(&protocol, &mut Cursor::new(frame(&padded)))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    });
}

fn gossip_peer() -> GossipPeer {
    let addrs: Vec<Multiaddr> = ["/ip4/8.8.8.8/tcp/4001", "/ip6/2a01:4f8:1::1/tcp/4001"]
        .map(|text| text.parse().unwrap())
        .to_vec();
    GossipPeer {
        peer_id: Keypair::generate_ed25519().public().to_peer_id(),
        addrs,
        last_seen: 1_800_000_000,
    }
}

fn gossip_peers() -> Vec<GossipPeer> {
    vec![gossip_peer()]
}

// v4 adds address exchange: a Peers request carries only its limit, and the
// reply lists identified peers with bare addresses and a unix last-seen time.
#[test]
fn v4_peers_request_and_reply_have_stable_shapes_and_round_trip() {
    assert_eq!(PROTOCOL, "/urma/node/record/4");
    assert_eq!(VERSION, 4);
    block_on(async {
        let protocol = StreamProtocol::new(PROTOCOL);
        let asked = Request {
            kind: Kind::Peers { limit: 32 },
            ..request()
        };
        let value = serde_json::to_value(&asked).unwrap();
        assert_eq!(value["kind"], json!({"kind":"peers","limit":32}));
        let mut wire = Stream::new(vec![]);
        Codec
            .write_request(&protocol, &mut wire, asked)
            .await
            .unwrap();
        let decoded = Codec
            .read_request(&protocol, &mut Stream::new(wire.output))
            .await
            .unwrap();
        assert_eq!(serde_json::to_value(&decoded).unwrap(), value);
        let peers = gossip_peers();
        let id = peers[0].peer_id;
        for listed in [peers, Vec::new()] {
            let answer = response(Reply::Peers(listed));
            let expected = serde_json::to_vec(&answer).unwrap();
            let mut wire = Stream::new(vec![]);
            Codec
                .write_response(&protocol, &mut wire, answer)
                .await
                .unwrap();
            assert!(wire.closed);
            assert_eq!(wire.output, frame(&expected));
            let decoded = Codec
                .read_response(&protocol, &mut Stream::new(wire.output))
                .await
                .unwrap();
            assert_eq!(serde_json::to_vec(&decoded).unwrap(), expected);
        }
        let mut listed = gossip_peers();
        listed[0].peer_id = id;
        let shaped = serde_json::to_value(response(Reply::Peers(listed))).unwrap();
        let id = id.to_string();
        assert_eq!(
            shaped["result"],
            json!({"status":"peers","package":[{"peer_id":id,
                "addrs":["/ip4/8.8.8.8/tcp/4001","/ip6/2a01:4f8:1::1/tcp/4001"],
                "last_seen":1_800_000_000}]})
        );
    });
}

// A full gossip reply fits PEERS_LIMIT; a larger Peers frame is refused by the
// writer before I/O and by the reader, though far below RESPONSE_LIMIT.
#[test]
fn peers_frames_have_their_own_smaller_bound_on_both_sides() {
    block_on(async {
        let protocol = StreamProtocol::new(PROTOCOL);
        let full: Vec<GossipPeer> = (0..PEERS_MAX).map(|_| gossip_peer()).collect();
        let body = serde_json::to_vec(&response(Reply::Peers(full))).unwrap();
        assert!(body.len() <= PEERS_LIMIT, "{}", body.len());
        let oversized: Vec<GossipPeer> = (0..16 * PEERS_MAX).map(|_| gossip_peer()).collect();
        let oversized = response(Reply::Peers(oversized));
        let body = serde_json::to_vec(&oversized).unwrap();
        assert!(body.len() > PEERS_LIMIT && body.len() < RESPONSE_LIMIT);
        let mut wire = Stream::new(vec![]);
        let error = Codec
            .write_response(&protocol, &mut wire, oversized)
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(wire.write_polls, 0);
        let error = Codec
            .read_response(&protocol, &mut Cursor::new(frame(&body)))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    });
}

#[test]
fn malformed_peers_requests_and_replies_are_rejected() {
    block_on(async {
        let protocol = StreamProtocol::new(PROTOCOL);
        let asked = Request {
            kind: Kind::Peers { limit: 32 },
            ..request()
        };
        let mut extra = serde_json::to_value(asked).unwrap();
        extra["kind"]["extra"] = true.into();
        let mut negative = extra.clone();
        negative["kind"] = json!({"kind":"peers","limit":-1});
        let mut absent = extra.clone();
        absent["kind"] = json!({"kind":"peers"});
        for body in [extra, negative, absent] {
            let body = serde_json::to_vec(&body).unwrap();
            let error = Codec
                .read_request(&protocol, &mut Cursor::new(frame(&body)))
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
        let good = serde_json::to_value(response(Reply::Peers(gossip_peers()))).unwrap();
        let mut unknown = good.clone();
        unknown["result"]["package"][0]["extra"] = true.into();
        let mut numeric_id = good.clone();
        numeric_id["result"]["package"][0]["peer_id"] = 7.into();
        let mut bad_id = good.clone();
        bad_id["result"]["package"][0]["peer_id"] = "bad".into();
        let mut bad_addr = good.clone();
        bad_addr["result"]["package"][0]["addrs"] = json!(["not a multiaddr"]);
        let mut missing = good.clone();
        missing["result"]["package"][0]
            .as_object_mut()
            .unwrap()
            .remove("last_seen");
        for body in [unknown, numeric_id, bad_id, bad_addr, missing] {
            let body = serde_json::to_vec(&body).unwrap();
            let error = Codec
                .read_response(&protocol, &mut Cursor::new(frame(&body)))
                .await
                .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        }
    });
}
