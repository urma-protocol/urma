use bitcoin::{BlockHash, Txid, hashes::Hash};
use libp2p::{
    StreamProtocol,
    futures::{
        executor::block_on,
        io::{AsyncRead, AsyncWrite, Cursor},
    },
    request_response::Codec as _,
};
use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
};
use urma_chain::inclusion::{MerklePath, TransactionProof};
use urma_node::{
    model::{ChainPoint, RecordPackage},
    peer_codec::Codec,
    peer_protocol::{Kind, PROTOCOL, REQUEST_LIMIT, RESPONSE_LIMIT, Reply, Request, Response},
};

fn request() -> Request {
    // Deliberately not a supported version/network: semantic filtering belongs
    // to transport, and must not be introduced by this framing codec.
    Request {
        version: 99,
        chain_genesis: BlockHash::from_byte_array([1; 32]),
        kind: Kind::Record,
        txid: Txid::from_byte_array([2; 32]),
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
        txid: request().txid,
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
        let expected = serde_json::to_vec(&request()).unwrap();
        let mut wire = Stream::new(vec![]);
        codec
            .write_request(&protocol, &mut wire, request())
            .await
            .unwrap();
        assert!(wire.closed);
        assert_eq!(wire.output, frame(&expected));
        let decoded = codec
            .read_request(&protocol, &mut Stream::new(wire.output))
            .await
            .unwrap();
        assert_eq!(serde_json::to_vec(&decoded).unwrap(), expected);
        for result in [
            Reply::Record(Box::new(package())),
            Reply::Missing,
            Reply::WrongNetwork,
            Reply::UnsupportedVersion,
            Reply::Busy,
            Reply::TooLarge,
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
        let wrong = StreamProtocol::new("/urma/node/record/2");
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
