use bitcoin::block::{Header, Version};
use bitcoin::consensus::encode::{Decodable, serialize};
use bitcoin::hashes::Hash;
use bitcoin::p2p::address::Address;
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_network::VersionMessage;
use bitcoin::p2p::{Magic, ServiceFlags};
use bitcoin::{
    Amount, Block, BlockHash, CompactTarget, OutPoint, ScriptBuf, Sequence, Transaction, TxIn,
    TxMerkleNode, TxOut, Witness, absolute, transaction,
};
use std::io::{BufReader, Write};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use urma_chain::observation::Chain;
use urma_chain::pow::check_header_pow;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Behaviour {
    Serve,
    EofOnGetData,
    Silent,
    CloseAfter(Duration),
    Trickle,
    SilentOnGetData,
    Announce(i32),
    Delay(Duration),
    Flood,
}

pub struct MockPeer {
    pub address: SocketAddr,
    pub getdata: Arc<AtomicUsize>,
    pub getheaders: Arc<AtomicUsize>,
    stop: Arc<AtomicBool>,
}

impl Drop for MockPeer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        let _poke = TcpStream::connect(self.address);
    }
}

pub fn regtest_chain(length: usize) -> Vec<Block> {
    let genesis = bitcoin::blockdata::constants::genesis_block(bitcoin::Network::Regtest);
    let mut blocks = vec![genesis];
    for height in 1..length {
        let previous = &blocks[height - 1];
        let coinbase = Transaction {
            version: transaction::Version::ONE,
            lock_time: absolute::LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::from_bytes(vec![0x51, u8::try_from(height).unwrap()]),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(50_0000_0000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let merkle_root = TxMerkleNode::from_byte_array(coinbase.compute_txid().to_byte_array());
        let mut header = Header {
            version: Version::ONE,
            prev_blockhash: previous.block_hash(),
            merkle_root,
            time: previous.header.time + 600,
            bits: CompactTarget::from_consensus(0x207f_ffff),
            nonce: 0,
        };
        while check_header_pow(&header, Chain::BitcoinRegtest).is_err() {
            header.nonce += 1;
        }
        blocks.push(Block {
            header,
            txdata: vec![coinbase],
        });
    }
    blocks
}

pub fn spawn(blocks: Arc<Vec<Block>>, behaviour: Behaviour) -> MockPeer {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let getdata = Arc::new(AtomicUsize::new(0));
    let getheaders = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let (count_data, count_headers, stopped) = (getdata.clone(), getheaders.clone(), stop.clone());
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            if stopped.load(Ordering::Acquire) {
                return;
            }
            let Ok(stream) = stream else { continue };
            let (blocks, count_data, count_headers) =
                (blocks.clone(), count_data.clone(), count_headers.clone());
            std::thread::spawn(move || {
                serve(stream, &blocks, behaviour, &count_data, &count_headers)
            });
        }
    });
    MockPeer {
        address,
        getdata,
        getheaders,
        stop,
    }
}

fn send(stream: &mut TcpStream, payload: NetworkMessage) -> bool {
    let frame = RawNetworkMessage::new(Magic::REGTEST, payload);
    stream.write_all(&serialize(&frame)).is_ok() && stream.flush().is_ok()
}

fn serve(
    stream: TcpStream,
    blocks: &[Block],
    behaviour: Behaviour,
    count_data: &AtomicUsize,
    count_headers: &AtomicUsize,
) {
    if behaviour == Behaviour::Silent {
        let mut sink = stream;
        let _drained = std::io::copy(&mut sink, &mut std::io::sink());
        return;
    }
    let closing = match behaviour {
        Behaviour::CloseAfter(delay) => Some(Instant::now() + delay),
        _other => None,
    };
    let mut writer = stream.try_clone().unwrap();
    let mut reader = BufReader::new(stream);
    let known = |hash: BlockHash| blocks.iter().position(|block| block.block_hash() == hash);
    loop {
        for deadline in closing.iter() {
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return;
            };
            reader.get_ref().set_read_timeout(Some(remaining)).unwrap();
        }
        let Ok(frame) = RawNetworkMessage::consensus_decode(&mut reader) else {
            return;
        };
        match frame.into_payload() {
            NetworkMessage::Version(_theirs) => {
                let ours = VersionMessage::new(
                    ServiceFlags::NETWORK | ServiceFlags::WITNESS,
                    0,
                    Address::new(&"127.0.0.1:0".parse().unwrap(), ServiceFlags::NONE),
                    Address::new(&"127.0.0.1:0".parse().unwrap(), ServiceFlags::NONE),
                    7,
                    "/mock:0/".into(),
                    match behaviour {
                        Behaviour::Announce(height) => height,
                        _other => i32::try_from(blocks.len() - 1).unwrap(),
                    },
                );
                if !send(&mut writer, NetworkMessage::Version(ours))
                    || !send(&mut writer, NetworkMessage::Verack)
                {
                    return;
                }
                if behaviour == Behaviour::Flood {
                    for block in blocks {
                        if !send(&mut writer, NetworkMessage::Block(block.clone())) {
                            return;
                        }
                    }
                }
                if behaviour == Behaviour::Trickle {
                    let mut pinger = writer.try_clone().unwrap();
                    std::thread::spawn(move || {
                        let mut nonce = 0;
                        while send(&mut pinger, NetworkMessage::Ping(nonce)) {
                            nonce += 1;
                            std::thread::sleep(Duration::from_millis(500));
                        }
                    });
                }
            }
            NetworkMessage::Ping(nonce) => {
                if !send(&mut writer, NetworkMessage::Pong(nonce)) {
                    return;
                }
            }
            NetworkMessage::GetHeaders(request) => {
                count_headers.fetch_add(1, Ordering::AcqRel);
                if behaviour == Behaviour::Trickle {
                    continue;
                }
                let start = request
                    .locator_hashes
                    .iter()
                    .find_map(|hash| known(*hash))
                    .map(|index| index + 1)
                    .unwrap_or(1);
                let headers: Vec<Header> = blocks[start..]
                    .iter()
                    .take(2000)
                    .map(|block| block.header)
                    .collect();
                if !send(&mut writer, NetworkMessage::Headers(headers)) {
                    return;
                }
            }
            NetworkMessage::GetData(items) => {
                count_data.fetch_add(1, Ordering::AcqRel);
                if behaviour == Behaviour::EofOnGetData {
                    return;
                }
                if behaviour == Behaviour::SilentOnGetData {
                    continue;
                }
                match behaviour {
                    Behaviour::Delay(pause) => std::thread::sleep(pause),
                    _other => (),
                }
                for item in items {
                    let (Inventory::WitnessBlock(hash) | Inventory::Block(hash)) = item else {
                        continue;
                    };
                    let answer = match known(hash) {
                        Some(index) => NetworkMessage::Block(blocks[index].clone()),
                        None => NetworkMessage::NotFound(vec![item]),
                    };
                    if !send(&mut writer, answer) {
                        return;
                    }
                }
            }
            _other => (),
        }
    }
}
