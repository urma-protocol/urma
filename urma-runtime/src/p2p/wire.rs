use crate::config::{
    P2P_MAX_ADDRESSES, P2P_MAX_HEADERS_PER_MESSAGE, P2P_MAX_INVENTORY, P2P_MAX_PAYLOAD_BYTES,
};
use crate::error::{Error, ensure};
use bitcoin::block::Header;
use bitcoin::consensus::encode::{Decodable, VarInt, serialize};
use bitcoin::hashes::{Hash, sha256d};
use bitcoin::p2p::Magic;
use bitcoin::p2p::address::{AddrV2Message, Address};
use bitcoin::p2p::message::{NetworkMessage, RawNetworkMessage};
use bitcoin::p2p::message_blockdata::Inventory;
use bitcoin::p2p::message_network::VersionMessage;
use std::io::{Read, Write};

pub(super) enum Message {
    Version(VersionMessage),
    Verack,
    Ping(u64),
    Pong(u64),
    Addr(Vec<(u32, Address)>),
    AddrV2(Vec<AddrV2Message>),
    Headers(Vec<Header>),
    Inv(Vec<Inventory>),
    NotFound(Vec<Inventory>),
    Block(Vec<u8>),
    Other(String),
}

pub(super) fn send(
    stream: &mut impl Write,
    magic: [u8; 4],
    payload: NetworkMessage,
) -> Result<(), Error> {
    let frame = RawNetworkMessage::new(Magic::from_bytes(magic), payload);
    stream.write_all(&serialize(&frame))?;
    stream.flush()?;
    Ok(())
}

pub(super) fn receive(stream: &mut impl Read, magic: [u8; 4]) -> Result<Message, Error> {
    let mut head = [0u8; 24];
    stream.read_exact(&mut head)?;
    ensure!(
        head[..4] == magic,
        "peer message carries a foreign network magic"
    );
    let command = command_name(&head[4..16])?;
    let length = usize::try_from(u32::from_le_bytes([head[16], head[17], head[18], head[19]]))?;
    ensure!(
        length <= P2P_MAX_PAYLOAD_BYTES,
        "peer message of {length} bytes exceeds the client payload limit"
    );
    let mut payload = Vec::new();
    payload.try_reserve_exact(length)?;
    payload.resize(length, 0);
    stream.read_exact(&mut payload)?;
    let digest = sha256d::Hash::hash(&payload);
    ensure!(
        digest.as_byte_array()[..4] == head[20..24],
        "peer message checksum mismatch"
    );
    decode(&command, payload)
}

fn command_name(raw: &[u8]) -> Result<String, Error> {
    let end = raw.iter().take_while(|byte| **byte != 0).count();
    ensure!(
        raw[end..].iter().all(|byte| *byte == 0),
        "peer command has bytes after its terminator"
    );
    let name = std::str::from_utf8(&raw[..end])?;
    ensure!(
        name.bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit()),
        "peer command is not lowercase ascii"
    );
    Ok(name.to_owned())
}

fn decode(command: &str, payload: Vec<u8>) -> Result<Message, Error> {
    let mut cursor = payload.as_slice();
    let message = match command {
        "version" => Message::Version(exact(&mut cursor)?),
        "verack" => Message::Verack,
        "ping" => Message::Ping(exact(&mut cursor)?),
        "pong" => Message::Pong(exact(&mut cursor)?),
        "addr" => Message::Addr(bounded_list(&mut cursor, P2P_MAX_ADDRESSES, "addr")?),
        "addrv2" => Message::AddrV2(bounded_list(&mut cursor, P2P_MAX_ADDRESSES, "addrv2")?),
        "inv" => Message::Inv(bounded_list(&mut cursor, P2P_MAX_INVENTORY, "inv")?),
        "notfound" => Message::NotFound(bounded_list(&mut cursor, P2P_MAX_INVENTORY, "notfound")?),
        "headers" => Message::Headers(headers(&mut cursor)?),
        "block" => return Ok(Message::Block(payload)),
        other => return Ok(Message::Other(other.to_owned())),
    };
    ensure!(
        cursor.is_empty(),
        "peer {command} message has trailing bytes"
    );
    Ok(message)
}

fn exact<T: Decodable>(cursor: &mut &[u8]) -> Result<T, Error> {
    Ok(T::consensus_decode_from_finite_reader(cursor)?)
}

fn bounded_list<T: Decodable>(
    cursor: &mut &[u8],
    limit: usize,
    command: &str,
) -> Result<Vec<T>, Error> {
    let count = usize::try_from(VarInt::consensus_decode_from_finite_reader(cursor)?.0)?;
    ensure!(
        count <= limit,
        "peer {command} message lists {count} items, above the client limit of {limit}"
    );
    let mut rows = Vec::new();
    rows.try_reserve_exact(count)?;
    for _index in 0..count {
        rows.push(exact(cursor)?);
    }
    Ok(rows)
}

fn headers(cursor: &mut &[u8]) -> Result<Vec<Header>, Error> {
    let count = usize::try_from(VarInt::consensus_decode_from_finite_reader(cursor)?.0)?;
    ensure!(
        count <= P2P_MAX_HEADERS_PER_MESSAGE,
        "peer headers message lists {count} headers, above the protocol limit"
    );
    let mut rows = Vec::new();
    rows.try_reserve_exact(count)?;
    for _index in 0..count {
        rows.push(exact::<Header>(cursor)?);
        let transactions: u8 = exact(cursor)?;
        ensure!(
            transactions == 0,
            "peer headers message embeds transactions"
        );
    }
    Ok(rows)
}
