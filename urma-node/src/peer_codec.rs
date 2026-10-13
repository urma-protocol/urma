//! Bounded framing for untrusted peer JSON. No record or chain verification.
//! The request-response layer owns timeouts, including waiting for stream EOF.
use crate::peer_protocol::{
    INVENTORY_LIMIT, PEERS_LIMIT, PROTOCOL, REQUEST_LIMIT, RESPONSE_LIMIT, Reply, Request, Response,
};
use async_trait::async_trait;
use libp2p::{
    StreamProtocol,
    futures::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
};
use serde::{Serialize, de::DeserializeOwned};
use std::io::{self, Write};

#[derive(Clone, Default)]
pub struct Codec;

fn protocol(protocol: &StreamProtocol) -> io::Result<()> {
    if protocol.as_ref() != PROTOCOL {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "unsupported peer protocol",
        ));
    }
    Ok(())
}

/// Inventory pages and peer gossip have their own, smaller frame bounds.
fn response_limit(response: &Response) -> usize {
    match response.result {
        Reply::Inventory(_) => INVENTORY_LIMIT,
        Reply::Peers(_) => PEERS_LIMIT,
        _ => RESPONSE_LIMIT,
    }
}

async fn read<T: AsyncRead + Unpin + Send, V: DeserializeOwned>(
    io: &mut T,
    limit: usize,
) -> io::Result<(V, usize)> {
    let mut prefix = [0; 4];
    io.read_exact(&mut prefix).await?;
    let length = u32::from_be_bytes(prefix) as usize;
    if length == 0 || length > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "peer frame length outside limits",
        ));
    }
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(length).map_err(io::Error::other)?;
    bytes.resize(length, 0);
    io.read_exact(&mut bytes).await?;
    let mut trailing = [0];
    if io.read(&mut trailing).await? != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing peer frame bytes",
        ));
    }
    let value = serde_json::from_slice(&bytes)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))?;
    Ok((value, length))
}

struct BoundedVec {
    bytes: Vec<u8>,
    limit: usize,
}

impl Write for BoundedVec {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.len() > self.limit - self.bytes.len() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "encoded peer frame exceeds byte limit",
            ));
        }
        let needed = self.bytes.len() + bytes.len();
        if needed > self.bytes.capacity() {
            // Amortize small serializer writes, without reserving past the cap.
            let capacity = needed
                .max(self.bytes.capacity().saturating_mul(2))
                .min(self.limit);
            self.bytes
                .try_reserve_exact(capacity - self.bytes.len())
                .map_err(io::Error::other)?;
        }
        self.bytes.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

async fn write<T: AsyncWrite + Unpin + Send, V: Serialize>(
    io: &mut T,
    value: &V,
    limit: usize,
) -> io::Result<()> {
    let mut body = BoundedVec {
        bytes: Vec::new(),
        limit,
    };
    serde_json::to_writer(&mut body, value)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
    let length = u32::try_from(body.bytes.len()).map_err(io::Error::other)?;
    io.write_all(&length.to_be_bytes()).await?;
    io.write_all(&body.bytes).await?;
    io.close().await
}

#[async_trait]
impl libp2p::request_response::Codec for Codec {
    type Protocol = StreamProtocol;
    type Request = Request;
    type Response = Response;

    async fn read_request<T>(
        &mut self,
        negotiated: &StreamProtocol,
        io: &mut T,
    ) -> io::Result<Request>
    where
        T: AsyncRead + Unpin + Send,
    {
        protocol(negotiated)?;
        Ok(read(io, REQUEST_LIMIT).await?.0)
    }
    /// The reader does not know the request kind, so a frame of up to
    /// RESPONSE_LIMIT is read first; the 256 KiB inventory bound then applies.
    async fn read_response<T>(
        &mut self,
        negotiated: &StreamProtocol,
        io: &mut T,
    ) -> io::Result<Response>
    where
        T: AsyncRead + Unpin + Send,
    {
        protocol(negotiated)?;
        let (response, length) = read(io, RESPONSE_LIMIT).await?;
        if length > response_limit(&response) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "peer inventory or gossip frame exceeds its limit",
            ));
        }
        Ok(response)
    }
    async fn write_request<T>(
        &mut self,
        negotiated: &StreamProtocol,
        io: &mut T,
        request: Request,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        protocol(negotiated)?;
        write(io, &request, REQUEST_LIMIT).await
    }
    async fn write_response<T>(
        &mut self,
        negotiated: &StreamProtocol,
        io: &mut T,
        response: Response,
    ) -> io::Result<()>
    where
        T: AsyncWrite + Unpin + Send,
    {
        protocol(negotiated)?;
        let limit = response_limit(&response);
        write(io, &response, limit).await
    }
}
