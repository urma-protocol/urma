//! Overlay reads. Book entries and omissions are operator data: routing hints
//! and the operator's own scan findings, not evidence about any peer.
use super::{Client, OPERATION_TIMEOUT, invalid, remaining};
use crate::{
    Error,
    model::{BookEntry, Omission},
};
use serde::de::DeserializeOwned;
use std::time::Instant;

const MAX_OMISSIONS: usize = 1024;
const MAX_BOOK: usize = 1024;
const MAX_ADDRESSES: usize = 4;

impl Client {
    /// The newest (highest) omissions recorded by the operator's scans, at
    /// most 1024, ascending by height. HTTP 404 (a daemon without the overlay
    /// routes) is `Error::Invalid("overlay disabled")`.
    pub fn overlay_omissions(&self) -> Result<Vec<Omission>, Error> {
        let omissions: Vec<Omission> = self.overlay_read("/v1/overlay/omissions", "omissions")?;
        if omissions.len() > MAX_OMISSIONS {
            return Err(invalid("local overlay omissions exceed 1024 entries"));
        }
        if omissions
            .windows(2)
            .any(|pair| pair[0].block.height > pair[1].block.height)
        {
            return Err(invalid("local overlay omissions are not ordered by height"));
        }
        Ok(omissions)
    }

    /// The operator's peer book: untrusted routing hints, at most 1024
    /// entries of one to four addresses. HTTP 404 (discovery not configured)
    /// is `Error::Invalid("overlay disabled")`.
    pub fn overlay_book(&self) -> Result<Vec<BookEntry>, Error> {
        let book: Vec<BookEntry> = self.overlay_read("/v1/overlay/book", "book")?;
        if book.len() > MAX_BOOK {
            return Err(invalid("local overlay book exceeds 1024 entries"));
        }
        if book
            .iter()
            .any(|entry| entry.addrs.is_empty() || entry.addrs.len() > MAX_ADDRESSES)
        {
            return Err(invalid(
                "local overlay book entry needs one to four addresses",
            ));
        }
        Ok(book)
    }

    fn overlay_read<T: DeserializeOwned>(&self, path: &str, what: &str) -> Result<T, Error> {
        let deadline = Instant::now() + OPERATION_TIMEOUT;
        let (code, body) = self.request("GET", path, deadline)?;
        match code {
            200 => {
                let value = serde_json::from_slice(&body)?;
                remaining(deadline)?;
                Ok(value)
            }
            404 => {
                let _: serde_json::Value = serde_json::from_slice(&body)?;
                remaining(deadline)?;
                Err(invalid("overlay disabled"))
            }
            _ => Err(invalid(format!("local overlay {what} HTTP {code}"))),
        }
    }
}
