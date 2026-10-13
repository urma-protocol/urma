use crate::config::P2P_GOOD_PEERS;
use crate::error::Error;
use crate::p2p::addr::{routable, unix_now};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use urma_chain::observation::Chain;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(super) struct Entry {
    pub(super) address: SocketAddr,
    pub(super) last_seen: u64,
}

pub(super) struct PeerBook {
    path: PathBuf,
    entries: Vec<Entry>,
}

impl PeerBook {
    pub(super) fn open(cache_dir: &Path, chain: Chain) -> Self {
        let path = cache_dir.join(format!("{}-peers.json", chain.label().replace(' ', "-")));
        let mut book = Self {
            entries: Vec::new(),
            path,
        };
        match book.load() {
            Ok(entries) => book.entries = entries,
            Err(error) => {
                tracing::warn!(path = %book.path.display(), %error, "peer book unreadable; starting empty")
            }
        }
        book.trim();
        book
    }

    fn load(&self) -> Result<Vec<Entry>, Error> {
        if !self.path.try_exists()? {
            return Ok(Vec::new());
        }
        let now = unix_now()?;
        let mut entries: Vec<Entry> = serde_json::from_slice(&std::fs::read(&self.path)?)?;
        entries.retain(|entry| routable(&entry.address));
        for entry in &mut entries {
            entry.last_seen = entry.last_seen.min(now);
        }
        Ok(entries)
    }

    pub(super) fn addresses(&self) -> Vec<SocketAddr> {
        self.entries.iter().map(|entry| entry.address).collect()
    }

    pub(super) fn record(&mut self, address: SocketAddr, now: u64) {
        self.entries.retain(|entry| entry.address != address);
        self.entries.push(Entry {
            address,
            last_seen: now,
        });
        self.trim();
        match self.save() {
            Ok(()) => (),
            Err(error) => {
                tracing::warn!(path = %self.path.display(), %error, "peer book not persisted")
            }
        }
    }

    fn trim(&mut self) {
        self.entries
            .sort_by(|left, right| right.last_seen.cmp(&left.last_seen));
        self.entries.truncate(P2P_GOOD_PEERS);
    }

    fn save(&self) -> Result<(), Error> {
        let bytes = serde_json::to_vec(&self.entries)?;
        Ok(urma_io::write_replace(&self.path, &bytes)?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn address(last: u16) -> SocketAddr {
        let [high, low] = last.to_be_bytes();
        SocketAddr::from(([45, 0, high, low], 19335))
    }

    #[test]
    fn good_peers_persist_most_recent_first_and_stay_bounded() {
        let dir = tempfile::tempdir().unwrap();
        let mut book = PeerBook::open(dir.path(), Chain::LitecoinTestnet);
        assert!(book.addresses().is_empty());
        book.record(address(1), 100);
        book.record(address(2), 200);
        book.record(address(1), 300);
        assert_eq!(book.addresses(), vec![address(1), address(2)]);
        let reopened = PeerBook::open(dir.path(), Chain::LitecoinTestnet);
        assert_eq!(reopened.addresses(), vec![address(1), address(2)]);
        assert!(
            PeerBook::open(dir.path(), Chain::LitecoinMainnet)
                .addresses()
                .is_empty()
        );
        let mut full = PeerBook::open(dir.path(), Chain::LitecoinTestnet);
        let extra = u16::try_from(P2P_GOOD_PEERS + 10).unwrap();
        for index in 0..extra {
            full.record(address(1000 + index), 1000 + u64::from(index));
        }
        let kept = PeerBook::open(dir.path(), Chain::LitecoinTestnet).addresses();
        assert_eq!(kept.len(), P2P_GOOD_PEERS);
        assert_eq!(kept[0], address(1000 + extra - 1));
    }

    #[test]
    fn loading_drops_unroutable_entries_and_clamps_future_sightings() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Litecoin-testnet-peers.json");
        let now = unix_now().unwrap();
        let stored = vec![
            Entry {
                address: "127.0.0.1:19335".parse().unwrap(),
                last_seen: now,
            },
            Entry {
                address: "192.168.0.7:19335".parse().unwrap(),
                last_seen: now,
            },
            Entry {
                address: address(1),
                last_seen: u64::MAX,
            },
            Entry {
                address: address(2),
                last_seen: now - 10,
            },
        ];
        std::fs::write(&path, serde_json::to_vec(&stored).unwrap()).unwrap();
        let mut book = PeerBook::open(dir.path(), Chain::LitecoinTestnet);
        assert_eq!(book.addresses(), vec![address(1), address(2)]);
        book.record(address(3), now + 1);
        assert_eq!(
            book.addresses()[0],
            address(3),
            "a clamped future sighting no longer outranks a real one"
        );
    }

    #[test]
    fn an_unreadable_book_starts_empty_and_is_rewritten() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("Litecoin-testnet-peers.json");
        std::fs::write(&path, b"not json").unwrap();
        let mut book = PeerBook::open(dir.path(), Chain::LitecoinTestnet);
        assert!(book.addresses().is_empty());
        book.record(address(7), 1);
        assert_eq!(
            PeerBook::open(dir.path(), Chain::LitecoinTestnet).addresses(),
            vec![address(7)]
        );
    }
}
