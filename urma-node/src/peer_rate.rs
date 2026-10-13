//! Serving allowances for the public overlay: token buckets per identity and
//! for the whole node, plus a bounded serialized-size counter.
use crate::peer_protocol::RESPONSE_LIMIT;
use libp2p::PeerId;
use std::{collections::HashMap, time::Instant};

pub(crate) struct Count(pub(crate) usize);
impl std::io::Write for Count {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .filter(|n| *n <= RESPONSE_LIMIT)
            .ok_or_else(|| std::io::Error::other("peer response size limit"))?;
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub(crate) struct Bucket {
    available: u64,
    capacity: u64,
    per_second: u64,
    updated: Instant,
}
impl Bucket {
    pub(crate) fn new(capacity: u64, per_second: u64) -> Self {
        Self {
            available: capacity,
            capacity,
            per_second,
            updated: Instant::now(),
        }
    }
    pub(crate) fn take(&mut self, amount: u64) -> bool {
        self.take_at(amount, Instant::now())
    }
    fn refill(&mut self, now: Instant) {
        let elapsed = now.duration_since(self.updated).as_nanos();
        let earned =
            (elapsed * u128::from(self.per_second) / 1_000_000_000).min(u128::from(self.capacity));
        let added = u64::try_from(earned).unwrap_or(self.capacity);
        if added > 0 {
            self.available = self.available.saturating_add(added).min(self.capacity);
            self.updated = now;
        }
    }
    fn take_at(&mut self, amount: u64, now: Instant) -> bool {
        self.refill(now);
        if self.available < amount {
            return false;
        }
        self.available -= amount;
        true
    }
}

pub(crate) fn peer_rate(rates: &mut HashMap<PeerId, Bucket>, peer: PeerId) -> bool {
    peer_rate_at(rates, peer, Instant::now())
}

fn peer_rate_at(rates: &mut HashMap<PeerId, Bucket>, peer: PeerId, now: Instant) -> bool {
    // Retain spent allowance across disconnects. Only fully replenished
    // identities may be forgotten: recreating those buckets changes no budget.
    // History is bounded independently of connection churn; at capacity a new
    // identity is refused instead of evicting another identity's spent budget.
    rates.retain(|_, bucket| {
        bucket.refill(now);
        bucket.available < bucket.capacity
    });
    if !rates.contains_key(&peer) && rates.len() >= 256 {
        return false;
    }
    rates
        .entry(peer)
        .or_insert_with(|| Bucket {
            available: 4,
            capacity: 4,
            per_second: 4,
            updated: now,
        })
        .take_at(1, now)
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::identity::Keypair;
    use std::{io::Write, time::Duration};

    #[test]
    fn request_rate_history_and_response_serialization_are_bounded() {
        let mut rates = HashMap::new();
        let mut peers = Vec::new();
        let now = Instant::now();
        for _ in 0..256 {
            let peer = Keypair::generate_ed25519().public().to_peer_id();
            assert!(peer_rate_at(&mut rates, peer, now));
            peers.push(peer);
        }
        assert!(!peer_rate_at(
            &mut rates,
            Keypair::generate_ed25519().public().to_peer_id(),
            now
        ));
        assert_eq!(rates.len(), 256);
        rates.get_mut(&peers[0]).unwrap().per_second = 0;
        for _ in 0..3 {
            assert!(peer_rate_at(&mut rates, peers[0], now));
        }
        assert!(!peer_rate_at(&mut rates, peers[0], now));
        let mut count = Count(RESPONSE_LIMIT - 1);
        count.write_all(&[0]).unwrap();
        assert!(count.write_all(&[0]).is_err());
        assert_eq!(count.0, RESPONSE_LIMIT);
        let mut bytes = Bucket::new(1024, 0);
        assert!(bytes.take(1024));
        assert!(!bytes.take(1));
    }

    #[test]
    fn identity_rate_survives_reconnect_until_allowance_replenishes() {
        let mut rates = HashMap::new();
        let peer = Keypair::generate_ed25519().public().to_peer_id();
        let now = Instant::now();
        for _ in 0..4 {
            assert!(peer_rate_at(&mut rates, peer, now));
        }
        // Connection lifetime has no effect on the identity accounting.
        assert!(!peer_rate_at(&mut rates, peer, now));
        let later = now + Duration::from_millis(250);
        assert!(peer_rate_at(&mut rates, peer, later));
        assert!(!peer_rate_at(&mut rates, peer, later));
        let replenished = later + Duration::from_secs(1);
        for _ in 0..4 {
            assert!(peer_rate_at(&mut rates, peer, replenished));
        }
        assert!(!peer_rate_at(&mut rates, peer, replenished));
        let other = Keypair::generate_ed25519().public().to_peer_id();
        assert!(peer_rate_at(
            &mut rates,
            other,
            replenished + Duration::from_secs(1)
        ));
        assert_eq!(rates.len(), 1);
        assert!(!rates.contains_key(&peer));
    }
}
