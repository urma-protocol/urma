use crate::config::{P2P_ADDRESS_POOL, P2P_SEED_INTERVAL_SECS};
use std::collections::{HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

#[derive(Debug, PartialEq, Eq)]
pub enum Next {
    Address(SocketAddr),
    Exhausted,
}

enum Seeded {
    Never,
    At(Instant),
}

enum Drought {
    Clear,
    Since(Instant),
}

pub struct Discovery {
    pool: VecDeque<SocketAddr>,
    tried: HashSet<SocketAddr>,
    banned: HashSet<IpAddr>,
    skip_v6: bool,
    seeded: Seeded,
    drought: Drought,
}

impl Discovery {
    pub fn new() -> Self {
        Self {
            pool: VecDeque::new(),
            tried: HashSet::new(),
            banned: HashSet::new(),
            skip_v6: false,
            seeded: Seeded::Never,
            drought: Drought::Clear,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.pool.is_empty()
    }

    pub fn len(&self) -> usize {
        self.pool.len()
    }

    pub fn seeding_due(&self, now: Instant) -> bool {
        if !self.pool.is_empty() {
            return false;
        }
        match self.seeded {
            Seeded::Never => true,
            Seeded::At(when) => {
                now.duration_since(when) >= Duration::from_secs(P2P_SEED_INTERVAL_SECS)
            }
        }
    }

    pub fn mark_seeded(&mut self, now: Instant) {
        self.seeded = Seeded::At(now);
    }

    pub fn drought_warns(&mut self, now: Instant) -> bool {
        if !self.pool.is_empty() {
            self.drought = Drought::Clear;
            return false;
        }
        match self.drought {
            Drought::Clear => {
                self.drought = Drought::Since(now);
                false
            }
            Drought::Since(start) => {
                if now.duration_since(start) >= Duration::from_secs(P2P_SEED_INTERVAL_SECS) {
                    self.drought = Drought::Since(now);
                    return true;
                }
                false
            }
        }
    }

    fn admissible(&self, address: &SocketAddr) -> bool {
        !(self.skip_v6 && address.is_ipv6())
            && !self.tried.contains(address)
            && !self.banned.contains(&address.ip())
            && !self.pool.contains(address)
            && self.pool.len() < P2P_ADDRESS_POOL
    }

    pub fn offer_seeded(&mut self, addresses: Vec<SocketAddr>) {
        for address in addresses.into_iter().rev() {
            if self.admissible(&address) {
                self.pool.push_front(address);
            }
        }
    }

    pub fn readmit(&mut self, addresses: Vec<SocketAddr>) {
        for address in &addresses {
            self.tried.remove(address);
        }
        self.offer_seeded(addresses);
    }

    pub fn offer_gossip(&mut self, address: SocketAddr) {
        if self.admissible(&address) {
            self.pool.push_back(address);
        }
    }

    pub fn next(&mut self) -> Next {
        let Some(address) = self.pool.pop_front() else {
            return Next::Exhausted;
        };
        self.tried.insert(address);
        Next::Address(address)
    }

    pub fn ban(&mut self, ip: IpAddr) {
        self.banned.insert(ip);
        self.pool.retain(|address| address.ip() != ip);
    }

    pub fn unreachable_v6(&mut self) {
        self.skip_v6 = true;
        self.pool.retain(|address| !address.is_ipv6());
    }

    pub fn skips_v6(&self) -> bool {
        self.skip_v6
    }
}
