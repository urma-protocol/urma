//! Built-in defaults that need one home. Seeds are DNS names whose records the
//! operator publishes; the daemon dials whatever they resolve to. Regtest and
//! Bitcoin test chains have no seeds.
use crate::Error;
use libp2p::Multiaddr;
use urma_chain::observation::Chain;

pub const SEEDS: &[(Chain, &str)] = &[
    (Chain::LitecoinMainnet, "/dnsaddr/ltc-seed.urma.rosint.org"),
    (Chain::LitecoinTestnet, "/dnsaddr/tltc-seed.urma.rosint.org"),
];

/// Parsed built-in seeds for `chain`.
pub fn seeds(chain: Chain) -> Result<Vec<Multiaddr>, Error> {
    let genesis = |chain: Chain| {
        chain
            .genesis()
            .map(|identity| identity.0)
            .map_err(|error| Error::Invalid(error.to_string()))
    };
    let wanted = genesis(chain)?;
    let mut seeds = Vec::new();
    for (seeded, address) in SEEDS {
        if genesis(*seeded)? == wanted {
            let parsed = address
                .parse()
                .map_err(|error| Error::Invalid(format!("built-in seed {address}: {error}")))?;
            seeds.push(parsed);
        }
    }
    Ok(seeds)
}
