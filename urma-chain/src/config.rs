use crate::observation::{ChainParams, PowFunction};

pub const LITECOIN_MAINNET: ChainParams = ChainParams {
    magic: [0xfb, 0xc0, 0xb6, 0xdb],
    port: 9333,
    dns_seeds: &[
        "seed-a.litecoin.loshan.co.uk",
        "dnsseed.thrasher.io",
        "dnsseed.litecointools.com",
        "dnsseed.ltcpool.org",
        "dnsseed.koin-project.com",
    ],
    pow: PowFunction::Scrypt,
    pow_limit_bits: 0x1e0f_ffff,
    retarget_interval: 2016,
    retarget_lookback: 2016,
    target_timespan: 302_400,
    target_spacing: 150,
    allow_min_difficulty: false,
    retargets: true,
};

pub const LITECOIN_TESTNET: ChainParams = ChainParams {
    magic: [0xfd, 0xd2, 0xc8, 0xf1],
    port: 19335,
    dns_seeds: &[
        "seed-b.litecoin.loshan.co.uk",
        "dnsseed-testnet.thrasher.io",
        "testnet-seed.litecointools.com",
    ],
    pow: PowFunction::Scrypt,
    pow_limit_bits: 0x1e0f_ffff,
    retarget_interval: 2016,
    retarget_lookback: 2016,
    target_timespan: 302_400,
    target_spacing: 150,
    allow_min_difficulty: true,
    retargets: true,
};

pub const BITCOIN_REGTEST: ChainParams = ChainParams {
    magic: [0xfa, 0xbf, 0xb5, 0xda],
    port: 18444,
    dns_seeds: &[],
    pow: PowFunction::Sha256d,
    pow_limit_bits: 0x207f_ffff,
    retarget_interval: 2016,
    retarget_lookback: 2015,
    target_timespan: 1_209_600,
    target_spacing: 600,
    allow_min_difficulty: true,
    retargets: false,
};

pub const BITCOIN_TESTNET4: ChainParams = ChainParams {
    magic: [0x1c, 0x16, 0x3f, 0x28],
    port: 48333,
    dns_seeds: &[
        "seed.testnet4.bitcoin.sprovoost.nl",
        "seed.testnet4.wiz.biz",
    ],
    pow: PowFunction::Sha256d,
    pow_limit_bits: 0x1d00_ffff,
    retarget_interval: 2016,
    retarget_lookback: 2015,
    target_timespan: 1_209_600,
    target_spacing: 600,
    allow_min_difficulty: true,
    retargets: true,
};

pub const SCRYPT_LOG_N: u8 = 10;
pub const SCRYPT_R: u32 = 1;
pub const SCRYPT_P: u32 = 1;
pub const POW_HASH_BYTES: usize = 32;
