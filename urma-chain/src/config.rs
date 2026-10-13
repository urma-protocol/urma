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
    fixed_seeds: &[],
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
    dns_seeds: &["dnsseed-testnet.thrasher.io"],
    fixed_seeds: &[
        "137.66.3.26:19335",
        "142.132.147.162:19335",
        "167.114.119.46:19335",
        "77.90.63.126:19335",
        "72.61.172.129:19335",
        "85.122.129.66:19335",
        "34.201.36.81:19335",
        "2.29.40.191:19335",
        "167.172.77.184:19335",
        "15.235.86.173:19335",
        "81.17.120.243:19335",
        "194.108.49.87:19335",
        "5.253.84.166:19335",
        "44.200.32.195:19335",
        "195.133.68.203:19335",
        "193.168.140.155:19335",
        "139.162.112.41:19335",
        "93.125.75.112:19335",
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

pub const BITCOIN_MAINNET: ChainParams = ChainParams {
    magic: [0xf9, 0xbe, 0xb4, 0xd9],
    port: 8333,
    dns_seeds: &[],
    fixed_seeds: &[],
    pow: PowFunction::Sha256d,
    pow_limit_bits: 0x1d00_ffff,
    retarget_interval: 2016,
    retarget_lookback: 2015,
    target_timespan: 1_209_600,
    target_spacing: 600,
    allow_min_difficulty: false,
    retargets: true,
};

pub const BITCOIN_REGTEST: ChainParams = ChainParams {
    magic: [0xfa, 0xbf, 0xb5, 0xda],
    port: 18444,
    dns_seeds: &[],
    fixed_seeds: &[],
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
    fixed_seeds: &[],
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
