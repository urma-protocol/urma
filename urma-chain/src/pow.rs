use crate::config::{POW_HASH_BYTES, SCRYPT_LOG_N, SCRYPT_P, SCRYPT_R};
use crate::observation::{Chain, PowFunction};
use bitcoin::block::Header;
use bitcoin::consensus::encode::serialize;
use bitcoin::hashes::Hash;
use bitcoin::pow::Work;
use bitcoin::{BlockHash, CompactTarget, Target};
use std::num::TryFromIntError;

#[derive(Debug)]
pub enum PowError {
    ScryptParams(scrypt::errors::InvalidParams),
    Scrypt(scrypt::errors::InvalidOutputLen),
    InvalidTarget,
    Unmet,
    EmptyWindow,
    ShortWindow { needed: usize, got: usize },
    HeightOverflow,
    TimeOverflow,
    Width(TryFromIntError),
}

impl std::fmt::Display for PowError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ScryptParams(cause) => write!(f, "scrypt parameters: {cause}"),
            Self::Scrypt(cause) => write!(f, "scrypt output: {cause}"),
            Self::InvalidTarget => f.write_str("header target is zero or above the chain limit"),
            Self::Unmet => f.write_str("header hash does not meet its target"),
            Self::EmptyWindow => f.write_str("header window is empty"),
            Self::ShortWindow { needed, got } => {
                write!(f, "retarget needs {needed} headers, window holds {got}")
            }
            Self::HeightOverflow => f.write_str("header height overflow"),
            Self::TimeOverflow => f.write_str("header time overflow"),
            Self::Width(cause) => write!(f, "integer width: {cause}"),
        }
    }
}

impl std::error::Error for PowError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Width(cause) => Some(cause),
            Self::ScryptParams(_params) => None,
            Self::Scrypt(_length) => None,
            Self::InvalidTarget
            | Self::Unmet
            | Self::EmptyWindow
            | Self::ShortWindow { .. }
            | Self::HeightOverflow
            | Self::TimeOverflow => None,
        }
    }
}

pub fn pow_hash(header: &Header, chain: Chain) -> Result<BlockHash, PowError> {
    match chain.params().pow {
        PowFunction::Sha256d => Ok(header.block_hash()),
        PowFunction::Scrypt => {
            let bytes = serialize(header);
            let params = scrypt::Params::new(SCRYPT_LOG_N, SCRYPT_R, SCRYPT_P, POW_HASH_BYTES)
                .map_err(PowError::ScryptParams)?;
            let mut digest = [0u8; POW_HASH_BYTES];
            scrypt::scrypt(&bytes, &bytes, &params, &mut digest).map_err(PowError::Scrypt)?;
            Ok(BlockHash::from_byte_array(digest))
        }
    }
}

pub fn pow_limit(chain: Chain) -> Target {
    Target::from_compact(CompactTarget::from_consensus(chain.params().pow_limit_bits))
}

pub fn check_header_pow(header: &Header, chain: Chain) -> Result<(), PowError> {
    let target = header.target();
    if target == Target::ZERO || target > pow_limit(chain) {
        return Err(PowError::InvalidTarget);
    }
    if !target.is_met_by(pow_hash(header, chain)?) {
        return Err(PowError::Unmet);
    }
    Ok(())
}

pub fn chain_work(headers: &[Header]) -> Result<Work, PowError> {
    let Some((first, rest)) = headers.split_first() else {
        return Err(PowError::EmptyWindow);
    };
    Ok(rest
        .iter()
        .fold(first.work(), |total, header| total + header.work()))
}

pub fn expected_bits(
    chain: Chain,
    headers: &[Header],
    first_height: u64,
    next_time: u32,
) -> Result<CompactTarget, PowError> {
    let params = chain.params();
    let Some(last) = headers.last() else {
        return Err(PowError::EmptyWindow);
    };
    let last_index = headers.len() - 1;
    let last_height = first_height
        .checked_add(u64::try_from(last_index).map_err(PowError::Width)?)
        .ok_or(PowError::HeightOverflow)?;
    let next_height = last_height.checked_add(1).ok_or(PowError::HeightOverflow)?;
    let limit_bits = CompactTarget::from_consensus(params.pow_limit_bits);
    if !params.retargets {
        return Ok(last.bits);
    }
    if next_height % params.retarget_interval != 0 {
        if !params.allow_min_difficulty {
            return Ok(last.bits);
        }
        let grace = params
            .target_spacing
            .checked_mul(2)
            .and_then(|window| last.time.checked_add(window))
            .ok_or(PowError::TimeOverflow)?;
        if next_time > grace {
            return Ok(limit_bits);
        }
        return Ok(last_regular_bits(
            headers,
            last_height,
            params.retarget_interval,
            limit_bits,
        ));
    }
    let lookback = match next_height == params.retarget_interval {
        true => params.retarget_interval - 1,
        false => params.retarget_lookback,
    };
    let needed = usize::try_from(lookback).map_err(PowError::Width)? + 1;
    if headers.len() < needed {
        return Err(PowError::ShortWindow {
            needed,
            got: headers.len(),
        });
    }
    let first = &headers[headers.len() - needed];
    Ok(retarget(last, first.time, params.target_timespan, pow_limit(chain))?.to_compact_lossy())
}

fn last_regular_bits(
    headers: &[Header],
    last_height: u64,
    interval: u64,
    limit_bits: CompactTarget,
) -> CompactTarget {
    let mut index = headers.len() - 1;
    let mut height = last_height;
    while index > 0 && height % interval != 0 && headers[index].bits == limit_bits {
        index -= 1;
        height -= 1;
    }
    headers[index].bits
}

fn retarget(
    last: &Header,
    first_time: u32,
    timespan: u32,
    limit: Target,
) -> Result<Target, PowError> {
    let span = i64::from(timespan);
    let actual = (i64::from(last.time) - i64::from(first_time)).clamp(span / 4, span * 4);
    let actual = u64::try_from(actual).map_err(PowError::Width)?;
    let old = Target::from_compact(last.bits);
    let scaled = div_u64(mul_mod_2_256(limbs(old), actual)?, u64::from(timespan))?;
    let fresh = Target::from_le_bytes(bytes(scaled));
    Ok(match fresh > limit {
        true => limit,
        false => fresh,
    })
}

fn limbs(target: Target) -> [u64; 4] {
    let raw = target.to_le_bytes();
    let mut out = [0u64; 4];
    for (index, limb) in out.iter_mut().enumerate() {
        let mut word = [0u8; 8];
        word.copy_from_slice(&raw[index * 8..index * 8 + 8]);
        *limb = u64::from_le_bytes(word);
    }
    out
}

fn bytes(limbs: [u64; 4]) -> [u8; 32] {
    let mut out = [0u8; 32];
    for (index, limb) in limbs.iter().enumerate() {
        out[index * 8..index * 8 + 8].copy_from_slice(&limb.to_le_bytes());
    }
    out
}

fn mul_mod_2_256(limbs: [u64; 4], by: u64) -> Result<[u64; 4], PowError> {
    let mut carry: u128 = 0;
    let mut out = [0u64; 4];
    for (slot, limb) in out.iter_mut().zip(limbs) {
        let product = u128::from(limb) * u128::from(by) + carry;
        *slot = u64::try_from(product & u128::from(u64::MAX)).map_err(PowError::Width)?;
        carry = product >> 64;
    }
    Ok(out)
}

fn div_u64(limbs: [u64; 4], by: u64) -> Result<[u64; 4], PowError> {
    let mut remainder: u128 = 0;
    let mut out = [0u64; 4];
    for index in (0..4).rev() {
        let current = (remainder << 64) | u128::from(limbs[index]);
        out[index] = u64::try_from(current / u128::from(by)).map_err(PowError::Width)?;
        remainder = current % u128::from(by);
    }
    Ok(out)
}
