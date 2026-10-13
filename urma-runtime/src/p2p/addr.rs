use crate::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) fn unix_now() -> Result<u64, Error> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|error| {
            Error::Invalid(format!("system clock precedes the unix epoch: {error}"))
        })?;
    Ok(elapsed.as_secs())
}

fn routable_v4(ip: Ipv4Addr) -> bool {
    let [first, second, ..] = ip.octets();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_broadcast()
        || ip.is_documentation()
        || ip.is_multicast()
        || first == 0
        || first >= 240
        || (first == 100 && (64..128).contains(&second))
        || (first == 198 && (second & 0xfe) == 18))
}

fn routable_v6(ip: Ipv6Addr) -> bool {
    match ip.to_ipv4_mapped() {
        Some(mapped) => routable_v4(mapped),
        None => routable_native_v6(ip),
    }
}

fn routable_native_v6(ip: Ipv6Addr) -> bool {
    let [first, second, ..] = ip.segments();
    !(ip.is_unspecified()
        || ip.is_loopback()
        || ip.is_multicast()
        || (first & 0xfe00) == 0xfc00
        || (first & 0xffc0) == 0xfe80
        || (first == 0x2001 && second == 0x0db8))
}

pub(super) fn routable(address: &SocketAddr) -> bool {
    address.port() != 0
        && match address.ip() {
            IpAddr::V4(ip) => routable_v4(ip),
            IpAddr::V6(ip) => routable_v6(ip),
        }
}
