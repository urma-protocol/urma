use bitcoin::Txid;
use clap::ValueEnum;
use std::{
    collections::BTreeMap,
    fmt::{Display, Formatter},
};
use urma_chain::observation::Chain;
use urma_names::name::Name;
use urma_runtime::error::{Error, ensure};

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum Suffix {
    Ltc,
    Btc,
    Tltc,
    Tbtc,
}

impl Suffix {
    pub(crate) const ALL: [Self; 4] = [Self::Ltc, Self::Btc, Self::Tltc, Self::Tbtc];

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Ltc => "ltc",
            Self::Btc => "btc",
            Self::Tltc => "tltc",
            Self::Tbtc => "tbtc",
        }
    }

    pub(crate) fn parse(label: &str) -> Result<Self, HostError> {
        for suffix in Self::ALL {
            if suffix.label() == label {
                return Ok(suffix);
            }
        }
        Err(HostError::Suffix(label.to_owned()))
    }

    pub(crate) fn chain(self) -> Result<Chain, Error> {
        match self {
            Self::Ltc => Ok(Chain::LitecoinMainnet),
            Self::Tltc => Ok(Chain::LitecoinTestnet),
            Self::Tbtc => Ok(Chain::BitcoinTestnet4),
            Self::Btc => Err(Error::Unsupported(
                "the .btc suffix names bitcoin mainnet, which this runtime does not support".into(),
            )),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub(crate) enum LinkScheme {
    Http,
    Https,
}

impl LinkScheme {
    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Https => "https",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PublicPort {
    Default,
    Explicit(u16),
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HostError {
    Malformed(String),
    Suffix(String),
    Name(String),
    Publication,
    Registry,
}

impl Display for HostError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Malformed(detail) => write!(formatter, "malformed host: {detail}"),
            Self::Suffix(label) => write!(
                formatter,
                "unknown network suffix {label:?}; URMA suffixes are ltc, btc, tltc and tbtc"
            ),
            Self::Name(cause) => write!(formatter, "not a registry name: {cause}"),
            Self::Publication => formatter.write_str(
                "publication (TXID) hosts are not served; this portal serves registry names only",
            ),
            Self::Registry => formatter.write_str(
                "explicit-registry hosts are not served; this portal serves <name>.<suffix> hosts of its registry",
            ),
        }
    }
}

impl std::error::Error for HostError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SiteHost {
    pub(crate) name: Name,
    pub(crate) suffix: Suffix,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Host {
    Apex,
    Site(SiteHost),
    Foreign,
}

#[derive(Debug)]
pub(crate) struct Portal {
    domain: String,
    scheme: LinkScheme,
    port: PublicPort,
    registries: BTreeMap<Suffix, Txid>,
}

impl Portal {
    pub(crate) const MAX_HOST_BYTES: usize = 253;

    pub(crate) fn new(
        domain: &str,
        scheme: LinkScheme,
        port: PublicPort,
        registries: BTreeMap<Suffix, Txid>,
    ) -> Result<Self, Error> {
        ensure!(
            (1..=Self::MAX_HOST_BYTES).contains(&domain.len()),
            "portal domain must be 1..253 bytes"
        );
        for label in domain.split('.') {
            ensure!(
                is_dns_label(label),
                "portal domain {domain:?} must be lowercase DNS labels (a-z, 0-9, hyphen)"
            );
        }
        ensure!(
            !registries.is_empty(),
            "configure at least one registry with --registry <suffix>=<genesis>"
        );
        Ok(Self {
            domain: domain.to_owned(),
            scheme,
            port,
            registries,
        })
    }

    pub(crate) fn domain(&self) -> &str {
        &self.domain
    }

    pub(crate) fn registries(&self) -> &BTreeMap<Suffix, Txid> {
        &self.registries
    }

    pub(crate) fn serves(&self, suffix: Suffix) -> bool {
        self.registries.contains_key(&suffix)
    }

    pub(crate) fn is_registry(&self, suffix: Suffix, genesis: &str) -> bool {
        let Some(configured) = self.registries.get(&suffix) else {
            return false;
        };
        configured.to_string() == genesis
    }

    pub(crate) fn apex_origin(&self) -> String {
        self.origin(&self.domain)
    }

    pub(crate) fn site_origin(&self, name: &Name, suffix: Suffix) -> String {
        self.origin(&format!("{name}.{}.{}", suffix.label(), self.domain))
    }

    pub(crate) fn unavailable(&self, original: &str) -> String {
        let encoded: String = url::form_urlencoded::byte_serialize(original.as_bytes()).collect();
        format!("{}/unavailable?u={encoded}", self.apex_origin())
    }

    fn origin(&self, host: &str) -> String {
        match self.port {
            PublicPort::Default => format!("{}://{host}", self.scheme.label()),
            PublicPort::Explicit(port) => format!("{}://{host}:{port}", self.scheme.label()),
        }
    }
}

fn is_dns_label(label: &str) -> bool {
    (1..=Name::MAX_BYTES).contains(&label.len())
        && label
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
}

pub(crate) fn is_txid(label: &str) -> bool {
    label.len() == 64
        && label
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

pub(crate) fn authority(header: &str) -> Result<String, HostError> {
    let host = without_port(header)?;
    if host.is_empty() || host.len() > Portal::MAX_HOST_BYTES {
        return Err(HostError::Malformed(format!(
            "host must be 1..{} bytes",
            Portal::MAX_HOST_BYTES
        )));
    }
    if !host.bytes().all(|byte| byte.is_ascii_graphic()) {
        return Err(HostError::Malformed(
            "host carries a space, a control byte or non-ASCII".into(),
        ));
    }
    Ok(host.to_ascii_lowercase())
}

fn without_port(header: &str) -> Result<&str, HostError> {
    if header.starts_with('[') {
        let Some(end) = header.find(']') else {
            return Err(HostError::Malformed("unterminated IPv6 literal".into()));
        };
        let (literal, rest) = header.split_at(end + 1);
        check_port(rest, rest.strip_prefix(':'))?;
        return Ok(literal);
    }
    let Some((host, port)) = header.rsplit_once(':') else {
        return Ok(header);
    };
    check_port(port, Some(port))?;
    Ok(host)
}

fn check_port(rest: &str, digits: Option<&str>) -> Result<(), HostError> {
    if rest.is_empty() {
        return Ok(());
    }
    let Some(digits) = digits else {
        return Err(HostError::Malformed("bytes after the IPv6 literal".into()));
    };
    if digits.is_empty() || digits.len() > 5 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(HostError::Malformed(format!("invalid port {digits:?}")));
    }
    Ok(())
}

pub(crate) fn classify(host: &str, portal: &Portal) -> Result<Host, HostError> {
    if host == portal.domain {
        return Ok(Host::Apex);
    }
    let Some(prefix) = host.strip_suffix(portal.domain.as_str()) else {
        return Ok(Host::Foreign);
    };
    let Some(labels) = prefix.strip_suffix('.') else {
        return Ok(Host::Foreign);
    };
    Ok(Host::Site(site(labels)?))
}

fn site(labels: &str) -> Result<SiteHost, HostError> {
    let parts: Vec<&str> = labels.split('.').collect();
    if parts.iter().any(|part| part.is_empty()) {
        return Err(HostError::Malformed("empty label".into()));
    }
    match parts.as_slice() {
        [name, suffix] => {
            let suffix = Suffix::parse(suffix)?;
            if is_txid(name) {
                return Err(HostError::Publication);
            }
            let name = Name::parse(name).map_err(|cause| HostError::Name(cause.to_string()))?;
            Ok(SiteHost { name, suffix })
        }
        [first, second, third] if is_txid(first) => {
            Suffix::parse(third)?;
            Name::parse(second).map_err(|cause| HostError::Name(cause.to_string()))?;
            Err(HostError::Registry)
        }
        [single] => Err(HostError::Malformed(format!(
            "{single:?} has no name before the suffix"
        ))),
        other => Err(HostError::Malformed(format!(
            "{} labels before the portal domain; expected <name>.<suffix>",
            other.len()
        ))),
    }
}
