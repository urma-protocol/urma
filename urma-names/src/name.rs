use serde::{Deserialize, Serialize};
use std::fmt::{Display, Formatter};
use urma_core::error::{Error, ensure};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Name(String);

impl Name {
    pub const MAX_BYTES: usize = 63;

    pub fn parse(text: &str) -> Result<Self, Error> {
        let bytes = text.as_bytes();
        ensure!(
            (1..=Self::MAX_BYTES).contains(&bytes.len()),
            "name must be 1..63 bytes"
        );
        ensure!(
            bytes
                .iter()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-'),
            "name bytes must be a-z, 0-9 or hyphen"
        );
        ensure!(
            bytes[0] != b'-' && bytes[bytes.len() - 1] != b'-',
            "name cannot start or end with a hyphen"
        );
        ensure!(
            bytes.len() < 4 || bytes[2..4] != *b"--",
            "name cannot carry a double hyphen at bytes 3-4"
        );
        Ok(Self(text.to_owned()))
    }

    pub fn normalize(text: &str) -> Result<Self, Error> {
        Self::parse(&text.to_ascii_lowercase())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl TryFrom<String> for Name {
    type Error = Error;

    fn try_from(text: String) -> Result<Self, Error> {
        Self::parse(&text)
    }
}

impl From<Name> for String {
    fn from(name: Name) -> Self {
        name.0
    }
}

impl Display for Name {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}
