use crate::error::{Error, ensure};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Topics {
    pub wire: String,
    pub hashtags: Vec<String>,
}

impl Topics {
    pub const MAX_LABEL_BYTES: usize = 32;
    pub const MAX_HASHTAGS: usize = 8;

    pub fn validate(&self) -> Result<(), Error> {
        if !self.wire.is_empty() {
            Self::validate_label(&self.wire)?;
        }
        ensure!(
            self.hashtags.len() <= Self::MAX_HASHTAGS,
            "at most 8 hashtags"
        );
        for tag in &self.hashtags {
            Self::validate_label(tag)?;
        }
        ensure!(
            self.hashtags.windows(2).all(|pair| pair[0] < pair[1]),
            "hashtags must be unique and sorted"
        );
        Ok(())
    }

    pub fn validate_label(label: &str) -> Result<(), Error> {
        let bytes = label.as_bytes();
        ensure!(
            (1..=Self::MAX_LABEL_BYTES).contains(&bytes.len()),
            "label must be 1..32 bytes"
        );
        ensure!(
            bytes[0].is_ascii_lowercase() || bytes[0].is_ascii_digit(),
            "label must start with a lowercase letter or digit"
        );
        ensure!(
            bytes.iter().all(|byte| byte.is_ascii_lowercase()
                || byte.is_ascii_digit()
                || *byte == b'-'
                || *byte == b'_'),
            "label permits only lowercase ASCII letters, digits, - and _"
        );
        Ok(())
    }

    pub fn encode_body(&self, text: &str) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut bytes = Vec::new();
        bytes.push(u8::try_from(self.wire.len())?);
        bytes.extend_from_slice(self.wire.as_bytes());
        bytes.push(u8::try_from(self.hashtags.len())?);
        for tag in &self.hashtags {
            bytes.push(u8::try_from(tag.len())?);
            bytes.extend_from_slice(tag.as_bytes());
        }
        bytes.extend_from_slice(&u16::try_from(text.len())?.to_le_bytes());
        bytes.extend_from_slice(text.as_bytes());
        Ok(bytes)
    }

    pub fn decode_body(mut bytes: &[u8]) -> Result<(Self, String), Error> {
        let wire_length = usize::from(take(&mut bytes, 1)?[0]);
        ensure!(
            wire_length <= Self::MAX_LABEL_BYTES,
            "wire exceeds 32 bytes"
        );
        let wire = std::str::from_utf8(take(&mut bytes, wire_length)?)?.to_owned();
        let count = usize::from(take(&mut bytes, 1)?[0]);
        ensure!(count <= Self::MAX_HASHTAGS, "at most 8 hashtags");
        let mut hashtags = Vec::with_capacity(count);
        for _ in 0..count {
            hashtags.push(read_label(&mut bytes)?);
        }
        let length = usize::from(u16::from_le_bytes(take(&mut bytes, 2)?.try_into()?));
        let text = std::str::from_utf8(take(&mut bytes, length)?)?.to_owned();
        ensure!(bytes.is_empty(), "trailing structured record bytes");
        let topics = Self { wire, hashtags };
        topics.validate()?;
        Ok((topics, text))
    }
}

fn take<'a>(bytes: &mut &'a [u8], length: usize) -> Result<&'a [u8], Error> {
    ensure!(bytes.len() >= length, "truncated structured record");
    let (head, tail) = bytes.split_at(length);
    *bytes = tail;
    Ok(head)
}

fn read_label(bytes: &mut &[u8]) -> Result<String, Error> {
    let length = usize::from(take(bytes, 1)?[0]);
    ensure!(
        (1..=Topics::MAX_LABEL_BYTES).contains(&length),
        "label must be 1..32 bytes"
    );
    Ok(std::str::from_utf8(take(bytes, length)?)?.to_owned())
}
