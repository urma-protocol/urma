use crate::error::{Context, Error, ensure};
use ring::signature::{
    ECDSA_P256_SHA256_ASN1, ECDSA_P384_SHA384_ASN1, ED25519, RSA_PKCS1_2048_8192_SHA256,
    RSA_PKCS1_2048_8192_SHA384, RSA_PKCS1_2048_8192_SHA512, RSA_PSS_2048_8192_SHA256,
    RSA_PSS_2048_8192_SHA384, RSA_PSS_2048_8192_SHA512, UnparsedPublicKey, VerificationAlgorithm,
};
use rustls::{
    Certificate, DigitallySignedStruct, ServerName, SignatureScheme,
    client::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::SystemTime,
};

pub struct Pins {
    directory: PinDirectory,
    memory: Mutex<HashMap<String, [u8; 32]>>,
}

enum PinDirectory {
    Ephemeral,
    Persistent(PathBuf),
}

impl Pins {
    pub fn ephemeral() -> Self {
        tracing::warn!(
            "electrum certificate pins are not persisted; trust on first use lasts this session only"
        );
        Self {
            directory: PinDirectory::Ephemeral,
            memory: Mutex::new(HashMap::new()),
        }
    }

    pub fn in_directory(cache_dir: &Path) -> Result<Self, Error> {
        let directory = cache_dir.join("electrum-pins");
        if !directory.try_exists()? {
            std::fs::create_dir_all(cache_dir)?;
            urma_io::create_private_directory(&directory)?;
        }
        Ok(Self {
            directory: PinDirectory::Persistent(directory),
            memory: Mutex::new(HashMap::new()),
        })
    }

    pub fn check(&self, key: &str, digest: [u8; 32]) -> Result<(), Error> {
        let mut memory = match self.memory.lock() {
            Ok(memory) => memory,
            Err(poisoned) => {
                tracing::error!("electrum pin table lock poisoned");
                poisoned.into_inner()
            }
        };
        let known = match memory.get(key) {
            Some(pinned) => Some(*pinned),
            None => self.load(key)?,
        };
        match known {
            Some(pinned) => {
                ensure!(
                    pinned == digest,
                    "electrum server {key} presented a certificate that differs from its pinned certificate; refusing"
                );
                memory.insert(key.to_owned(), digest);
                Ok(())
            }
            None => {
                self.persist(key, digest)?;
                memory.insert(key.to_owned(), digest);
                tracing::warn!(
                    server = key,
                    pin = hex::encode(digest),
                    "electrum certificate pinned on first use"
                );
                Ok(())
            }
        }
    }

    fn load(&self, key: &str) -> Result<Option<[u8; 32]>, Error> {
        let PinDirectory::Persistent(directory) = &self.directory else {
            return Ok(None);
        };
        let path = directory.join(format!("{key}.sha256"));
        if !path.try_exists()? {
            return Ok(None);
        }
        let text = String::from_utf8(urma_io::read_bounded(&path, 128)?)?;
        let bytes = hex::decode(text.trim())?;
        Ok(Some(<[u8; 32]>::try_from(bytes.as_slice())?))
    }

    fn persist(&self, key: &str, digest: [u8; 32]) -> Result<(), Error> {
        let PinDirectory::Persistent(directory) = &self.directory else {
            return Ok(());
        };
        let path = directory.join(format!("{key}.sha256"));
        urma_io::write_new(&path, format!("{}\n", hex::encode(digest)).as_bytes())?;
        Ok(())
    }
}

pub(crate) struct Pinned {
    pub(crate) pins: Arc<Pins>,
    pub(crate) key: String,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &Certificate,
        _intermediates: &[Certificate],
        _server_name: &ServerName,
        _scts: &mut dyn Iterator<Item = &[u8]>,
        _ocsp_response: &[u8],
        _now: SystemTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let digest: [u8; 32] = Sha256::digest(&end_entity.0).into();
        match self.pins.check(&self.key, digest) {
            Ok(()) => Ok(ServerCertVerified::assertion()),
            Err(error) => {
                tracing::error!(server = %self.key, %error, "electrum certificate rejected");
                Err(rustls::Error::General(error.to_string()))
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verify_signature(message, cert, dss)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        self.verify_signature(message, cert, dss)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA256,
        ]
    }

    fn request_scts(&self) -> bool {
        false
    }
}

impl Pinned {
    fn verify_signature(
        &self,
        message: &[u8],
        cert: &Certificate,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        match verify_handshake(message, &cert.0, dss) {
            Ok(()) => Ok(HandshakeSignatureValid::assertion()),
            Err(error) => {
                tracing::error!(server = %self.key, %error, "electrum handshake signature rejected");
                Err(rustls::Error::General(error.to_string()))
            }
        }
    }
}

enum PublicKey<'a> {
    Rsa(&'a [u8]),
    P256(&'a [u8]),
    P384(&'a [u8]),
    Ed25519(&'a [u8]),
}

fn verify_handshake(
    message: &[u8],
    certificate: &[u8],
    dss: &DigitallySignedStruct,
) -> Result<(), Error> {
    let key = public_key(certificate)?;
    let (algorithm, bytes): (&'static dyn VerificationAlgorithm, &[u8]) = match (dss.scheme, key) {
        (SignatureScheme::RSA_PKCS1_SHA256, PublicKey::Rsa(k)) => (&RSA_PKCS1_2048_8192_SHA256, k),
        (SignatureScheme::RSA_PKCS1_SHA384, PublicKey::Rsa(k)) => (&RSA_PKCS1_2048_8192_SHA384, k),
        (SignatureScheme::RSA_PKCS1_SHA512, PublicKey::Rsa(k)) => (&RSA_PKCS1_2048_8192_SHA512, k),
        (SignatureScheme::RSA_PSS_SHA256, PublicKey::Rsa(k)) => (&RSA_PSS_2048_8192_SHA256, k),
        (SignatureScheme::RSA_PSS_SHA384, PublicKey::Rsa(k)) => (&RSA_PSS_2048_8192_SHA384, k),
        (SignatureScheme::RSA_PSS_SHA512, PublicKey::Rsa(k)) => (&RSA_PSS_2048_8192_SHA512, k),
        (SignatureScheme::ECDSA_NISTP256_SHA256, PublicKey::P256(k)) => {
            (&ECDSA_P256_SHA256_ASN1, k)
        }
        (SignatureScheme::ECDSA_NISTP384_SHA384, PublicKey::P384(k)) => {
            (&ECDSA_P384_SHA384_ASN1, k)
        }
        (SignatureScheme::ED25519, PublicKey::Ed25519(k)) => (&ED25519, k),
        (scheme, _) => {
            return Err(Error::Unsupported(format!(
                "handshake signature scheme {scheme:?} does not match the pinned certificate key"
            )));
        }
    };
    UnparsedPublicKey::new(algorithm, bytes)
        .verify(message, dss.signature())
        .map_err(|cause| Error::Invalid(format!("handshake signature invalid: {cause}")))
}

fn element(bytes: &[u8]) -> Result<(u8, &[u8], &[u8]), Error> {
    let tag = *bytes.first().context("certificate DER truncated")?;
    let first = *bytes.get(1).context("certificate DER truncated")?;
    let (length, header) = if first < 0x80 {
        (usize::from(first), 2)
    } else {
        let count = usize::from(first & 0x7f);
        ensure!(
            (1..=3).contains(&count),
            "certificate DER length form unsupported"
        );
        let mut length = 0_usize;
        for offset in 0..count {
            let byte = *bytes.get(2 + offset).context("certificate DER truncated")?;
            length = (length << 8) | usize::from(byte);
        }
        (length, 2 + count)
    };
    let end = header
        .checked_add(length)
        .context("certificate DER length overflow")?;
    let content = bytes
        .get(header..end)
        .context("certificate DER truncated")?;
    Ok((tag, content, &bytes[end..]))
}

fn sequence(bytes: &[u8]) -> Result<(&[u8], &[u8]), Error> {
    let (tag, content, rest) = element(bytes)?;
    ensure!(tag == 0x30, "certificate DER expected a SEQUENCE");
    Ok((content, rest))
}

fn public_key(certificate: &[u8]) -> Result<PublicKey<'_>, Error> {
    let (body, _trailer) = sequence(certificate)?;
    let (tbs, _signature) = sequence(body)?;
    let (tag, _content, after_first) = element(tbs)?;
    let mut rest = if tag == 0xA0 { after_first } else { tbs };
    for _field in 0..5 {
        let (_tag, _content, after) = element(rest)?;
        rest = after;
    }
    let (spki, _extensions) = sequence(rest)?;
    let (algorithm, key_rest) = sequence(spki)?;
    let (tag, oid, params) = element(algorithm)?;
    ensure!(tag == 0x06, "certificate key algorithm is not an OID");
    let (tag, bits, _after_key) = element(key_rest)?;
    ensure!(
        tag == 0x03 && bits.first() == Some(&0),
        "certificate key is not a byte-aligned BIT STRING"
    );
    let key = &bits[1..];
    match oid {
        [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01] => Ok(PublicKey::Rsa(key)),
        [0x2B, 0x65, 0x70] => Ok(PublicKey::Ed25519(key)),
        [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01] => {
            let (tag, curve, _after_curve) = element(params)?;
            ensure!(tag == 0x06, "certificate EC curve is not an OID");
            match curve {
                [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07] => Ok(PublicKey::P256(key)),
                [0x2B, 0x81, 0x04, 0x00, 0x22] => Ok(PublicKey::P384(key)),
                other => Err(Error::Unsupported(format!(
                    "certificate EC curve {} unsupported",
                    hex::encode(other)
                ))),
            }
        }
        other => Err(Error::Unsupported(format!(
            "certificate key algorithm {} unsupported",
            hex::encode(other)
        ))),
    }
}
