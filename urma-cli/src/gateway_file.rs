use crate::{
    gateway_host::Portal,
    gateway_http::{Refusal, Reply, Request, State},
    gateway_links::{Transformed, transform},
    gateway_pages::Subject,
};
use sha2::{Digest, Sha256};
use urma_web::grammar::is_entry_mime;

pub(crate) struct Provenance {
    pub(crate) subject: Subject,
    pub(crate) root: String,
    pub(crate) author: String,
    pub(crate) payload_sha256: String,
}

impl Provenance {
    pub(crate) fn stamp(&self, mut reply: Reply) -> Reply {
        for (name, value) in self.subject.headers() {
            reply = reply.with(name, value);
        }
        reply
            .with("URMA-Root", self.root.clone())
            .with("URMA-Author", self.author.clone())
            .with("URMA-Payload-SHA256", self.payload_sha256.clone())
    }
}

pub(crate) struct Declared {
    pub(crate) path: String,
    pub(crate) mime: String,
    pub(crate) sha256: String,
    pub(crate) bytes: Vec<u8>,
}

pub(crate) struct Serving<'a> {
    pub(crate) portal: &'a Portal,
    pub(crate) max_age: u64,
    pub(crate) html_memory: usize,
}

enum Linked {
    Verbatim(Vec<u8>),
    Unchanged(Vec<u8>),
    Rewritten(Vec<u8>),
}

impl Serving<'_> {
    pub(crate) const TRANSFORM: &'static str = "links-v1";

    pub(crate) fn file(
        &self,
        provenance: &Provenance,
        declared: Declared,
        request: &Request,
    ) -> Result<Reply, Refusal> {
        let Declared {
            path,
            mime,
            sha256,
            bytes,
        } = declared;
        if hex::encode(Sha256::digest(&bytes)) != sha256 {
            return Err(Refusal::new(
                State::VerificationFailed,
                format!("{path}: bytes differ from the declared SHA-256 {sha256}"),
            ));
        }
        let site = |body: Vec<u8>| Reply::site(200, &mime, self.max_age, body);
        let (reply, digest) = match self.linked(&mime, bytes) {
            Linked::Verbatim(body) => (site(body), sha256),
            Linked::Unchanged(body) => (marked(site(body), &sha256), sha256),
            Linked::Rewritten(body) => {
                let digest = hex::encode(Sha256::digest(&body));
                (marked(site(body), &sha256), digest)
            }
        };
        let etag = format!("\"{digest}\"");
        let reply = provenance
            .stamp(reply)
            .with("URMA-Path", path)
            .with("URMA-SHA256", digest)
            .with("ETag", etag.clone());
        if request.validates(&etag) {
            return Ok(reply.not_modified());
        }
        Ok(reply)
    }

    fn linked(&self, mime: &str, bytes: Vec<u8>) -> Linked {
        if !is_entry_mime(mime) {
            return Linked::Verbatim(bytes);
        }
        match transform(&bytes, self.portal, self.html_memory) {
            Ok(Transformed::Rewritten(rewritten)) => Linked::Rewritten(rewritten),
            Ok(Transformed::Unchanged) => Linked::Unchanged(bytes),
            Err(cause) => {
                tracing::warn!(target: "urma_gateway", error = %cause, "links-v1 transform failed; serving the verified original bytes without URMA-Transform");
                Linked::Verbatim(bytes)
            }
        }
    }
}

fn marked(reply: Reply, original: &str) -> Reply {
    reply
        .with("URMA-Transform", Serving::TRANSFORM.to_owned())
        .with("URMA-Original-SHA256", original.to_owned())
}
