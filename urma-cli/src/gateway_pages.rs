use crate::gateway_host::Portal;
use std::fmt::{Display, Formatter};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct IndexPoint {
    pub(crate) height: u64,
    pub(crate) block_hash: String,
}

impl Display for IndexPoint {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{} {}", self.height, self.block_hash)
    }
}

#[derive(Clone, Debug)]
pub(crate) struct Subject {
    pub(crate) name: String,
    pub(crate) suffix: &'static str,
    pub(crate) network: Option<String>,
    pub(crate) registry: Option<String>,
    pub(crate) index: Option<IndexPoint>,
}

impl Subject {
    pub(crate) fn new(name: String, suffix: &'static str) -> Self {
        Self {
            name,
            suffix,
            network: None,
            registry: None,
            index: None,
        }
    }

    pub(crate) fn address(&self) -> String {
        format!("urma://{}.{}/", self.name, self.suffix)
    }

    pub(crate) fn headers(&self) -> Vec<(&'static str, String)> {
        let mut headers = Vec::new();
        for network in self.network.iter() {
            headers.push(("URMA-Network", network.clone()));
        }
        for registry in self.registry.iter() {
            headers.push(("URMA-Registry", registry.clone()));
        }
        headers.push(("URMA-Name", self.name.clone()));
        for index in self.index.iter() {
            headers.push(("URMA-Index", index.to_string()));
        }
        headers
    }

    fn facts(&self) -> String {
        let mut facts = format!(
            "<span>Name</span><code>{}.{}</code>",
            escape(&self.name),
            escape(self.suffix)
        );
        for network in self.network.iter() {
            facts.push_str(&format!(
                "<span>Network</span><code>{}</code>",
                escape(network)
            ));
        }
        for registry in self.registry.iter() {
            facts.push_str(&format!(
                "<span>Registry</span><code>{}</code>",
                escape(registry)
            ));
        }
        for index in self.index.iter() {
            facts.push_str(&format!(
                "<span>Index height</span><span>{} (block <code>{}</code>)</span>",
                index.height,
                escape(&index.block_hash)
            ));
        }
        facts
    }
}

pub(crate) struct ListedName {
    pub(crate) name: String,
    pub(crate) url: String,
    pub(crate) root: String,
    pub(crate) expiry: u64,
}

pub(crate) enum ListingState {
    Pending(String),
    Ready {
        index: IndexPoint,
        tip: u64,
        names: Vec<ListedName>,
    },
    Behind {
        index: IndexPoint,
        tip: u64,
        reason: String,
    },
}

pub(crate) struct Listing {
    pub(crate) suffix: &'static str,
    pub(crate) network: String,
    pub(crate) registry: String,
    pub(crate) state: ListingState,
}

struct Page;

impl Page {
    const STYLE: &'static str = "body{margin:0;font:16px/1.55 system-ui,-apple-system,Segoe UI,sans-serif;background:#f6f5f1;color:#1f1e1b}main{max-width:46rem;margin:3rem auto;padding:0 1rem}h1{font-size:1.6rem;margin:0 0 1rem}h2{font-size:1.15rem;margin:2rem 0 .5rem}code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:.9em;word-break:break-all}a{color:#0b5cad}ul{padding-left:1.2rem}li{margin:.35rem 0}.note{color:#5e5b53;font-size:.92rem}.facts{display:grid;grid-template-columns:max-content 1fr;gap:.2rem 1rem}@media (prefers-color-scheme:dark){body{background:#161614;color:#e9e7e1}a{color:#7db7ff}.note{color:#a8a49a}}";
}

pub(crate) fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            other => escaped.push(other),
        }
    }
    escaped
}

fn document(title: &str, body: &str) -> String {
    format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n<title>{}</title>\n<style>{}</style>\n</head>\n<body>\n<main>\n{body}\n</main>\n</body>\n</html>\n",
        escape(title),
        Page::STYLE
    )
}

fn failure(status: u16, title: &str, detail: &str, facts: &str, closing: &str) -> String {
    document(
        &format!("{status} {title}"),
        &format!(
            "<h1>{status} {}</h1>\n<p>{}</p>\n<div class=\"facts\">{facts}</div>\n{closing}<p class=\"note\">URMA portal</p>",
            escape(title),
            escape(detail)
        ),
    )
}

fn state_fact(state: &str) -> String {
    format!("<span>State</span><code>{}</code>", escape(state))
}

pub(crate) fn error_page(status: u16, title: &str, state: &str, detail: &str) -> String {
    failure(status, title, detail, &state_fact(state), "")
}

pub(crate) fn name_error_page(
    status: u16,
    title: &str,
    state: &str,
    detail: &str,
    subject: &Subject,
) -> String {
    let facts = format!("{}{}", state_fact(state), subject.facts());
    let closing = format!(
        "<p>The URMA browser opens this site as <code>{}</code> and checks the registry and the publication itself.</p>\n",
        escape(&subject.address())
    );
    failure(status, title, detail, &facts, &closing)
}

fn names_list(names: &[ListedName]) -> String {
    if names.is_empty() {
        return "<p class=\"note\">No name is bound to a publication.</p>".to_owned();
    }
    let mut items = String::from("<ul>\n");
    for listed in names {
        items.push_str(&format!(
            "<li><a href=\"{}\">{}</a> <span class=\"note\">root <code>{}</code>, expires at block {}</span></li>\n",
            escape(&listed.url),
            escape(&listed.name),
            escape(&listed.root),
            listed.expiry
        ));
    }
    items.push_str("</ul>");
    items
}

fn indexed(index: &IndexPoint, tip: u64) -> String {
    format!(
        "<span>Indexed height</span><span>{} (chain tip {tip})</span><span>Block</span><code>{}</code>",
        index.height,
        escape(&index.block_hash)
    )
}

fn listing_section(listing: &Listing) -> String {
    let heading = format!(
        "<h2>.{} — {}</h2>\n<div class=\"facts\"><span>Registry</span><code>{}</code>",
        escape(listing.suffix),
        escape(&listing.network),
        escape(&listing.registry)
    );
    match &listing.state {
        ListingState::Pending(reason) => format!(
            "{heading}<span>Index</span><span>not ready: {}</span></div>",
            escape(reason)
        ),
        ListingState::Ready { index, tip, names } => {
            format!(
                "{heading}{}</div>\n{}",
                indexed(index, *tip),
                names_list(names)
            )
        }
        ListingState::Behind { index, tip, reason } => format!(
            "{heading}{}<span>Index</span><span>behind: {}</span></div>\n<p class=\"note\">Names of this network answer 503 until its index is current again.</p>",
            indexed(index, *tip),
            escape(reason)
        ),
    }
}

pub(crate) fn index_page(portal: &Portal, listings: &[Listing]) -> String {
    let mut body = format!(
        "<h1>URMA portal — {}</h1>\n<p>This portal serves URMA web publications bound to names of one registry per network. Every file is re-verified against its on-chain publication before it is served; each name host answers <code>/.well-known/urma/proof</code> with the evidence.</p>",
        escape(portal.domain())
    );
    for listing in listings {
        body.push_str(&listing_section(listing));
    }
    document(&format!("URMA portal — {}", portal.domain()), &body)
}

pub(crate) fn unavailable_page(portal: &Portal, originals: &[String]) -> String {
    let mut body = String::from(
        "<h1>Not available on this portal</h1>\n<p>The link you followed names a URMA publication by transaction ID or through another registry. This portal serves only names of its configured registries; open the link in a URMA browser instead.</p>",
    );
    if !originals.is_empty() {
        body.push_str("\n<ul>\n");
        for original in originals {
            body.push_str(&format!("<li><code>{}</code></li>\n", escape(original)));
        }
        body.push_str("</ul>");
    }
    body.push_str(&format!(
        "\n<p><a href=\"{}/\">Portal index</a></p>",
        escape(&portal.apex_origin())
    ));
    document("Not available on this portal", &body)
}
