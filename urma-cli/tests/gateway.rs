#[path = "../src/gateway_file.rs"]
mod gateway_file;
#[path = "../src/gateway_host.rs"]
mod gateway_host;
#[path = "../src/gateway_http.rs"]
mod gateway_http;
#[path = "../src/gateway_links.rs"]
mod gateway_links;
#[path = "../src/gateway_pages.rs"]
mod gateway_pages;
#[path = "../src/gateway_route.rs"]
mod gateway_route;

use anyhow::{Context, Result};
use bitcoin::{Txid, XOnlyPublicKey};
use gateway_file::{Declared, Provenance, Serving};
use gateway_host::{
    Host, HostError, LinkScheme, Portal, PublicPort, SiteHost, Suffix, authority, classify, is_txid,
};
use gateway_http::{HttpLimits, Method, Refusal, Reply, Request, State, accept_loop};
use gateway_links::{Rewrite, Transformed, rewrite, transform};
use gateway_pages::{
    IndexPoint, ListedName, Listing, ListingState, Subject, index_page, unavailable_page,
};
use gateway_route::{Currency, Freshness, Route, Scan, route, split_target, standing};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    time::{Duration, Instant},
};
use urma_chain::observation::Chain;
use urma_names::{
    name::Name,
    state::{Bound, Resolution, Target},
};
use urma_web::package::{FileEntry, Package, PinnedEntry};

const ROSINT: &str = "4c53ebbea660c206c4a09d4ccc48479950d7300e39876c9772b2f72ca232d1e3";
const OTHER: &str = "1111111111111111111111111111111111111111111111111111111111111111";
const ROOT: &str = "e5ef78d5fe042c2b7c646d9ab03256a4c0d479a8032adca1e88425f99e4fef1a";
const AUTHOR: &str = "986514fb8d4da75550980a77764dfd1dcadf76ca374192560e0b690183fcf251";
const PAYLOAD: &str = "9e33a615b5343d6d81b8a686ac6eb0d7675ede101d5dccd4806706375eaecac0";
const BLOCK: &str = "0000000000000a1b2c3d4e5f60718293a4b5c6d7e8f9011223344556677889900";
const MEMORY: usize = 16 * 1024 * 1024;
const SITE_CSP: &str = "default-src 'self'; script-src 'self' 'unsafe-inline' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; font-src 'self'; connect-src 'self'; worker-src 'self'; frame-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'self'";
const PORTAL_CSP: &str = "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'";
const HSTS: &str = "max-age=31536000; includeSubDomains";
const FEATURES: [&str; 27] = [
    "accelerometer",
    "ambient-light-sensor",
    "attribution-reporting",
    "bluetooth",
    "browsing-topics",
    "camera",
    "clipboard-read",
    "display-capture",
    "geolocation",
    "gyroscope",
    "hid",
    "identity-credentials-get",
    "idle-detection",
    "local-fonts",
    "magnetometer",
    "microphone",
    "midi",
    "otp-credentials",
    "payment",
    "publickey-credentials-create",
    "publickey-credentials-get",
    "screen-wake-lock",
    "serial",
    "storage-access",
    "usb",
    "window-management",
    "xr-spatial-tracking",
];

fn portal(domain: &str, scheme: LinkScheme, port: PublicPort) -> Result<Portal> {
    let mut registries = BTreeMap::new();
    registries.insert(Suffix::Tltc, ROSINT.parse::<Txid>()?);
    Ok(Portal::new(domain, scheme, port, registries)?)
}

fn public() -> Result<Portal> {
    portal("portal.example", LinkScheme::Https, PublicPort::Default)
}

fn local() -> Result<Portal> {
    portal("localhost", LinkScheme::Http, PublicPort::Explicit(8080))
}

fn site(name: &str, suffix: Suffix) -> Result<Host> {
    Ok(Host::Site(SiteHost {
        name: Name::parse(name)?,
        suffix,
    }))
}

fn to(url: &str) -> Rewrite {
    Rewrite::To(url.to_owned())
}

#[test]
fn suffixes_round_trip_and_map_to_supported_chains() -> Result<()> {
    for suffix in Suffix::ALL {
        assert_eq!(Suffix::parse(suffix.label()), Ok(suffix));
    }
    assert_eq!(Suffix::parse("TLTC"), Err(HostError::Suffix("TLTC".into())));
    assert_eq!(Suffix::parse("doge"), Err(HostError::Suffix("doge".into())));
    assert!(matches!(Suffix::Ltc.chain()?, Chain::LitecoinMainnet));
    assert!(matches!(Suffix::Tltc.chain()?, Chain::LitecoinTestnet));
    assert!(matches!(Suffix::Tbtc.chain()?, Chain::BitcoinTestnet4));
    assert!(Suffix::Btc.chain().is_err());
    Ok(())
}

#[test]
fn host_headers_lose_their_port_but_keep_their_case() -> Result<()> {
    assert_eq!(
        authority("HelloWorld.TLTC.localhost:8080")?,
        "HelloWorld.TLTC.localhost"
    );
    assert_eq!(authority("portal.example")?, "portal.example");
    assert_eq!(authority("portal.example:")?, "portal.example");
    assert_eq!(authority("[::1]:8080")?, "[::1]");
    assert_eq!(authority("[::1]")?, "[::1]");
    let long = "a".repeat(254);
    for bad in [
        "",
        ":8080",
        "a b",
        "host:80x",
        "host:123456",
        "[::1",
        "[::1]x",
        "caf\u{e9}.tltc.localhost",
        "tab\t.tltc.localhost",
        long.as_str(),
    ] {
        assert!(authority(bad).is_err(), "{bad:?}");
    }
    Ok(())
}

#[test]
fn hosts_classify_as_apex_name_or_foreign() -> Result<()> {
    let portal = public()?;
    assert_eq!(classify("portal.example", &portal)?, Host::Apex);
    assert_eq!(
        classify("helloworld.tltc.portal.example", &portal)?,
        site("helloworld", Suffix::Tltc)?
    );
    assert_eq!(
        classify("urma.ltc.portal.example", &portal)?,
        site("urma", Suffix::Ltc)?
    );
    let longest = "z".repeat(63);
    assert_eq!(
        classify(&format!("{longest}.tbtc.portal.example"), &portal)?,
        site(&longest, Suffix::Tbtc)?
    );
    for foreign in [
        "example.com",
        "xportal.example",
        "portal.example.evil",
        "helloworld.tltc.portal.example.",
        "helloworld.tltc.Portal.Example",
        "PORTAL.EXAMPLE",
        "localhost",
        "[::1]",
    ] {
        assert_eq!(classify(foreign, &portal)?, Host::Foreign, "{foreign}");
    }
    Ok(())
}

#[test]
fn txid_registry_and_malformed_hosts_are_refused() -> Result<()> {
    let portal = public()?;
    let refused = |host: &str| classify(host, &portal);
    assert_eq!(
        refused(&format!("{ROOT}.tltc.portal.example")),
        Err(HostError::Publication)
    );
    assert_eq!(
        refused(&format!("{ROSINT}.helloworld.tltc.portal.example")),
        Err(HostError::Registry)
    );
    for malformed in [
        "tltc.portal.example",
        "a.b.tltc.portal.example",
        "hello..tltc.portal.example",
        ".tltc.portal.example",
    ] {
        assert!(
            matches!(refused(malformed), Err(HostError::Malformed(..))),
            "{malformed}"
        );
    }
    assert_eq!(
        refused("hello.xyz.portal.example"),
        Err(HostError::Suffix("xyz".into()))
    );
    assert_eq!(
        refused("helloworld.TLTC.portal.example"),
        Err(HostError::Suffix("TLTC".into()))
    );
    let overlong = "g".repeat(64);
    for name in [
        "-bad",
        "bad-",
        "ab--cd",
        "under_score",
        "HelloWorld",
        overlong.as_str(),
    ] {
        assert!(
            matches!(
                refused(&format!("{name}.tltc.portal.example")),
                Err(HostError::Name(..))
            ),
            "{name}"
        );
    }
    assert!(
        HostError::Publication
            .to_string()
            .contains("registry names only")
    );
    Ok(())
}

#[test]
fn portals_validate_their_domain_and_format_origins() -> Result<()> {
    for domain in [
        "Portal.Example",
        "",
        "portal..example",
        "portal.example.",
        "portal_example",
    ] {
        assert!(
            portal(domain, LinkScheme::Https, PublicPort::Default).is_err(),
            "{domain:?}"
        );
    }
    assert!(
        Portal::new(
            "portal.example",
            LinkScheme::Https,
            PublicPort::Default,
            BTreeMap::new()
        )
        .is_err()
    );
    let public = public()?;
    assert_eq!(public.domain(), "portal.example");
    assert_eq!(public.registries().len(), 1);
    assert_eq!(public.apex_origin(), "https://portal.example");
    assert_eq!(
        public.site_origin(&Name::parse("urma")?, Suffix::Tltc),
        "https://urma.tltc.portal.example"
    );
    assert!(public.serves(Suffix::Tltc));
    assert!(!public.serves(Suffix::Ltc));
    assert!(public.is_registry(Suffix::Tltc, ROSINT));
    assert!(!public.is_registry(Suffix::Tltc, OTHER));
    assert!(!public.is_registry(Suffix::Ltc, ROSINT));
    let local = local()?;
    assert_eq!(local.apex_origin(), "http://localhost:8080");
    assert_eq!(
        local.unavailable("urma://x y&z"),
        "http://localhost:8080/unavailable?u=urma%3A%2F%2Fx+y%26z"
    );
    assert!(is_txid(ROOT));
    assert!(!is_txid(&ROOT.to_uppercase()));
    assert!(!is_txid(&ROOT[1..]));
    Ok(())
}

#[test]
fn name_links_map_to_name_hosts_keeping_path_query_and_fragment() -> Result<()> {
    let portal = public()?;
    let explicit = format!("urma://{ROSINT}.urma.tltc/how.html");
    let cases = [
        (
            "urma://helloworld.tltc/",
            "https://helloworld.tltc.portal.example/",
        ),
        (
            "urma://helloworld.tltc",
            "https://helloworld.tltc.portal.example/",
        ),
        (
            "urma://helloworld.tltc/a/b.html?x=1&y=2#part",
            "https://helloworld.tltc.portal.example/a/b.html?x=1&y=2#part",
        ),
        (
            "urma://helloworld.tltc?x=1",
            "https://helloworld.tltc.portal.example/?x=1",
        ),
        (
            "urma://helloworld.tltc#top",
            "https://helloworld.tltc.portal.example/#top",
        ),
        (
            explicit.as_str(),
            "https://urma.tltc.portal.example/how.html",
        ),
    ];
    for (link, expected) in cases {
        assert_eq!(rewrite(link, &portal), to(expected), "{link}");
    }
    assert_eq!(
        rewrite("urma://urma.tltc/how.html", &local()?),
        to("http://urma.tltc.localhost:8080/how.html")
    );
    Ok(())
}

#[test]
fn txid_foreign_registry_and_unserved_network_links_go_to_unavailable() -> Result<()> {
    let portal = public()?;
    assert_eq!(
        rewrite(&format!("urma://{ROOT}.tltc/x"), &portal),
        to(&format!(
            "https://portal.example/unavailable?u=urma%3A%2F%2F{ROOT}.tltc%2Fx"
        ))
    );
    for link in [
        format!("urma://{OTHER}.helloworld.tltc/"),
        "urma://helloworld.ltc/".to_owned(),
        format!("urma://{ROSINT}.helloworld.ltc/"),
        format!("urma://{ROOT}.btc/"),
    ] {
        let encoded: String = url::form_urlencoded::byte_serialize(link.as_bytes()).collect();
        assert_eq!(
            rewrite(&link, &portal),
            to(&format!("https://portal.example/unavailable?u={encoded}")),
            "{link}"
        );
    }
    Ok(())
}

#[test]
fn non_canonical_and_other_values_are_left_untouched() -> Result<()> {
    let portal = public()?;
    let upper_genesis = format!("urma://{}.helloworld.tltc/", ROSINT.to_uppercase());
    for value in [
        "urma://HelloWorld.tltc/",
        "URMA://helloworld.tltc/",
        "Urma://helloworld.tltc/",
        "urma://user@helloworld.tltc/",
        "urma://helloworld.tltc:8080/",
        "urma://hello%77orld.tltc/",
        "urma://helloworld..tltc/",
        "urma://helloworld.tltc./",
        "urma://.helloworld.tltc/",
        "urma:///path",
        "urma://",
        "urma://helloworld.com/",
        "urma://-bad.tltc/",
        "urma://a.b.tltc/",
        "urma://a.b.c.tltc/",
        " urma://helloworld.tltc/",
        "urma:helloworld.tltc",
        "style.css",
        "/about.html",
        "https://example.com/",
        "#top",
        "",
        upper_genesis.as_str(),
    ] {
        assert_eq!(rewrite(value, &portal), Rewrite::Keep, "{value:?}");
    }
    Ok(())
}

#[test]
fn transform_rewrites_only_navigation_attributes() -> Result<()> {
    let portal = public()?;
    let page = format!(
        r##"<!doctype html>
<html><head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="30; url=urma://helloworld.tltc/next.html">
<link rel="stylesheet" href="urma://helloworld.tltc/style.css">
</head><body>
<a href="urma://helloworld.tltc/about.html?x=1&amp;y=2#team">About</a>
<a href='urma://{ROSINT}.urma.tltc/'>Explicit</a>
<a href=urma://urma.tltc>Unquoted</a>
<a
   class="x"   href="urma://HelloWorld.tltc/">Upper host</a>
<map name="m"><area shape="rect" coords="0,0,1,1" href="urma://{ROOT}.tltc/x"></map>
<form action="urma://{OTHER}.helloworld.tltc/search" method="get"></form>
<img src="urma://helloworld.tltc/logo.png">
<a href="relative.html" data-x="urma://helloworld.tltc/">Relative</a>
<script>location.href = "urma://helloworld.tltc/";</script>
<p>urma://helloworld.tltc/ in text</p>
</body></html>
"##
    );
    let expected = format!(
        r##"<!doctype html>
<html><head>
<meta charset="utf-8">
<meta http-equiv="refresh" content="30; url=https://helloworld.tltc.portal.example/next.html">
<link rel="stylesheet" href="urma://helloworld.tltc/style.css">
</head><body>
<a href="https://helloworld.tltc.portal.example/about.html?x=1&amp;y=2#team">About</a>
<a href='https://urma.tltc.portal.example/'>Explicit</a>
<a href=https://urma.tltc.portal.example/>Unquoted</a>
<a
   class="x"   href="urma://HelloWorld.tltc/">Upper host</a>
<map name="m"><area shape="rect" coords="0,0,1,1" href="https://portal.example/unavailable?u=urma%3A%2F%2F{ROOT}.tltc%2Fx"></map>
<form action="https://portal.example/unavailable?u=urma%3A%2F%2F{OTHER}.helloworld.tltc%2Fsearch" method="get"></form>
<img src="urma://helloworld.tltc/logo.png">
<a href="relative.html" data-x="urma://helloworld.tltc/">Relative</a>
<script>location.href = "urma://helloworld.tltc/";</script>
<p>urma://helloworld.tltc/ in text</p>
</body></html>
"##
    );
    assert_eq!(
        transform(page.as_bytes(), &portal, MEMORY)?,
        Transformed::Rewritten(expected.into_bytes())
    );
    Ok(())
}

#[test]
fn transform_handles_uppercase_markup_and_refresh_forms() -> Result<()> {
    let portal = local()?;
    let cases = [
        (
            r#"<A HREF="urma://helloworld.tltc/x">x</A>"#,
            r#"<A HREF="http://helloworld.tltc.localhost:8080/x">x</A>"#,
        ),
        (
            r#"<meta http-equiv="Refresh" content="0;URL='urma://urma.tltc/how.html'">"#,
            r#"<meta http-equiv="Refresh" content="0;URL='http://urma.tltc.localhost:8080/how.html'">"#,
        ),
        (
            r#"<meta http-equiv="refresh" content="0; urma://urma.tltc/">"#,
            r#"<meta http-equiv="refresh" content="0; http://urma.tltc.localhost:8080/">"#,
        ),
        (
            r#"<meta http-equiv="refresh" content='1, url = "urma://urma.tltc/a" trailing'>"#,
            r#"<meta http-equiv="refresh" content='1, url = "http://urma.tltc.localhost:8080/a" trailing'>"#,
        ),
        (
            r#"<meta content="0; url=urma://urma.tltc/" http-equiv=REFRESH>"#,
            r#"<meta content="0; url=http://urma.tltc.localhost:8080/" http-equiv=REFRESH>"#,
        ),
        (
            r#"<form method="post" action="urma://urma.tltc?q=1"></form>"#,
            r#"<form method="post" action="http://urma.tltc.localhost:8080/?q=1"></form>"#,
        ),
    ];
    for (page, expected) in cases {
        assert_eq!(
            transform(page.as_bytes(), &portal, MEMORY)?,
            Transformed::Rewritten(expected.as_bytes().to_vec()),
            "{page}"
        );
    }
    for page in [
        r#"<meta http-equiv="content-type" content="0; url=urma://urma.tltc/">"#,
        r#"<meta http-equiv="refresh" content="5">"#,
        r#"<meta http-equiv="refresh" content="x; url=urma://urma.tltc/">"#,
        r#"<meta name="refresh" content="0; url=urma://urma.tltc/">"#,
        r#"<a href="urma&#58;//urma.tltc/">entity</a>"#,
        r#"<a href>empty</a>"#,
        r#"<button formaction="urma://urma.tltc/">button</button>"#,
        r#"<link rel="next" href="urma://urma.tltc/">"#,
    ] {
        assert_eq!(
            transform(page.as_bytes(), &portal, MEMORY)?,
            Transformed::Unchanged,
            "{page}"
        );
    }
    Ok(())
}

#[test]
fn transform_keeps_every_other_byte() -> Result<()> {
    let portal = public()?;
    let page = b"<!doctype html><title>\xff\xfe</title><!-- <a href=\"urma://helloworld.tltc/\"> -->\n<a  href = \"urma://helloworld.tltc/p\"  >p</a>\xc3\x28";
    let expected = b"<!doctype html><title>\xff\xfe</title><!-- <a href=\"urma://helloworld.tltc/\"> -->\n<a  href = \"https://helloworld.tltc.portal.example/p\"  >p</a>\xc3\x28";
    assert_eq!(
        transform(page, &portal, MEMORY)?,
        Transformed::Rewritten(expected.to_vec())
    );
    let hello = b"<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n<title>Hello World</title>\n<link rel=\"stylesheet\" href=\"style.css\">\n</head>\n<body>\n<main>\n<h1>Hello World</h1>\n</main>\n</body>\n</html>\n";
    assert_eq!(transform(hello, &portal, MEMORY)?, Transformed::Unchanged);
    Ok(())
}

fn package() -> Result<Package> {
    let files = vec![
        FileEntry::new(
            "index.html",
            "text/html",
            b"<!doctype html><title>home</title>".to_vec(),
        ),
        FileEntry::new("style.css", "text/css", b"body{}".to_vec()),
        FileEntry::new(
            "docs/index.html",
            "text/html;charset=utf-8",
            b"<p>docs</p>".to_vec(),
        ),
        FileEntry::new("docs/page.html", "text/html", b"<p>page</p>".to_vec()),
        FileEntry::new("assets/logo.svg", "image/svg+xml", b"<svg/>".to_vec()),
        FileEntry::new(
            ".well-known/urma/index.html",
            "text/html",
            b"<p>shadowed</p>".to_vec(),
        ),
        FileEntry::new(".well-known/urma/proof", "application/json", b"{}".to_vec()),
        FileEntry::new(".well-known/security.txt", "text/plain", b"x".to_vec()),
    ];
    let pinned = vec![PinnedEntry {
        path: "media/film.mp4".into(),
        mime: "video/mp4".into(),
        root_txid: ROOT.parse()?,
        payload_sha256: [7; 32],
    }];
    Ok(Package::build("fixture", "index.html", files, pinned)?)
}

#[test]
fn declared_set_routing_matches_the_browser() -> Result<()> {
    let package = package()?;
    let serve = |path: &str| Route::Serve(path.to_owned());
    let cases = [
        ("/", serve("index.html")),
        ("/?utm=1", serve("index.html")),
        ("/index.html", serve("index.html")),
        ("/style.css?v=3", serve("style.css")),
        ("/docs/", serve("docs/index.html")),
        ("/docs/page.html#frag", serve("docs/page.html")),
        ("/media/film.mp4", serve("media/film.mp4")),
        (
            "/.well-known/security.txt",
            serve(".well-known/security.txt"),
        ),
        ("/.well-known/urma/", Route::Undeclared),
        ("/.well-known/urma", Route::Undeclared),
        ("/.well-known/urma/index.html", Route::Undeclared),
        ("/.well-known/urma/proof", Route::Undeclared),
        ("/docs", Route::Redirect("/docs/".into())),
        ("/docs?x=1", Route::Redirect("/docs/?x=1".into())),
        ("/missing.html", Route::Undeclared),
        ("/assets", Route::Undeclared),
        ("/assets/", Route::Undeclared),
        ("/Style.css", Route::Undeclared),
        ("/style.css/", Route::Undeclared),
        ("//style.css", Route::Undeclared),
        ("/./style.css", Route::Undeclared),
        ("/docs/../style.css", Route::Undeclared),
        ("/style%2Ecss", Route::Undeclared),
        ("style.css", Route::Undeclared),
        ("", Route::Undeclared),
    ];
    for (target, expected) in cases {
        assert_eq!(route(&package, target), expected, "{target}");
    }
    assert_eq!(split_target("/a/b?c=d#e"), ("/a/b", "?c=d#e"));
    assert_eq!(split_target("/a#e?x"), ("/a", "#e?x"));
    assert_eq!(split_target("/plain"), ("/plain", ""));
    Ok(())
}

#[test]
fn registry_standing_maps_to_http_statuses() -> Result<()> {
    let registry: Txid = ROSINT.parse()?;
    let root: Txid = ROOT.parse()?;
    let owner: XOnlyPublicKey = AUTHOR.parse()?;
    let bound = |target: Target, expiry: u64| {
        Resolution::Bound(Bound {
            owner,
            target,
            expiry,
            claim_txid: registry,
            last_txid: registry,
        })
    };
    let answer =
        |resolution: Resolution, tip: u64| match standing("urma.tltc", registry, resolution, tip) {
            Ok(..) => (200, "servable"),
            Err(refusal) => (refusal.status(), refusal.state.label()),
        };
    assert_eq!(answer(Resolution::Unbound, 10), (404, "unbound"));
    assert_eq!(answer(Resolution::Suspended, 10), (403, "suspended"));
    assert_eq!(answer(bound(Target::Reserved, 100), 10), (404, "reserved"));
    assert_eq!(
        answer(bound(Target::Publication(root), 100), 100),
        (404, "expired")
    );
    assert_eq!(
        answer(bound(Target::Publication(root), 100), 101),
        (404, "expired")
    );
    assert_eq!(
        answer(bound(Target::Publication(root), 100), 99),
        (200, "servable")
    );
    let (kept, served) = standing(
        "urma.tltc",
        registry,
        bound(Target::Publication(root), 100),
        99,
    )?;
    assert_eq!((kept.expiry, served), (100, root));
    let suspended = standing("urma.tltc", registry, Resolution::Suspended, 1)
        .err()
        .context("suspended names are refused")?;
    assert_eq!(suspended.state, State::Suspended);
    assert!(suspended.detail.contains(ROSINT));
    assert!(!suspended.detail.contains(ROOT));
    Ok(())
}

#[test]
fn states_follow_the_portal_status_table() {
    for (state, label, status) in [
        (State::NotAName, "not-a-name", 404),
        (State::NetworkNotServed, "network-not-served", 404),
        (State::IndexBehind, "index-behind", 503),
        (State::Unbound, "unbound", 404),
        (State::Reserved, "reserved", 404),
        (State::Expired, "expired", 404),
        (State::Suspended, "suspended", 403),
        (State::Undeclared, "undeclared", 404),
        (State::VerificationFailed, "verification-failed", 502),
        (State::Fetching, "fetching", 503),
        (State::FetchFailed, "fetch-failed", 502),
        (State::ServiceWorker, "service-worker", 403),
        (State::NotAPortalPage, "not-a-portal-page", 404),
        (State::NotServable, "not-servable", 404),
        (State::Misdirected, "misdirected", 421),
        (State::BadRequest, "bad-request", 400),
        (State::MethodNotAllowed, "method-not-allowed", 405),
        (State::RequestTimeout, "request-timeout", 408),
        (State::BodyRefused, "body-refused", 413),
        (State::TargetTooLong, "target-too-long", 414),
        (State::HeadTooLarge, "head-too-large", 431),
        (State::Internal, "internal-error", 500),
    ] {
        assert_eq!((state.label(), state.status()), (label, status));
        let reply = Refusal::new(state, "detail".into()).reply();
        assert_eq!(reply.status, status, "{label}");
        assert_eq!(values(&reply.headers, "URMA-State"), [label]);
        assert_eq!(values(&reply.headers, "Cache-Control"), ["no-store"]);
        assert_eq!(
            values(&reply.headers, "Content-Security-Policy"),
            [PORTAL_CSP]
        );
        assert!(values(&reply.headers, "URMA-Name").is_empty(), "{label}");
    }
}

fn values<'a>(headers: &'a [(&'static str, String)], name: &str) -> Vec<&'a str> {
    let mut found = Vec::new();
    for (header, value) in headers {
        if header.eq_ignore_ascii_case(name) {
            found.push(value.as_str());
        }
    }
    found
}

#[test]
fn pages_and_refusals_escape_untrusted_text() -> Result<()> {
    let portal = local()?;
    let page = unavailable_page(
        &portal,
        &["urma://x.tltc/<script>alert(1)</script>\"'&".to_owned()],
    );
    assert!(page.contains("urma://x.tltc/&lt;script&gt;alert(1)&lt;/script&gt;&quot;&#39;&amp;"));
    assert!(!page.contains("<script>"));
    assert!(page.contains("<a href=\"http://localhost:8080/\">Portal index</a>"));
    let index = index_page(
        &portal,
        &[
            Listing {
                suffix: "tltc",
                network: "litecoin-testnet".into(),
                registry: ROSINT.into(),
                state: ListingState::Ready {
                    index: IndexPoint {
                        height: 10,
                        block_hash: "ab".into(),
                    },
                    tip: 11,
                    names: vec![ListedName {
                        name: "urma".into(),
                        url: "http://urma.tltc.localhost:8080/".into(),
                        root: ROOT.into(),
                        expiry: 99,
                    }],
                },
            },
            Listing {
                suffix: "ltc",
                network: "litecoin-mainnet".into(),
                registry: OTHER.into(),
                state: ListingState::Pending("no index <yet>".into()),
            },
            Listing {
                suffix: "tbtc",
                network: "bitcoin-testnet4".into(),
                registry: OTHER.into(),
                state: ListingState::Behind {
                    index: IndexPoint {
                        height: 7,
                        block_hash: "cd".into(),
                    },
                    tip: 12,
                    reason: "5 blocks <behind>".into(),
                },
            },
        ],
    );
    assert!(index.contains("<a href=\"http://urma.tltc.localhost:8080/\">urma</a>"));
    assert!(index.contains("<span>10 (chain tip 11)</span><span>Block</span><code>ab</code>"));
    assert!(index.contains("not ready: no index &lt;yet&gt;"));
    assert!(index.contains("<span>7 (chain tip 12)</span>"));
    assert!(index.contains("behind: 5 blocks &lt;behind&gt;"));
    assert!(index.contains("answer 503"));
    let reply = Refusal::new(State::Undeclared, "<b>x</b>".into())
        .with("Retry-After", "5".into())
        .reply();
    assert_eq!(reply.status, 404);
    let body = String::from_utf8(reply.body.clone())?;
    assert!(body.contains("&lt;b&gt;x&lt;/b&gt;"));
    assert!(body.contains("<span>State</span><code>undeclared</code>"));
    assert!(!body.contains("<script"));
    for (name, value) in [
        ("Retry-After", "5"),
        ("Cache-Control", "no-store"),
        ("Content-Security-Policy", PORTAL_CSP),
        ("Content-Type", "text/html; charset=utf-8"),
        ("URMA-State", "undeclared"),
    ] {
        assert_eq!(values(&reply.headers, name), [value], "{name}");
    }
    let json = Reply::json(200, &json!({"name": "urma"}))?;
    assert_eq!(json.body, b"{\n  \"name\": \"urma\"\n}\n");
    Ok(())
}

#[test]
fn portal_pages_are_uncached_and_locked_down_while_site_bytes_get_the_site_policy() -> Result<()> {
    for reply in [
        Reply::html(200, index_page(&public()?, &[])),
        Reply::html(200, unavailable_page(&public()?, &[])),
        Reply::text(200, "ok\n"),
        Reply::json(200, &json!({"format": "URMA-PORTAL-PROOF-1"}))?,
    ] {
        assert_eq!(values(&reply.headers, "Cache-Control"), ["no-store"]);
        assert_eq!(
            values(&reply.headers, "Content-Security-Policy"),
            [PORTAL_CSP]
        );
    }
    let site = Reply::site(200, "text/css", 60, b"body{}".to_vec());
    assert_eq!(values(&site.headers, "Content-Type"), ["text/css"]);
    assert_eq!(
        values(&site.headers, "Cache-Control"),
        ["public, max-age=60, no-transform"]
    );
    assert_eq!(values(&site.headers, "Content-Security-Policy"), [SITE_CSP]);
    Ok(())
}

fn permissions() -> String {
    let mut listed = Vec::new();
    for feature in FEATURES {
        listed.push(format!("{feature}=()"));
    }
    listed.join(", ")
}

#[test]
fn every_reply_is_secured_and_https_adds_hsts() {
    let permissions = permissions();
    for (reply, scheme, hsts) in [
        (Reply::text(200, "ok\n"), LinkScheme::Https, vec![HSTS]),
        (Reply::text(200, "ok\n"), LinkScheme::Http, Vec::new()),
        (
            Refusal::new(State::Unbound, "x".into()).reply(),
            LinkScheme::Https,
            vec![HSTS],
        ),
        (
            Reply::site(200, "text/css", 60, Vec::new()),
            LinkScheme::Http,
            Vec::new(),
        ),
    ] {
        let secured = reply.secured(scheme);
        for (name, value) in [
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
            ("Cross-Origin-Opener-Policy", "same-origin"),
            ("Cross-Origin-Resource-Policy", "same-origin"),
            ("Origin-Agent-Cluster", "?1"),
            ("Permissions-Policy", permissions.as_str()),
        ] {
            assert_eq!(values(&secured.headers, name), [value], "{name}");
        }
        assert_eq!(values(&secured.headers, "Strict-Transport-Security"), hsts);
        assert!(values(&secured.headers, "Set-Cookie").is_empty());
    }
}

fn subject() -> Subject {
    let mut subject = Subject::new("helloworld".into(), "tltc");
    subject.network = Some("litecoin-testnet".into());
    subject.registry = Some(ROSINT.into());
    subject.index = Some(IndexPoint {
        height: 4898700,
        block_hash: BLOCK.into(),
    });
    subject
}

#[test]
fn name_error_pages_state_what_the_portal_knows() -> Result<()> {
    let index = format!("4898700 {BLOCK}");
    let reply = Refusal::new(State::Suspended, "helloworld.tltc is suspended".into())
        .about(subject())
        .reply();
    assert_eq!(reply.status, 403);
    for (name, value) in [
        ("URMA-State", "suspended"),
        ("URMA-Network", "litecoin-testnet"),
        ("URMA-Registry", ROSINT),
        ("URMA-Name", "helloworld"),
        ("URMA-Index", index.as_str()),
        ("Cache-Control", "no-store"),
        ("Content-Security-Policy", PORTAL_CSP),
    ] {
        assert_eq!(values(&reply.headers, name), [value], "{name}");
    }
    assert!(values(&reply.headers, "URMA-Root").is_empty());
    let body = String::from_utf8(reply.body)?;
    for fact in [
        "<span>State</span><code>suspended</code>",
        "<span>Name</span><code>helloworld.tltc</code>",
        "<span>Network</span><code>litecoin-testnet</code>",
        &format!("<span>Registry</span><code>{ROSINT}</code>"),
        &format!("<span>Index height</span><span>4898700 (block <code>{BLOCK}</code>)</span>"),
        "<code>urma://helloworld.tltc/</code>",
    ] {
        assert!(body.contains(fact), "{fact}");
    }
    assert!(!body.contains("<script"));
    let unserved = Refusal::new(State::NetworkNotServed, "not served".into())
        .about(Subject::new("helloworld".into(), "ltc"))
        .reply();
    assert_eq!(unserved.status, 404);
    assert_eq!(values(&unserved.headers, "URMA-Name"), ["helloworld"]);
    assert_eq!(
        values(&unserved.headers, "URMA-State"),
        ["network-not-served"]
    );
    for absent in ["URMA-Network", "URMA-Registry", "URMA-Index"] {
        assert!(values(&unserved.headers, absent).is_empty(), "{absent}");
    }
    assert!(String::from_utf8(unserved.body)?.contains("urma://helloworld.ltc/"));
    Ok(())
}

#[test]
fn stale_indexes_answer_index_behind() -> Result<()> {
    let policy = Freshness {
        max_lag: 2,
        max_age: Duration::from_secs(600),
        retry: Duration::from_secs(30),
    };
    let scanned = Instant::now();
    let after = |seconds: u64| scanned + Duration::from_secs(seconds);
    let at = Scan::At(scanned);
    assert_eq!(policy.judge(100, 100, at, after(0)), Currency::Current);
    assert_eq!(policy.judge(98, 100, at, after(599)), Currency::Current);
    assert_eq!(policy.judge(101, 100, at, after(1)), Currency::Current);
    for (height, tip, scan, now) in [
        (97, 100, at, after(1)),
        (100, 100, at, after(600)),
        (100, 100, at, after(3600)),
        (100, 100, Scan::Never, after(0)),
    ] {
        assert!(
            matches!(policy.judge(height, tip, scan, now), Currency::Behind(..)),
            "{height} {tip} {scan:?}"
        );
    }
    let Currency::Behind(reason) = policy.judge(90, 100, at, after(1)) else {
        anyhow::bail!("an index 10 blocks behind is not current");
    };
    assert!(
        reason.contains("10 blocks behind the chain tip 100"),
        "{reason}"
    );
    let reply = policy
        .refusal("litecoin-testnet", &reason)
        .about(subject())
        .reply();
    assert_eq!(reply.status, 503);
    let index = format!("4898700 {BLOCK}");
    for (name, value) in [
        ("URMA-State", "index-behind"),
        ("Retry-After", "30"),
        ("Cache-Control", "no-store"),
        ("URMA-Network", "litecoin-testnet"),
        ("URMA-Registry", ROSINT),
        ("URMA-Name", "helloworld"),
        ("URMA-Index", index.as_str()),
    ] {
        assert_eq!(values(&reply.headers, name), [value], "{name}");
    }
    assert!(String::from_utf8(reply.body)?.contains("index-behind"));
    Ok(())
}

fn provenance() -> Provenance {
    Provenance {
        subject: subject(),
        root: ROOT.into(),
        author: AUTHOR.into(),
        payload_sha256: PAYLOAD.into(),
    }
}

fn declared(path: &str, mime: &str, bytes: &[u8]) -> Declared {
    Declared {
        path: path.into(),
        mime: mime.into(),
        sha256: hex::encode(Sha256::digest(bytes)),
        bytes: bytes.to_vec(),
    }
}

fn get(validators: &[&str]) -> Request {
    Request {
        method: Method::Get,
        target: "/".into(),
        host: "helloworld.tltc.portal.example".into(),
        validators: validators.iter().map(|tag| (*tag).to_owned()).collect(),
    }
}

#[test]
fn site_files_carry_the_verification_surface() -> Result<()> {
    let portal = public()?;
    let serving = Serving {
        portal: &portal,
        max_age: 60,
        html_memory: MEMORY,
    };
    let css = declared("style.css", "text/css", b"body{}");
    let sha = css.sha256.clone();
    let reply = serving.file(&provenance(), css, &get(&[]))?;
    assert_eq!(reply.status, 200);
    assert_eq!(reply.body, b"body{}");
    let index = format!("4898700 {BLOCK}");
    let etag = format!("\"{sha}\"");
    for (name, value) in [
        ("Content-Type", "text/css"),
        ("Cache-Control", "public, max-age=60, no-transform"),
        ("Content-Security-Policy", SITE_CSP),
        ("URMA-Network", "litecoin-testnet"),
        ("URMA-Registry", ROSINT),
        ("URMA-Name", "helloworld"),
        ("URMA-Index", index.as_str()),
        ("URMA-Root", ROOT),
        ("URMA-Author", AUTHOR),
        ("URMA-Payload-SHA256", PAYLOAD),
        ("URMA-Path", "style.css"),
        ("URMA-SHA256", sha.as_str()),
        ("ETag", etag.as_str()),
    ] {
        assert_eq!(values(&reply.headers, name), [value], "{name}");
    }
    for absent in ["URMA-Transform", "URMA-Original-SHA256", "URMA-State"] {
        assert!(values(&reply.headers, absent).is_empty(), "{absent}");
    }
    Ok(())
}

#[test]
fn html_files_are_marked_links_v1_even_when_unchanged() -> Result<()> {
    let portal = public()?;
    let serving = Serving {
        portal: &portal,
        max_age: 60,
        html_memory: MEMORY,
    };
    let plain = declared("index.html", "text/html", b"<p>hello</p>");
    let original = plain.sha256.clone();
    let reply = serving.file(&provenance(), plain, &get(&[]))?;
    assert_eq!(reply.body, b"<p>hello</p>");
    for (name, value) in [
        ("URMA-Transform", "links-v1"),
        ("URMA-Original-SHA256", original.as_str()),
        ("URMA-SHA256", original.as_str()),
        ("URMA-Path", "index.html"),
    ] {
        assert_eq!(values(&reply.headers, name), [value], "{name}");
    }
    let linked = declared(
        "docs/index.html",
        "text/html;charset=utf-8",
        b"<a href=\"urma://urma.tltc/x\">x</a>",
    );
    let original = linked.sha256.clone();
    let reply = serving.file(&provenance(), linked, &get(&[]))?;
    let body = b"<a href=\"https://urma.tltc.portal.example/x\">x</a>";
    assert_eq!(reply.body, body);
    let digest = hex::encode(Sha256::digest(body));
    let etag = format!("\"{digest}\"");
    for (name, value) in [
        ("Content-Type", "text/html;charset=utf-8"),
        ("URMA-Transform", "links-v1"),
        ("URMA-Original-SHA256", original.as_str()),
        ("URMA-SHA256", digest.as_str()),
        ("ETag", etag.as_str()),
    ] {
        assert_eq!(values(&reply.headers, name), [value], "{name}");
    }
    let xhtml = declared(
        "page.xhtml",
        "application/xhtml+xml",
        b"<a href=\"urma://urma.tltc/x\">x</a>",
    );
    let reply = serving.file(&provenance(), xhtml, &get(&[]))?;
    assert_eq!(reply.body, b"<a href=\"urma://urma.tltc/x\">x</a>");
    assert!(values(&reply.headers, "URMA-Transform").is_empty());
    Ok(())
}

#[test]
fn matching_validators_answer_304_and_bad_bytes_answer_502() -> Result<()> {
    let portal = public()?;
    let serving = Serving {
        portal: &portal,
        max_age: 60,
        html_memory: MEMORY,
    };
    let css = declared("style.css", "text/css", b"body{}");
    let etag = format!("\"{}\"", css.sha256);
    let weak = format!("W/{etag}");
    for validators in [
        vec![etag.as_str()],
        vec!["\"other\"", weak.as_str()],
        vec!["*"],
    ] {
        let copy = declared("style.css", "text/css", b"body{}");
        let reply = serving.file(&provenance(), copy, &get(&validators))?;
        assert_eq!(reply.status, 304, "{validators:?}");
        assert!(reply.body.is_empty());
        assert_eq!(values(&reply.headers, "ETag"), [etag.as_str()]);
        assert_eq!(
            values(&reply.headers, "Cache-Control"),
            ["public, max-age=60, no-transform"]
        );
    }
    let fresh = serving.file(&provenance(), css, &get(&["\"other\""]))?;
    assert_eq!(fresh.status, 200);
    let mut tampered = declared("style.css", "text/css", b"body{}");
    tampered.bytes = b"body{color:red}".to_vec();
    let refusal = serving
        .file(&provenance(), tampered, &get(&[]))
        .err()
        .context("tampered bytes are refused")?;
    assert_eq!(
        (refusal.status(), refusal.state),
        (502, State::VerificationFailed)
    );
    Ok(())
}

fn limits() -> HttpLimits {
    HttpLimits {
        head_bytes: 4096,
        max_headers: 16,
        target_bytes: 256,
        io_timeout: Duration::from_secs(5),
        head_timeout: Duration::from_secs(5),
        accept_backoff: Duration::from_millis(10),
        linger: Duration::from_secs(1),
        linger_bytes: 64 * 1024,
    }
}

fn echo_server(scheme: LinkScheme) -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    std::thread::spawn(move || {
        accept_loop(&listener, &limits(), scheme, &|request: &Request| {
            let body = format!("{:?} {} {}", request.method, request.host, request.target);
            let reply = Reply::text(200, &body).with("ETag", "\"tag\"".into());
            if request.validates("\"tag\"") {
                reply.not_modified()
            } else {
                reply
            }
        })
    });
    Ok(address)
}

fn response_values(response: &str, name: &str) -> Vec<String> {
    let mut found = Vec::new();
    let head = match response.split_once("\r\n\r\n") {
        Some((head, _body)) => head,
        None => response,
    };
    for line in head.lines().skip(1) {
        let Some((header, value)) = line.split_once(": ") else {
            continue;
        };
        if header.eq_ignore_ascii_case(name) {
            found.push(value.to_owned());
        }
    }
    found
}

fn exchange(address: SocketAddr, raw: &[u8]) -> Result<String> {
    let mut stream = TcpStream::connect(address)?;
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    stream.write_all(raw)?;
    stream.shutdown(Shutdown::Write)?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    Ok(String::from_utf8(response)?)
}

fn status_line(response: &str) -> &str {
    response.lines().next().unwrap_or_default()
}

#[test]
fn http_layer_serves_get_head_and_conditional_requests() -> Result<()> {
    let address = echo_server(LinkScheme::Https)?;
    let get = exchange(address, b"GET /a?b=1 HTTP/1.1\r\nHost: Example:80\r\n\r\n")?;
    assert_eq!(status_line(&get), "HTTP/1.1 200 OK");
    assert!(get.contains("\r\nContent-Length: 21\r\n"), "{get}");
    assert!(get.contains("\r\nConnection: close\r\n"));
    assert_eq!(
        response_values(&get, "Content-Security-Policy"),
        [PORTAL_CSP]
    );
    assert!(get.ends_with("\r\n\r\nGet Example:80 /a?b=1"), "{get}");
    let head = exchange(address, b"HEAD /a HTTP/1.1\r\nHost: example\r\n\r\n")?;
    assert_eq!(status_line(&head), "HTTP/1.1 200 OK");
    assert!(head.contains("\r\nContent-Length: 15\r\n"), "{head}");
    assert!(head.ends_with("\r\n\r\n"));
    let conditional = exchange(
        address,
        b"GET / HTTP/1.1\r\nHost: example\r\nIf-None-Match: \"other\", W/\"tag\"\r\n\r\n",
    )?;
    assert_eq!(status_line(&conditional), "HTTP/1.1 304 Not Modified");
    assert!(!conditional.contains("Content-Length"));
    assert!(conditional.ends_with("\r\n\r\n"));
    assert_eq!(response_values(&conditional, "ETag"), ["\"tag\""]);
    let empty_body = exchange(
        address,
        b"GET / HTTP/1.1\r\nHost: example\r\nContent-Length: 0\r\n\r\n",
    )?;
    assert_eq!(status_line(&empty_body), "HTTP/1.1 200 OK");
    assert_eq!(exchange(address, b"")?, "");
    Ok(())
}

#[test]
fn every_response_on_the_wire_is_secured_and_hsts_follows_the_scheme() -> Result<()> {
    let permissions = permissions();
    for (scheme, hsts) in [
        (LinkScheme::Https, vec![HSTS]),
        (LinkScheme::Http, Vec::new()),
    ] {
        let address = echo_server(scheme)?;
        for raw in [
            b"GET / HTTP/1.1\r\nHost: example\r\n\r\n".as_slice(),
            b"GET / HTTP/1.1\r\nHost: example\r\nIf-None-Match: \"tag\"\r\n\r\n",
            b"DELETE / HTTP/1.1\r\nHost: example\r\n\r\n",
            b"GET / HTTP/1.1\r\n\r\n",
        ] {
            let response = exchange(address, raw)?;
            for (name, value) in [
                ("X-Content-Type-Options", "nosniff"),
                ("Referrer-Policy", "no-referrer"),
                ("Cross-Origin-Opener-Policy", "same-origin"),
                ("Cross-Origin-Resource-Policy", "same-origin"),
                ("Origin-Agent-Cluster", "?1"),
                ("Permissions-Policy", permissions.as_str()),
            ] {
                assert_eq!(response_values(&response, name), [value], "{name}");
            }
            assert_eq!(
                response_values(&response, "Strict-Transport-Security"),
                hsts,
                "{response}"
            );
        }
    }
    Ok(())
}

#[test]
fn cookies_are_ignored_and_never_set() -> Result<()> {
    let address = echo_server(LinkScheme::Https)?;
    let response = exchange(
        address,
        b"GET /c HTTP/1.1\r\nHost: example\r\nCookie: session=secret-value\r\n\r\n",
    )?;
    assert_eq!(status_line(&response), "HTTP/1.1 200 OK");
    assert!(response_values(&response, "Set-Cookie").is_empty());
    assert!(!response.contains("secret-value"));
    assert!(response.ends_with("\r\n\r\nGet example /c"), "{response}");
    Ok(())
}

#[test]
fn service_worker_scripts_are_forbidden() -> Result<()> {
    let address = echo_server(LinkScheme::Https)?;
    for header in ["Service-Worker: script", "service-worker:  Script "] {
        let raw = format!("GET /sw.js HTTP/1.1\r\nHost: example\r\n{header}\r\n\r\n");
        let response = exchange(address, raw.as_bytes())?;
        assert_eq!(status_line(&response), "HTTP/1.1 403 Forbidden", "{header}");
        assert_eq!(response_values(&response, "URMA-State"), ["service-worker"]);
        assert_eq!(response_values(&response, "Cache-Control"), ["no-store"]);
        assert_eq!(
            response_values(&response, "Strict-Transport-Security"),
            [HSTS]
        );
    }
    let navigation = exchange(
        address,
        b"GET /sw.js HTTP/1.1\r\nHost: example\r\nService-Worker-Navigation-Preload: true\r\n\r\n",
    )?;
    assert_eq!(status_line(&navigation), "HTTP/1.1 200 OK");
    Ok(())
}

#[test]
fn http_layer_refuses_malformed_and_oversized_requests() -> Result<()> {
    let address = echo_server(LinkScheme::Http)?;
    let long_target = format!("GET /{} HTTP/1.1\r\nHost: x\r\n\r\n", "a".repeat(300));
    let big_head = format!(
        "GET / HTTP/1.1\r\nHost: x\r\nX-Fill: {}\r\n\r\n",
        "a".repeat(5000)
    );
    let many_headers = format!(
        "GET / HTTP/1.1\r\nHost: x\r\n{}\r\n",
        (0..20)
            .map(|index| format!("X-{index}: 1\r\n"))
            .collect::<String>()
    );
    let cases: [(&[u8], &str, &str); 13] = [
        (
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello",
            "405 Method Not Allowed",
            "method-not-allowed",
        ),
        (
            b"OPTIONS / HTTP/1.1\r\nHost: x\r\n\r\n",
            "405 Method Not Allowed",
            "method-not-allowed",
        ),
        (
            b"GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello",
            "413 Content Too Large",
            "body-refused",
        ),
        (
            b"GET / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "413 Content Too Large",
            "body-refused",
        ),
        (b"GET / HTTP/1.1\r\n\r\n", "400 Bad Request", "bad-request"),
        (b"GET / HTTP/1.0\r\n\r\n", "400 Bad Request", "bad-request"),
        (
            b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
            "400 Bad Request",
            "bad-request",
        ),
        (
            b"GET http://x/ HTTP/1.1\r\nHost: x\r\n\r\n",
            "400 Bad Request",
            "bad-request",
        ),
        (
            b"GET / HTTP/1.1\r\nHost: \xff\r\n\r\n",
            "400 Bad Request",
            "bad-request",
        ),
        (b"NOT HTTP AT ALL\r\n\r\n", "400 Bad Request", "bad-request"),
        (
            long_target.as_bytes(),
            "414 URI Too Long",
            "target-too-long",
        ),
        (
            big_head.as_bytes(),
            "431 Request Header Fields Too Large",
            "head-too-large",
        ),
        (
            many_headers.as_bytes(),
            "431 Request Header Fields Too Large",
            "head-too-large",
        ),
    ];
    for (raw, expected, state) in cases {
        let response = exchange(address, raw)?;
        let request = String::from_utf8_lossy(raw);
        assert_eq!(
            status_line(&response),
            format!("HTTP/1.1 {expected}"),
            "{request}"
        );
        assert_eq!(
            response_values(&response, "URMA-State"),
            [state],
            "{request}"
        );
        assert_eq!(
            response_values(&response, "X-Content-Type-Options"),
            ["nosniff"]
        );
        assert!(response_values(&response, "Strict-Transport-Security").is_empty());
    }
    let method = exchange(address, b"DELETE / HTTP/1.1\r\nHost: x\r\n\r\n")?;
    assert!(method.contains("\r\nAllow: GET, HEAD\r\n"));
    let partial = exchange(address, b"GET / HTTP/1.1\r\nHost: x\r\n")?;
    assert_eq!(status_line(&partial), "HTTP/1.1 400 Bad Request");
    Ok(())
}
