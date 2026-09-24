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
use gateway_host::{
    Host, HostError, LinkScheme, Portal, PublicPort, SiteHost, Suffix, authority, classify, is_txid,
};
use gateway_http::{HttpLimits, Refusal, Reply, Request, accept_loop};
use gateway_links::{Rewrite, Transformed, rewrite, transform};
use gateway_pages::{ListedName, Listing, ListingState, index_page, unavailable_page};
use gateway_route::{Route, route, split_target, standing};
use serde_json::json;
use std::{
    collections::BTreeMap,
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream},
    time::Duration,
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
const MEMORY: usize = 16 * 1024 * 1024;

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
fn host_headers_lose_their_port_and_case() -> Result<()> {
    assert_eq!(
        authority("HelloWorld.TLTC.localhost:8080")?,
        "helloworld.tltc.localhost"
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
    let overlong = "g".repeat(64);
    for name in ["-bad", "bad-", "ab--cd", "under_score", overlong.as_str()] {
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
        ("/", serve("/")),
        ("/?utm=1", serve("/")),
        ("/index.html", serve("/index.html")),
        ("/style.css?v=3", serve("/style.css")),
        ("/docs/", serve("/docs/")),
        ("/docs/page.html#frag", serve("/docs/page.html")),
        ("/media/film.mp4", serve("/media/film.mp4")),
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
    let owner: XOnlyPublicKey =
        "986514fb8d4da75550980a77764dfd1dcadf76ca374192560e0b690183fcf251".parse()?;
    let bound = |target: Target, expiry: u64| {
        Resolution::Bound(Bound {
            owner,
            target,
            expiry,
            claim_txid: registry,
            last_txid: registry,
        })
    };
    let status =
        |resolution: Resolution, tip: u64| match standing("urma.tltc", registry, resolution, tip) {
            Ok(..) => 200,
            Err(refusal) => refusal.status,
        };
    assert_eq!(status(Resolution::Unbound, 10), 404);
    assert_eq!(status(Resolution::Suspended, 10), 451);
    assert_eq!(status(bound(Target::Reserved, 100), 10), 404);
    assert_eq!(status(bound(Target::Publication(root), 100), 100), 410);
    assert_eq!(status(bound(Target::Publication(root), 100), 101), 410);
    assert_eq!(status(bound(Target::Publication(root), 100), 99), 200);
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
    assert_eq!(suspended.title, "Unavailable For Legal Reasons");
    assert!(suspended.detail.contains(ROSINT));
    Ok(())
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
                    height: 10,
                    tip: 11,
                    block_hash: "ab".into(),
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
        ],
    );
    assert!(index.contains("<a href=\"http://urma.tltc.localhost:8080/\">urma</a>"));
    assert!(index.contains("not ready: no index &lt;yet&gt;"));
    let reply = Refusal::new(404, "Not Found", "<b>x</b>".into())
        .with("Retry-After", "5".into())
        .reply();
    assert_eq!(reply.status, 404);
    assert!(String::from_utf8(reply.body.clone())?.contains("&lt;b&gt;x&lt;/b&gt;"));
    for (name, value) in [
        ("Retry-After", "5"),
        ("Cache-Control", "no-store"),
        ("X-Content-Type-Options", "nosniff"),
        ("Referrer-Policy", "no-referrer"),
        ("Cross-Origin-Opener-Policy", "same-origin"),
        ("Cross-Origin-Resource-Policy", "same-origin"),
    ] {
        assert!(
            reply
                .headers
                .iter()
                .any(|(header, set)| *header == name && set == value),
            "{name}"
        );
    }
    let json = Reply::json(200, &json!({"name": "urma"}))?;
    assert_eq!(json.body, b"{\n  \"name\": \"urma\"\n}\n");
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

fn echo_server() -> Result<SocketAddr> {
    let listener = TcpListener::bind("127.0.0.1:0")?;
    let address = listener.local_addr()?;
    std::thread::spawn(move || {
        accept_loop(&listener, &limits(), &|request: &Request| {
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
    let address = echo_server()?;
    let get = exchange(address, b"GET /a?b=1 HTTP/1.1\r\nHost: Example:80\r\n\r\n")?;
    assert_eq!(status_line(&get), "HTTP/1.1 200 OK");
    assert!(get.contains("\r\nContent-Length: 21\r\n"), "{get}");
    assert!(get.contains("\r\nConnection: close\r\n"));
    assert!(get.contains("\r\nContent-Security-Policy: default-src 'self'; "));
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
    let empty_body = exchange(
        address,
        b"GET / HTTP/1.1\r\nHost: example\r\nContent-Length: 0\r\n\r\n",
    )?;
    assert_eq!(status_line(&empty_body), "HTTP/1.1 200 OK");
    assert_eq!(exchange(address, b"")?, "");
    Ok(())
}

#[test]
fn http_layer_refuses_malformed_and_oversized_requests() -> Result<()> {
    let address = echo_server()?;
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
    let cases: [(&[u8], &str); 12] = [
        (
            b"POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello",
            "405 Method Not Allowed",
        ),
        (
            b"GET / HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello",
            "413 Content Too Large",
        ),
        (
            b"GET / HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            "413 Content Too Large",
        ),
        (b"GET / HTTP/1.1\r\n\r\n", "400 Bad Request"),
        (b"GET / HTTP/1.0\r\n\r\n", "400 Bad Request"),
        (
            b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n",
            "400 Bad Request",
        ),
        (
            b"GET http://x/ HTTP/1.1\r\nHost: x\r\n\r\n",
            "400 Bad Request",
        ),
        (b"GET / HTTP/1.1\r\nHost: \xff\r\n\r\n", "400 Bad Request"),
        (b"NOT HTTP AT ALL\r\n\r\n", "400 Bad Request"),
        (long_target.as_bytes(), "414 URI Too Long"),
        (big_head.as_bytes(), "431 Request Header Fields Too Large"),
        (
            many_headers.as_bytes(),
            "431 Request Header Fields Too Large",
        ),
    ];
    for (raw, expected) in cases {
        let response = exchange(address, raw)?;
        assert_eq!(
            status_line(&response),
            format!("HTTP/1.1 {expected}"),
            "{}",
            String::from_utf8_lossy(raw)
        );
        assert!(response.contains("\r\nX-Content-Type-Options: nosniff\r\n"));
    }
    let method = exchange(address, b"DELETE / HTTP/1.1\r\nHost: x\r\n\r\n")?;
    assert!(method.contains("\r\nAllow: GET, HEAD\r\n"));
    let partial = exchange(address, b"GET / HTTP/1.1\r\nHost: x\r\n")?;
    assert_eq!(status_line(&partial), "HTTP/1.1 400 Bad Request");
    Ok(())
}
