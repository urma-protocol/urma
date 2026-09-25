#!/usr/bin/env python3
# SPDX-License-Identifier: 0BSD
"""Generate links-v1 portal transform vectors (PORTAL.md section 6) without any URMA library.
Each case is <name>.html (input bytes) and <name>.expected (output bytes, equal to the input
when nothing matches); manifest.json names the parameters D, S and G per suffix of each case.
Expected outputs are written by hand from the specification, never produced by an implementation."""
import json
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "tests/vectors/portal/links-v1"
ROSINT = b"4c53ebbea660c206c4a09d4ccc48479950d7300e39876c9772b2f72ca232d1e3"
HELLO = b"ec14869df741deb3fc92114d2bd81c03b3b94891dd34a807eee206b171b0e7c2"
URMA = b"e5ef78d5fe042c2b7c646d9ab03256a4c0d479a8032adca1e88425f99e4fef1a"
OTHER = b"11" * 32
REGISTRIES = {"ltc": None, "btc": None, "tltc": ROSINT.decode(), "tbtc": None}
PARAMETERS = {
    "public": {"D": "urma-portal.rosint.org", "S": "https", "G": REGISTRIES},
    "local": {"D": "localhost:8080", "S": "http", "G": REGISTRIES},
}
U = b"https://urma.tltc.urma-portal.rosint.org"
H = b"https://helloworld.tltc.urma-portal.rosint.org"
GONE = b"https://urma-portal.rosint.org/unavailable?u="
UNRESERVED = set(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
manifest = {"transform": "links-v1", "specification": "PORTAL.md section 6", "license": "CC0-1.0",
            "parameters": PARAMETERS, "cases": []}


def pct(data):
    return b"".join(bytes([byte]) if byte in UNRESERVED else b"%%%02X" % byte for byte in data)


def gone(candidate):
    return GONE + pct(candidate)


def case(name, about, rows, parameters="public", newline=True):
    end = b"\n" if newline else b""
    source = b"\n".join(given for given, _ in rows) + end
    expected = b"\n".join(given if wanted is None else wanted for given, wanted in rows) + end
    (OUT / (name + ".html")).write_bytes(source)
    (OUT / (name + ".expected")).write_bytes(expected)
    manifest["cases"].append({"name": name, "parameters": parameters, "changed": source != expected,
                              "about": about})


def spec():
    case("spec-example-a", "6.4: short name; path, query, fragment and the character reference are kept", [
        (b'<a href="urma://urma.tltc/docs/?v=2&amp;x=1#top">',
         b'<a href="https://urma.tltc.urma-portal.rosint.org/docs/?v=2&amp;x=1#top">')])
    case("spec-example-area", "6.4: explicit registry equal to G(tltc), unquoted, uppercase markup, empty tail", [
        (b"<AREA HREF=urma://" + ROSINT + b".helloworld.tltc>",
         b"<AREA HREF=https://helloworld.tltc.urma-portal.rosint.org/>")])
    case("spec-example-meta", "6.4: meta refresh; URL= and a quote, cut at the closing quote", [
        (b"<meta http-equiv=\"Refresh\" content=\"3; URL='urma://urma.tltc/new/'\">",
         b"<meta http-equiv=\"Refresh\" content=\"3; URL='https://urma.tltc.urma-portal.rosint.org/new/'\">")])
    case("spec-example-form", "6.4: a publication address goes to /unavailable with pct(C)", [
        (b'<form action="urma://' + HELLO + b'.tltc/q">',
         b'<form action="https://urma-portal.rosint.org/unavailable?u=urma%3A%2F%2F' + HELLO + b'.tltc%2Fq">')])
    for name, line in [
        ("scheme-case", b'<a href="URMA://urma.tltc/">'),
        ("host-case", b'<a href="urma://Urma.tltc/">'),
        ("port", b'<a href="urma://urma.tltc:80/">'),
        ("character-reference", b'<a href="urma&#58;//urma.tltc/">'),
        ("scheme-relative", b'<a href="//urma.tltc/">'),
        ("img-src", b'<img src="urma://urma.tltc/a.png">'),
        ("script", b'<script>location = "urma://urma.tltc/"</script>'),
        ("comment", b'<!-- <a href="urma://urma.tltc/"> -->'),
        ("textarea", b'<textarea><a href="urma://urma.tltc/"></textarea>'),
    ]:
        case("spec-untouched-" + name, "6.4: listed as untouched", [(line, None)])


def slots():
    case("slot-whitespace-kept", "6.2: leading and trailing ASCII whitespace of a slot is kept and excluded from C", [
        (b'<a href="  urma://urma.tltc/a  ">', b'<a href="  %s/a  ">' % U),
        (b'<a href="\turma://urma.tltc/b\n">', b'<a href="\t%s/b\n">' % U),
        (b'<a href="\r\nurma://urma.tltc/c\x0c">', b'<a href="\r\n%s/c\x0c">' % U),
        (b"<area href=' urma://urma.tltc/d'>", b"<area href=' %s/d'>" % U),
        (b'<form action=" urma://urma.tltc?q ">', b'<form action=" %s/?q ">' % U),
        (b'<a href=" urma://' + URMA + b'.tltc/x ">', b'<a href=" ' + gone(b"urma://" + URMA + b".tltc/x") + b' ">'),
        (b'<meta http-equiv="refresh" content="0; url=urma://urma.tltc/e \t">',
         b'<meta http-equiv="refresh" content="0; url=%s/e \t">' % U),
    ])
    case("slot-whitespace-untouched", "6.2: whitespace inside C, or a vertical tab (not ASCII whitespace), leaves the slot untouched", [
        (b'<a href="urma://urma.tltc/a b">', None),
        (b'<a href="urma://urma.tltc/a\tb">', None),
        (b'<a href="urma://urma.tltc/a\nb">', None),
        (b'<a href="\x0burma://urma.tltc/">', None),
        (b'<a href="urma://urma.tltc/\x0b">', None),
        (b'<a href=" urma:// urma.tltc/">', None),
        (b'<a href="   ">', None),
    ])
    case("tail-rejected-bytes", "6.2: a tail T with a byte <= 0x20, 0x7F or a backslash leaves the slot untouched", [
        (b'<a href="urma://urma.tltc/a\x00b">', None),
        (b'<a href="urma://urma.tltc/a\x01b">', None),
        (b'<a href="urma://urma.tltc/a\x1fb">', None),
        (b'<a href="urma://urma.tltc/a\x7fb">', None),
        (b'<a href="urma://urma.tltc/a\\b">', None),
        (b'<a href="urma://urma.tltc?a\\b">', None),
        (b'<a href="urma://urma.tltc#a b">', None),
        (b'<a href="urma://' + URMA + b'.tltc/a\\b">', None),
    ])
    case("tail-allowed-bytes", "6.2 and 6.3: every other tail byte (quotes, angle brackets, %, bytes >= 0x80) is copied as is", [
        (b"<a href='urma://urma.tltc/say\"hi\"'>", b"<a href='%s/say\"hi\"'>" % U),
        (b"<a href=\"urma://urma.tltc/it's\">", b"<a href=\"%s/it's\">" % U),
        (b'<a href="urma://urma.tltc/a<b>c">', b'<a href="%s/a<b>c">' % U),
        (b'<a href="urma://urma.tltc/{x}|[y]^`z`">', b'<a href="%s/{x}|[y]^`z`">' % U),
        (b'<a href="urma://urma.tltc/100%zz%41">', b'<a href="%s/100%%zz%%41">' % U),
        (b'<a href="urma://urma.tltc/caf\xe9?\xff#\x80">', b'<a href="%s/caf\xe9?\xff#\x80">' % U),
        (b'<a href=urma://urma.tltc/"quoted">', b'<a href=%s/"quoted">' % U),
        (b'<a href="urma://urma.tltc/a?b=/c#d?e">', b'<a href="%s/a?b=/c#d?e">' % U),
    ])
    case("pct-encoding", "6.3: pct keeps A-Z a-z 0-9 - . _ ~ and writes every other byte as % and two uppercase hex digits", [
        (b'<a href="urma://' + URMA + b'.tltc/a~b*c+d">',
         b'<a href="https://urma-portal.rosint.org/unavailable?u=urma%3A%2F%2F' + URMA + b'.tltc%2Fa~b%2Ac%2Bd">'),
        (b'<a href="urma://' + URMA + b".tltc/Z_z.0-9!$&'(),;=:@%41?q=1&amp;r#f\">",
         b'<a href="https://urma-portal.rosint.org/unavailable?u=urma%3A%2F%2F' + URMA
         + b'.tltc%2FZ_z.0-9%21%24%26%27%28%29%2C%3B%3D%3A%40%2541%3Fq%3D1%26amp%3Br%23f">'),
        (b'<a href="urma://' + URMA + b'.tltc/\xc8\x99\xff\x80">',
         b'<a href="https://urma-portal.rosint.org/unavailable?u=urma%3A%2F%2F' + URMA + b'.tltc%2F%C8%99%FF%80">'),
        (b'<a href="urma://' + OTHER + b'.helloworld.tltc/x?y#z">',
         b'<a href="https://urma-portal.rosint.org/unavailable?u=urma%3A%2F%2F' + OTHER + b'.helloworld.tltc%2Fx%3Fy%23z">'),
    ])


def targets():
    case("short-names", "6.3: short name.s maps to S://name.s.D followed by T' (a / is added when T is empty or starts with ? or #)", [
        (b'<a href="urma://helloworld.tltc/">', b'<a href="%s/">' % H),
        (b'<a href="urma://helloworld.tltc">', b'<a href="%s/">' % H),
        (b'<a href="urma://helloworld.tltc?x=1&y=2">', b'<a href="%s/?x=1&y=2">' % H),
        (b'<a href="urma://helloworld.tltc#top">', b'<a href="%s/#top">' % H),
        (b'<a href="urma://helloworld.tltc/a/b.html?x=1#part">', b'<a href="%s/a/b.html?x=1#part">' % H),
        (b'<a href="urma://helloworld.tltc//x">', b'<a href="%s//x">' % H),
        (b'<a href="urma://a.tltc/">', b'<a href="https://a.tltc.urma-portal.rosint.org/">'),
        (b'<a href="urma://x-1.tltc/">', b'<a href="https://x-1.tltc.urma-portal.rosint.org/">'),
        (b'<a href="urma://a--b.tltc/">', b'<a href="https://a--b.tltc.urma-portal.rosint.org/">'),
        (b'<a href="urma://' + b"z" * 63 + b'.tltc/">', b'<a href="https://' + b"z" * 63 + b'.tltc.urma-portal.rosint.org/">'),
    ])
    case("short-names-any-suffix", "6.3: a short name maps to its name host whether or not G(s) exists", [
        (b'<a href="urma://helloworld.ltc/">', b'<a href="https://helloworld.ltc.urma-portal.rosint.org/">'),
        (b'<a href="urma://helloworld.btc/x">', b'<a href="https://helloworld.btc.urma-portal.rosint.org/x">'),
        (b'<a href="urma://helloworld.tbtc">', b'<a href="https://helloworld.tbtc.urma-portal.rosint.org/">'),
    ])
    case("explicit-registry", "6.3: explicit g.name.s maps to the name host iff g = G(s), otherwise to /unavailable", [
        (b'<a href="urma://' + ROSINT + b'.urma.tltc/how.html">', b'<a href="%s/how.html">' % U),
        (b'<a href="urma://' + ROSINT + b'.urma.tltc?x#y">', b'<a href="%s/?x#y">' % U),
        (b'<a href="urma://' + OTHER + b'.urma.tltc/how.html">',
         b'<a href="' + gone(b"urma://" + OTHER + b".urma.tltc/how.html") + b'">'),
        (b'<a href="urma://' + ROSINT + b'.urma.ltc/">', b'<a href="' + gone(b"urma://" + ROSINT + b".urma.ltc/") + b'">'),
        (b'<a href="urma://' + ROSINT + b'.urma.btc">', b'<a href="' + gone(b"urma://" + ROSINT + b".urma.btc") + b'">'),
        (b'<a href="urma://' + ROSINT + b'.urma.tbtc/x">', b'<a href="' + gone(b"urma://" + ROSINT + b".urma.tbtc/x") + b'">'),
    ])
    case("publication-addresses", "6.3: a publication address r.s always maps to /unavailable", [
        (b'<a href="urma://' + URMA + b'.tltc/">', b'<a href="' + gone(b"urma://" + URMA + b".tltc/") + b'">'),
        (b'<a href="urma://' + URMA + b'.ltc">', b'<a href="' + gone(b"urma://" + URMA + b".ltc") + b'">'),
        (b'<a href="urma://' + URMA + b'.tltc?x=1#y">', b'<a href="' + gone(b"urma://" + URMA + b".tltc?x=1#y") + b'">'),
        (b'<a href="urma://' + ROSINT + b'.tltc/">', b'<a href="' + gone(b"urma://" + ROSINT + b".tltc/") + b'">'),
    ])
    rejected = [b"HelloWorld.tltc/", b"helloworld.TLTC/", b"user@helloworld.tltc/", b"helloworld.tltc:8080/",
                b"hello%77orld.tltc/", b"helloworld..tltc/", b"helloworld.tltc./", b".helloworld.tltc/", b"/path", b"",
                b"helloworld.com/", b"-bad.tltc/", b"bad-.tltc/", b"ab--cd.tltc/", b"under_score.tltc/",
                b"g" * 64 + b".tltc/", b"a.b.tltc/", b"a.b.c.tltc/", b"tltc/", ROSINT.upper() + b".helloworld.tltc/",
                ROSINT + b"." + URMA + b".tltc/", URMA.upper() + b".tltc/", b"h\xc3\xa9llo.tltc/", b"urma.tltc\xc2\xa0/",
                b"urma.tltc\\x"]
    lines = [(b'<a href="urma://' + host + b'">', None) for host in rejected]
    lines += [(b'<a href="' + other + b'">', None) for other in [
        b"urma:helloworld.tltc", b"urma:/helloworld.tltc/", b"Urma://helloworld.tltc/", b"urma//helloworld.tltc/",
        b"https://example.com/", b"about.html", b"#top", b"", b"urma://urma.tltc/".replace(b"/", b"&#47;")]]
    lines.append((b"<a href>", None))
    case("non-canonical-addresses", "6.2: an address that is not canonical per BROWSER_CONTRACT 4, or not urma://, is left untouched", lines)
    case("local-parameters", "6: D = localhost:<port> uses S = http", [
        (b'<a href="urma://urma.tltc/how.html">', b'<a href="http://urma.tltc.localhost:8080/how.html">'),
        (b"<A HREF='urma://helloworld.tltc'>", b"<A HREF='http://helloworld.tltc.localhost:8080/'>"),
        (b"<meta http-equiv=\"refresh\" content=\"0;URL='urma://urma.tltc/how.html'\">",
         b"<meta http-equiv=\"refresh\" content=\"0;URL='http://urma.tltc.localhost:8080/how.html'\">"),
        (b'<form action="urma://' + URMA + b'.tltc/x">',
         b'<form action="http://localhost:8080/unavailable?u=urma%3A%2F%2F' + URMA + b'.tltc%2Fx">'),
    ], parameters="local")


def attributes():
    case("attribute-syntax", "6.1: quoted, unquoted and spaced values, missing whitespace, slashes and FF as separators", [
        (b'<a href="urma://urma.tltc/double">', b'<a href="%s/double">' % U),
        (b"<a href='urma://urma.tltc/single'>", b"<a href='%s/single'>" % U),
        (b"<a href=urma://urma.tltc/unquoted>", b"<a href=%s/unquoted>" % U),
        (b"<a href=urma://urma.tltc/ class=x>", b"<a href=%s/ class=x>" % U),
        (b"<a href=urma://urma.tltc/unquoted-slash/>", b"<a href=%s/unquoted-slash/>" % U),
        (b'<a href = "urma://urma.tltc/spaced" >', b'<a href = "%s/spaced" >' % U),
        (b"<a href=\n'urma://urma.tltc/newline'>", b"<a href=\n'%s/newline'>" % U),
        (b'<a class="x"href="urma://urma.tltc/adjacent">', b'<a class="x"href="%s/adjacent">' % U),
        (b'<a href="urma://urma.tltc/self"/>', b'<a href="%s/self"/>' % U),
        (b'<a/href="urma://urma.tltc/slash">', b'<a/href="%s/slash">' % U),
        (b'<a / href="urma://urma.tltc/slashes"//>', b'<a / href="%s/slashes"//>' % U),
        (b'<a\x0chref="urma://urma.tltc/ff">', b'<a\x0chref="%s/ff">' % U),
        (b'<a hReF="urma://urma.tltc/mixed">', b'<a hReF="%s/mixed">' % U),
        (b'<a title="x>y" href="urma://urma.tltc/gt-in-value">', b'<a title="x>y" href="%s/gt-in-value">' % U),
    ])
    case("attribute-first-wins", "6.1: only the first attribute of a name counts; the tokenizer drops later duplicates", [
        (b'<a href="urma://urma.tltc/first" href="urma://urma.tltc/second">',
         b'<a href="%s/first" href="urma://urma.tltc/second">' % U),
        (b'<a href="about.html" href="urma://urma.tltc/second">', None),
        (b'<a href HREF="urma://urma.tltc/second">', None),
        (b'<a HREF="urma://urma.tltc/first" href="urma://urma.tltc/second">',
         b'<a HREF="%s/first" href="urma://urma.tltc/second">' % U),
        (b'<form action="urma://urma.tltc/a" action="urma://urma.tltc/b">',
         b'<form action="%s/a" action="urma://urma.tltc/b">' % U),
        (b'<meta http-equiv="content-type" http-equiv="refresh" content="0; url=urma://urma.tltc/">', None),
        (b'<meta http-equiv="refresh" content="5" content="0; url=urma://urma.tltc/">', None),
    ])
    case("attribute-names", "6.1: attribute names run to whitespace, /, > or = and compare after ASCII lowercasing only", [
        (b'<a =href="urma://urma.tltc/">', None),
        (b'<a data-href="urma://urma.tltc/">', None),
        (b'<a hrefx="urma://urma.tltc/">', None),
        (b'<a href"x"="urma://urma.tltc/">', None),
        (b'<a h\xc3\xa9ref="urma://urma.tltc/">', None),
        (b'<a href\x00="urma://urma.tltc/">', None),
    ])
    case("slot-elements", "6.2: the slots are a and area href, form action and meta refresh content; namespaces are ignored", [
        (b'<area href="urma://urma.tltc/area">', b'<area href="%s/area">' % U),
        (b'<form method="post" action=urma://urma.tltc?q=1>', b'<form method="post" action=%s/?q=1>' % U),
        (b'<svg><a href="urma://urma.tltc/svg"></a></svg>', b'<svg><a href="%s/svg"></a></svg>' % U),
        (b'<math><a href="urma://urma.tltc/math"></a></math>', b'<math><a href="%s/math"></a></math>' % U),
        (b'<link rel="next" href="urma://urma.tltc/">', None),
        (b'<base href="urma://urma.tltc/">', None),
        (b'<img src="urma://urma.tltc/i.png" srcset="urma://urma.tltc/j.png 2x">', None),
        (b'<button formaction="urma://urma.tltc/">b</button>', None),
        (b'<input type="submit" formaction="urma://urma.tltc/">', None),
        (b'<a action="urma://urma.tltc/">', None),
        (b'<form href="urma://urma.tltc/">', None),
        (b'<abbr href="urma://urma.tltc/">', None),
        (b'<a2 href="urma://urma.tltc/">', None),
        (b'</a href="urma://urma.tltc/end-tag">', None),
        (b'<p data-href="urma://urma.tltc/">urma://urma.tltc/ in text</p>', None),
        (b'<iframe src="urma://urma.tltc/"></iframe>', None),
        (b"<iframe srcdoc=\"<a href='urma://urma.tltc/'>\"></iframe>", None),
        (b'<object data="urma://urma.tltc/"></object>', None),
    ])


def refresh():
    case("meta-refresh-forms", "6.2: the URL of the shared declarative refresh steps over the raw content bytes", [
        (b'<meta http-equiv="refresh" content="0;url=urma://urma.tltc/a">',
         b'<meta http-equiv="refresh" content="0;url=%s/a">' % U),
        (b'<meta http-equiv="refresh" content="0; URL=urma://urma.tltc/b">',
         b'<meta http-equiv="refresh" content="0; URL=%s/b">' % U),
        (b'<meta http-equiv="refresh" content="0 ; url = urma://urma.tltc/c">',
         b'<meta http-equiv="refresh" content="0 ; url = %s/c">' % U),
        (b'<meta http-equiv="refresh" content="0,url=urma://urma.tltc/d">',
         b'<meta http-equiv="refresh" content="0,url=%s/d">' % U),
        (b'<meta http-equiv="refresh" content="  5  urma://urma.tltc/e">',
         b'<meta http-equiv="refresh" content="  5  %s/e">' % U),
        (b'<meta http-equiv="refresh" content="0;urma://urma.tltc/f">',
         b'<meta http-equiv="refresh" content="0;%s/f">' % U),
        (b'<meta http-equiv="refresh" content=".5; url=urma://urma.tltc/g">',
         b'<meta http-equiv="refresh" content=".5; url=%s/g">' % U),
        (b'<meta http-equiv="refresh" content="1.5.2; url=urma://urma.tltc/h">',
         b'<meta http-equiv="refresh" content="1.5.2; url=%s/h">' % U),
        (b"<meta http-equiv=\"refresh\" content=\"0; url='urma://urma.tltc/i'\">",
         b"<meta http-equiv=\"refresh\" content=\"0; url='%s/i'\">" % U),
        (b"<meta http-equiv=\"refresh\" content='0; url=\"urma://urma.tltc/j\" trailing'>",
         b"<meta http-equiv=\"refresh\" content='0; url=\"%s/j\" trailing'>" % U),
        (b"<meta http-equiv=\"refresh\" content=\"0; url='urma://urma.tltc/k\">",
         b"<meta http-equiv=\"refresh\" content=\"0; url='%s/k\">" % U),
        (b"<meta http-equiv=\"refresh\" content=\"0; 'urma://urma.tltc/l'\">",
         b"<meta http-equiv=\"refresh\" content=\"0; '%s/l'\">" % U),
        (b"<meta http-equiv=REFRESH content=0;url=urma://urma.tltc/m>",
         b"<meta http-equiv=REFRESH content=0;url=%s/m>" % U),
        (b'<meta content="0; url=urma://urma.tltc/n" http-equiv="refresh">',
         b'<meta content="0; url=%s/n" http-equiv="refresh">' % U),
        (b'<META HTTP-EQUIV="REFRESH" CONTENT="0; URL=urma://urma.tltc/o">',
         b'<META HTTP-EQUIV="REFRESH" CONTENT="0; URL=%s/o">' % U),
        (b'<meta http-equiv="refresh" content="0;\turl=\turma://urma.tltc/p">',
         b'<meta http-equiv="refresh" content="0;\turl=\t%s/p">' % U),
        (b"<meta http-equiv=\"refresh\" content=\"0; url ='urma://urma.tltc/q'\">",
         b"<meta http-equiv=\"refresh\" content=\"0; url ='%s/q'\">" % U),
        (b"<meta http-equiv=\"refresh\" content=\"0; url='urma://urma.tltc/r'x'\">",
         b"<meta http-equiv=\"refresh\" content=\"0; url='%s/r'x'\">" % U),
        (b'<meta http-equiv="refresh" content="0;url=urma://urma.tltc?s">',
         b'<meta http-equiv="refresh" content="0;url=%s/?s">' % U),
        (b'<meta http-equiv="refresh" content="0; url=urma://' + URMA + b'.tltc/t">',
         b'<meta http-equiv="refresh" content="0; url=' + gone(b"urma://" + URMA + b".tltc/t") + b'">'),
    ])
    case("meta-refresh-no-slot", "6.2: no slot when the refresh steps end before a URL, and no match for a non-canonical URL", [
        (b'<meta http-equiv="refresh" content="5">', None),
        (b'<meta http-equiv="refresh" content="0;">', None),
        (b'<meta http-equiv="refresh" content="0; ">', None),
        (b'<meta http-equiv="refresh" content="x; url=urma://urma.tltc/">', None),
        (b'<meta http-equiv="refresh" content="; url=urma://urma.tltc/">', None),
        (b'<meta http-equiv="refresh" content="0x; url=urma://urma.tltc/">', None),
        (b'<meta http-equiv="refresh" content="-1; url=urma://urma.tltc/">', None),
        (b'<meta http-equiv="refresh" content="0;;url=urma://urma.tltc/">', None),
        (b'<meta http-equiv="refresh" content="0; urlurma://urma.tltc/">', None),
        (b'<meta http-equiv="refresh" content="0; url=urma&#58;//urma.tltc/">', None),
        (b'<meta http-equiv="refresh" content="0; url=URMA://urma.tltc/">', None),
        (b'<meta http-equiv="refresh" content="0; url=urma://urma.tltc/a b">', None),
        (b'<meta http-equiv="refresh " content="0; url=urma://urma.tltc/">', None),
        (b'<meta http-equiv="&#114;efresh" content="0; url=urma://urma.tltc/">', None),
        (b'<meta name="refresh" content="0; url=urma://urma.tltc/">', None),
        (b'<meta http-equiv="content-type" content="0; url=urma://urma.tltc/">', None),
        (b'<meta content="0; url=urma://urma.tltc/">', None),
        (b'<meta http-equiv="refresh">', None),
        (b'<metas http-equiv="refresh" content="0; url=urma://urma.tltc/">', None),
    ])


def contexts():
    case("rcdata", "6.1: title and textarea switch to RCDATA until the appropriate end tag, end-tag attributes included", [
        (b'<title><a href="urma://urma.tltc/in-title"></title>', None),
        (b'<a href="urma://urma.tltc/after-title">', b'<a href="%s/after-title">' % U),
        (b'<textarea><a href="urma://urma.tltc/in-textarea"></TEXTAREA>', None),
        (b'<a href="urma://urma.tltc/after-textarea">', b'<a href="%s/after-textarea">' % U),
        (b'<title></titlex><a href="urma://urma.tltc/still-title"></title >', None),
        (b'<a href="urma://urma.tltc/after-spaced-end">', b'<a href="%s/after-spaced-end">' % U),
        (b"<title></title x=\"><a href='urma://urma.tltc/end-tag-attribute'>\">", None),
        (b'<a href="urma://urma.tltc/after-end-tag-attribute">', b'<a href="%s/after-end-tag-attribute">' % U),
        (b'<title/><a href="urma://urma.tltc/self-closing-title"></title>', None),
        (b'<textarea></text><a href="urma://urma.tltc/partial-name"></textarea\n>', None),
        (b'<a href="urma://urma.tltc/after-newline-end">', b'<a href="%s/after-newline-end">' % U),
    ])
    case("rawtext", "6.1: style, xmp, iframe, noembed and noframes switch to RAWTEXT; noscript does not switch", [
        (b"<style>a::after{content:\"<a href='urma://urma.tltc/in-style'>\"}</style>", None),
        (b'<xmp><a href="urma://urma.tltc/in-xmp"></xmp>', None),
        (b'<iframe><a href="urma://urma.tltc/in-iframe"></iframe>', None),
        (b'<noembed><a href="urma://urma.tltc/in-noembed"></noembed>', None),
        (b'<noframes><a href="urma://urma.tltc/in-noframes"></noframes>', None),
        (b'<a href="urma://urma.tltc/after-rawtext">', b'<a href="%s/after-rawtext">' % U),
        (b'<noscript><a href="urma://urma.tltc/in-noscript"></noscript>',
         b'<noscript><a href="%s/in-noscript"></noscript>' % U),
        (b'<STYLE><a href="urma://urma.tltc/in-upper-style"></Style><a href="urma://urma.tltc/after-upper-style">',
         b'<STYLE><a href="urma://urma.tltc/in-upper-style"></Style><a href="%s/after-upper-style">' % U),
    ])
    case("plaintext", "6.1: plaintext switches to PLAINTEXT, which never ends", [
        (b'<a href="urma://urma.tltc/before">', b'<a href="%s/before">' % U),
        (b'<plaintext><a href="urma://urma.tltc/in-plaintext"></plaintext>', None),
        (b'<a href="urma://urma.tltc/after-end-tag">', None),
    ])
    case("script-data", "6.1: script switches to script data until </script>, whatever the namespace or self-closing flag", [
        (b"<script>document.write('<a href=\"urma://urma.tltc/in-script\">')</script>", None),
        (b'<a href="urma://urma.tltc/after-script">', b'<a href="%s/after-script">' % U),
        (b"<script type=\"module\">let x = \"</scrip\"; let y = '<a href=\"urma://urma.tltc/still-script\">'</script >", None),
        (b'<a href="urma://urma.tltc/after-spaced-end">', b'<a href="%s/after-spaced-end">' % U),
        (b"<script/>'<a href=\"urma://urma.tltc/self-closing-script\">'</script>", None),
        (b"<svg><script>'<a href=\"urma://urma.tltc/svg-script\">'</script></svg>", None),
        (b"<SCRIPT>'<a href=\"urma://urma.tltc/upper\">'</ScRiPt><a href=\"urma://urma.tltc/after-upper\">",
         b"<SCRIPT>'<a href=\"urma://urma.tltc/upper\">'</ScRiPt><a href=\"%s/after-upper\">" % U),
        (b"<script></script x='><a href=\"urma://urma.tltc/end-tag-attribute\">'>", None),
        (b'<a href="urma://urma.tltc/after-end-tag-attribute">', b'<a href="%s/after-end-tag-attribute">' % U),
    ])
    case("script-escaped", "6.1: the script data escaped and double escaped states", [
        (b"<script><!-- '<a href=\"urma://urma.tltc/escaped\">' --></script>", None),
        (b'<a href="urma://urma.tltc/after-escaped">', b'<a href="%s/after-escaped">' % U),
        (b"<script><!--<script>'</script><a href=\"urma://urma.tltc/double-escaped\">'--></script>", None),
        (b'<a href="urma://urma.tltc/after-double-escaped">', b'<a href="%s/after-double-escaped">' % U),
        (b'<script><!--<script></script>--><a href="urma://urma.tltc/escaped-then-data"></script>', None),
        (b'<script><!--</script><a href="urma://urma.tltc/after-escaped-end">',
         b'<script><!--</script><a href="%s/after-escaped-end">' % U),
        (b'<script>--><a href="urma://urma.tltc/dashes-in-data"></script>', None),
        (b'<script><!--<script>--><a href="urma://urma.tltc/double-then-data"></script><a href="urma://urma.tltc/after-double-exit">',
         b'<script><!--<script>--><a href="urma://urma.tltc/double-then-data"></script><a href="%s/after-double-exit">' % U),
        (b"<script><!--<SCRIPT >'</Script/><a href=\"urma://urma.tltc/case-folded\">'--></script><a href=\"urma://urma.tltc/after-case-folded\">",
         b"<script><!--<SCRIPT >'</Script/><a href=\"urma://urma.tltc/case-folded\">'--></script><a href=\"%s/after-case-folded\">" % U),
        (b"<script><!--<scripty>'</script><a href=\"urma://urma.tltc/not-double\">",
         b"<script><!--<scripty>'</script><a href=\"%s/not-double\">" % U),
        (b'<script><!-x</script><a href="urma://urma.tltc/after-false-escape">',
         b'<script><!-x</script><a href="%s/after-false-escape">' % U),
        (b'<script><!--->\'</script><a href="urma://urma.tltc/after-dashes">',
         b'<script><!--->\'</script><a href="%s/after-dashes">' % U),
    ])
    case("comments", "6.1: comments end at -->, --!>, or right after <!-- and <!---; the less-than sign states change nothing", [
        (b'<!-- <a href="urma://urma.tltc/in-comment"> -->', None),
        (b'<a href="urma://urma.tltc/after-comment">', b'<a href="%s/after-comment">' % U),
        (b'<!--><a href="urma://urma.tltc/after-abrupt">', b'<!--><a href="%s/after-abrupt">' % U),
        (b'<!---><a href="urma://urma.tltc/after-abrupt-dash">', b'<!---><a href="%s/after-abrupt-dash">' % U),
        (b'<!----><a href="urma://urma.tltc/after-empty">', b'<!----><a href="%s/after-empty">' % U),
        (b'<!-- --!><a href="urma://urma.tltc/after-bang-close">', b'<!-- --!><a href="%s/after-bang-close">' % U),
        (b'<!-- ---><a href="urma://urma.tltc/after-triple-dash">', b'<!-- ---><a href="%s/after-triple-dash">' % U),
        (b'<!-- <!-- nested --><a href="urma://urma.tltc/after-nested">', b'<!-- <!-- nested --><a href="%s/after-nested">' % U),
        (b'<!-- -- ><a href="urma://urma.tltc/in-spaced-close"> -->', None),
        (b'<!-- --!-><a href="urma://urma.tltc/in-bang-dash"> -->', None),
        (b'<!-- a > <a href="urma://urma.tltc/in-gt"> -->', None),
        (b'<!--!><a href="urma://urma.tltc/in-bang-start"> -->', None),
    ])
    case("bogus-comments-and-doctype", "6.1: DOCTYPE, <?, <!x, </ followed by a non-letter and <![CDATA[ all end at the next >", [
        (b'<!DOCTYPE html><a href="urma://urma.tltc/after-doctype">', b'<!DOCTYPE html><a href="%s/after-doctype">' % U),
        (b'<!DOCTYPE html PUBLIC "-//x>y" "z"><a href="urma://urma.tltc/after-doctype-gt">',
         b'<!DOCTYPE html PUBLIC "-//x>y" "z"><a href="%s/after-doctype-gt">' % U),
        (b'<?xml version="1.0"?><a href="urma://urma.tltc/after-pi">', b'<?xml version="1.0"?><a href="%s/after-pi">' % U),
        (b'<? <a href="urma://urma.tltc/in-pi"> ?>', None),
        (b'<!x <a href="urma://urma.tltc/in-bogus">', None),
        (b'</1 <a href="urma://urma.tltc/in-bogus-end">', None),
        (b'</ <a href="urma://urma.tltc/in-bogus-space">', None),
        (b'<![CDATA[<a href="urma://urma.tltc/in-cdata">]]>', None),
        (b'<!-x><a href="urma://urma.tltc/after-bogus-dash">', b'<!-x><a href="%s/after-bogus-dash">' % U),
        (b'</><a href="urma://urma.tltc/after-empty-end">', b'</><a href="%s/after-empty-end">' % U),
    ])
    case("svg-cdata-is-bogus-comment", "6.1: <![CDATA[ starts a bogus comment even inside svg, ending at the first >", [
        (b'<svg><![CDATA[ > <a href="urma://urma.tltc/after-first-gt"> ]]></svg>',
         b'<svg><![CDATA[ > <a href="%s/after-first-gt"> ]]></svg>' % U),
        (b'<svg><![CDATA[<a href="urma://urma.tltc/in-cdata"> ]]></svg>', None),
    ])
    case("markup-edges", "6.1: < needs an ASCII letter to open a tag; a tag name runs to whitespace, / or >", [
        (b'< a href="urma://urma.tltc/space-after-lt">', None),
        (b'<<a href="urma://urma.tltc/double-lt">', b'<<a href="%s/double-lt">' % U),
        (b'<a<b href="urma://urma.tltc/lt-in-name">', None),
        (b'<\xc3\xa0 href="urma://urma.tltc/non-ascii-name">', None),
        (b'<a\xc2\xa0href="urma://urma.tltc/nbsp">', None),
        (b'<a\x00 href="urma://urma.tltc/nul-in-name">', None),
        (b'<a\x0bhref="urma://urma.tltc/vertical-tab">', None),
        (b'\x00<a href="urma://urma.tltc/after-nul">', b'\x00<a href="%s/after-nul">' % U),
        (b'&lt;a href="urma://urma.tltc/escaped-lt">', None),
    ])
    case("eof-in-tag", "6.1: a start tag cut by the end of the input is never emitted", [
        (b'<a href="urma://urma.tltc/complete">', b'<a href="%s/complete">' % U),
        (b'<a href="urma://urma.tltc/unterminated"', None),
    ], newline=False)
    case("eof-in-attribute-value", "6.1: an attribute value left open at the end of the input drops its tag", [
        (b'<a href="urma://urma.tltc/complete">', b'<a href="%s/complete">' % U),
        (b'<a href="urma://urma.tltc/open>', None),
    ], newline=False)


def encodings():
    case("latin1-document", "6.1: bytes >= 0x80 are ordinary characters, copied in T and pct-encoded byte by byte", [
        (b"<p>caf\xe9</p>", None),
        (b'<a href="urma://urma.tltc/caf\xe9">', b'<a href="%s/caf\xe9">' % U),
        (b'<a href="urma://' + URMA + b'.tltc/caf\xe9">',
         b'<a href="https://urma-portal.rosint.org/unavailable?u=urma%3A%2F%2F' + URMA + b'.tltc%2Fcaf%E9">'),
    ])
    case("invalid-utf8-document", "6.1: no decoding and no sniffing; a UTF-16 byte order mark before ASCII markup changes nothing", [
        (b"\xff\xfe<title>\xc3\x28</title>", None),
        (b'<a href="urma://urma.tltc/p">\x80\xbf', b'<a href="%s/p">\x80\xbf' % U),
    ])
    case("utf8-bom-document", "6.1: a UTF-8 byte order mark is three ordinary characters", [
        (b'\xef\xbb\xbf<a href="urma://urma.tltc/">', b'\xef\xbb\xbf<a href="%s/">' % U),
    ])
    markup = '<a href="urma://urma.tltc/">\n'
    case("utf16le-document", "6.1: a UTF-16 document stays unchanged", [
        (("\ufeff" + markup).encode("utf-16-le"), None)], newline=False)
    case("utf16be-document", "6.1: a UTF-16 document stays unchanged", [
        (("\ufeff" + markup).encode("utf-16-be"), None)], newline=False)
    case("carriage-returns", "6.1: CR is treated as LF; a CR inside C stops the match", [
        (b'<a\rhref="urma://urma.tltc/cr-separator">\r', b'<a\rhref="%s/cr-separator">\r' % U),
        (b'<a\r\nhref="urma://urma.tltc/crlf-separator">', b'<a\r\nhref="%s/crlf-separator">' % U),
        (b'<a href\r=\r"urma://urma.tltc/cr-around-equals">', b'<a href\r=\r"%s/cr-around-equals">' % U),
        (b"<a href=\rurma://urma.tltc/cr-unquoted\r>", b"<a href=\r%s/cr-unquoted\r>" % U),
        (b'<a href="\rurma://urma.tltc/cr-leading\r">', b'<a href="\r%s/cr-leading\r">' % U),
        (b'<title>\r</title\r><a href="urma://urma.tltc/after-cr-end-tag">',
         b'<title>\r</title\r><a href="%s/after-cr-end-tag">' % U),
        (b'<meta http-equiv="refresh" content="0;\r\nurl=urma://urma.tltc/cr-refresh\r">',
         b'<meta http-equiv="refresh" content="0;\r\nurl=%s/cr-refresh\r">' % U),
        (b'<a href="urma://urma.tltc/cr\rinside">', None),
    ])


def pages():
    page = [
        (b"<!doctype html>", None),
        (b"<html><head>", None),
        (b'<meta charset="utf-8">', None),
        (b'<meta http-equiv="refresh" content="30; url=urma://helloworld.tltc/next.html">',
         b'<meta http-equiv="refresh" content="30; url=%s/next.html">' % H),
        (b'<link rel="stylesheet" href="urma://helloworld.tltc/style.css">', None),
        (b"</head><body>", None),
        (b'<a href="urma://helloworld.tltc/about.html?x=1&amp;y=2#team">About</a>',
         b'<a href="%s/about.html?x=1&amp;y=2#team">About</a>' % H),
        (b"<a href='urma://" + ROSINT + b".urma.tltc/'>Explicit</a>", b"<a href='%s/'>Explicit</a>" % U),
        (b"<a href=urma://urma.tltc>Unquoted</a>", b"<a href=%s/>Unquoted</a>" % U),
        (b"<a", None),
        (b'   class="x"   href="urma://HelloWorld.tltc/">Upper host</a>', None),
        (b'<map name="m"><area shape="rect" coords="0,0,1,1" href="urma://' + URMA + b'.tltc/x"></map>',
         b'<map name="m"><area shape="rect" coords="0,0,1,1" href="' + gone(b"urma://" + URMA + b".tltc/x") + b'"></map>'),
        (b'<form action="urma://' + OTHER + b'.helloworld.tltc/search" method="get"></form>',
         b'<form action="' + gone(b"urma://" + OTHER + b".helloworld.tltc/search") + b'" method="get"></form>'),
        (b'<img src="urma://helloworld.tltc/logo.png">', None),
        (b'<a href="relative.html" data-x="urma://helloworld.tltc/">Relative</a>', None),
        (b'<script>location.href = "urma://helloworld.tltc/";</script>', None),
        (b"<p>urma://helloworld.tltc/ in text</p>", None),
        (b"</body></html>", None),
    ]
    case("page-mixed", "6.3: a whole page; only matched candidates change, in document order", page)
    hello = [(line, None) for line in [
        b"<!doctype html>", b'<html lang="en">', b"<head>", b'<meta charset="utf-8">', b"<title>Hello World</title>",
        b'<link rel="stylesheet" href="style.css">', b"</head>", b"<body>", b"<main>", b"<h1>Hello World</h1>",
        b"</main>", b"</body>", b"</html>"]]
    case("page-without-links", "6.3: a page without urma:// slots is served unchanged", hello)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for stale in OUT.iterdir():
        stale.unlink()
    spec()
    slots()
    targets()
    attributes()
    refresh()
    contexts()
    encodings()
    pages()
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"{len(manifest['cases'])} cases in {OUT}")


if __name__ == "__main__":
    main()
