#!/usr/bin/env python3
# SPDX-License-Identifier: 0BSD
"""Generate URMAWEB1 revision 2 package vectors without any URMA library.
Each file is a complete package payload (the bytes a root manifest would carry)."""
import hashlib
import json
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "tests/vectors/web"
ROOT = bytes(range(0x80, 0xa0))
DIGEST = bytes(range(0xa0, 0xc0))
PNG = bytes.fromhex("89504e470d0a1a0a0000000d494844520000000100000001080600000" "01f15c4890000000d49444154789c6360f8cfc00000030001010f9a4b1a0000000049454e44ae426082")
manifest = {"profile": "URMAWEB1", "revision": 2, "license": "CC0-1.0", "cases": []}


def sha(data):
    return hashlib.sha256(data).digest()


def uint(n, size):
    return n.to_bytes(size, "little")


def entry(path, mime, data, length=None, digest=None):
    return (uint(len(path), 2) + path + bytes([len(mime)]) + mime
            + uint(len(data) if length is None else length, 8) + (sha(data) if digest is None else digest))


def pin(path, mime, txid=ROOT, digest=DIGEST):
    return uint(len(path), 2) + path + bytes([len(mime)]) + mime + txid + digest


def package(files, pins=(), entry_index=0, label=b"", revision=2, flags=0, file_count=None,
            pinned_count=None, data=None, overrides=()):
    header = (bytes([revision, flags]) + uint(len(files) if file_count is None else file_count, 2)
              + uint(len(pins) if pinned_count is None else pinned_count, 2) + uint(entry_index, 2)
              + bytes([len(label)]) + label)
    table = b"".join(entry(p, m, d, *o) for (p, m, d), o in zip(files, list(overrides) + [()] * (len(files) - len(overrides))))
    table += b"".join(pin(*p) for p in pins)
    body = b"".join(d for _, _, d in files) if data is None else data
    return header + table + body


def case(name, payload, outcome):
    (OUT / (name + ".package")).write_bytes(payload)
    manifest["cases"].append({"name": name, "outcome": outcome,
                              "record": {"file": name + ".package", "bytes": len(payload), "sha256": sha(payload).hex()}})


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    html = b"<!doctype html><meta charset=utf-8><title>Atelier</title><p>\xc8\x99tire</p>"
    minimal = [(b"index.html", b"text/html", html)]
    site = [(b"app.js", b"text/javascript", b"document.title='x';\n"),
            (b"assets/logo.png", b"image/png", PNG),
            (b"index.html", b"text/html;charset=utf-8", html),
            (b"style.css", b"text/css", b"body{margin:0}")]
    apk = [(b"downloads/wire.apk", b"application/vnd.android.package-archive")]
    case("minimal", package(minimal), "valid")
    case("site", package(site, apk, entry_index=2, label=b"Atelier demo"), "valid")
    case("empty-file", package([(b"empty.txt", b"text/plain", b""), (b"index.html", b"text/html", html)], entry_index=1), "valid")
    case("label-max", package(minimal, label=b"L" * 64), "valid")
    deep = b"/".join([b"a"] * 31) + b"/z.txt"
    case("deep-path", package([(deep, b"text/plain", b"deep"), (b"index.html", b"text/html", html)], entry_index=1), "valid")
    case("binary", package([(b"blob.bin", b"application/octet-stream", bytes(range(256)) * 4), (b"index.html", b"text/html", html)], entry_index=1), "valid")
    case("two-pins", package(minimal, [(b"a.bin", b"application/octet-stream"), (b"b.bin", b"application/octet-stream", bytes(32), bytes(32))]), "valid")
    invalid = [
        ("revision-01", package(minimal, revision=1)),
        ("flags-01", package(minimal, flags=1)),
        ("no-files", package([], file_count=0)),
        ("entry-out-of-range", package(minimal, entry_index=1)),
        ("label-65", package(minimal, label=b"L" * 65)),
        ("label-nonprintable", package(minimal, label=b"a\x01b")),
        ("unsorted-files", package([(b"index.html", b"text/html", html), (b"app.js", b"text/javascript", b"1")])),
        ("duplicate-path", package([(b"index.html", b"text/html", html), (b"index.html", b"text/html", html)])),
        ("duplicate-across-tables", package([(b"index.html", b"text/html", html), (b"x.bin", b"application/octet-stream", b"1")], [(b"x.bin", b"application/octet-stream")])),
        ("unsorted-pins", package(minimal, [(b"b.bin", b"application/octet-stream"), (b"a.bin", b"application/octet-stream")])),
        ("leading-slash", package([(b"/index.html", b"text/html", html)])),
        ("dotdot-segment", package([(b"../index.html", b"text/html", html)])),
        ("dot-segment", package([(b"./index.html", b"text/html", html)])),
        ("empty-segment", package([(b"a//index.html", b"text/html", html)])),
        ("trailing-slash", package([(b"index.html/", b"text/html", html)])),
        ("space-in-path", package([(b"index page.html", b"text/html", html)])),
        ("utf8-path", package([("știre.html".encode(), b"text/html", html)])),
        ("uppercase-mime", package([(b"index.html", b"TEXT/HTML", html)])),
        ("mime-no-slash", package([(b"index.html", b"html", html)])),
        ("mime-bad-parameter", package([(b"index.html", b"text/html;charset=latin1", html)])),
        ("mime-two-parameters", package([(b"index.html", b"text/html;charset=utf-8;charset=utf-8", html)])),
        ("entry-not-html", package([(b"index.html", b"text/css", html)])),
        ("hash-mismatch", package(minimal, overrides=[(None, bytes(32))])),
        ("length-short", package(minimal, overrides=[(len(html) + 1, None)])),
        ("length-long", package(minimal, overrides=[(len(html) - 1, None)])),
        ("trailing-bytes", package(minimal) + b"\x00"),
        ("truncated", package(minimal)[:-1]),
        ("pinned-count-mismatch", package(minimal, pinned_count=1)),
        ("file-count-mismatch", package(minimal, file_count=2)),
        ("header-only", package(minimal)[:9]),
        ("empty", b""),
    ]
    for name, payload in invalid:
        case(name, payload, "invalid")
    # Protocol-valid, outside the client's default policy limits (not normative rules).
    policy = [
        ("policy-path-1025", package([(b"a" * 1025, b"text/html", html)])),
        ("policy-segments-33", package([(b"/".join([b"a"] * 33), b"text/html", html)])),
        ("policy-segment-256", package([(b"a" * 256, b"text/html", html)])),
        ("policy-mime-129", package([(b"data.bin", b"a" * 100 + b"/" + b"b" * 28, b"x"), (b"index.html", b"text/html", html)], entry_index=1)),
        ("policy-path-65535", package([(b"/".join([b"a" * 255] * 255) + b"/" + b"b" * 255, b"text/html", html)])),
    ]
    for name, payload in policy:
        case(name, payload, "policy")
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
