#!/usr/bin/env python3
# SPDX-License-Identifier: 0BSD
"""Generate URMANAM1 (names registry profile) record vectors without any URMA library.
Every file is a complete kind 0C record: header, profile identifier, payload.
The tiny secp256k1 arithmetic only derives x-only approver keys from small test scalars.
"""
import hashlib
import json
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "tests/vectors/names"
P = 2**256 - 2**32 - 977
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
HEADER = b"URMA\x00\x0c\x00\x00"
PROFILE = b"URMANAM1"
REGISTRY = bytes(range(0x40, 0x60))
TARGET = bytes(range(0x60, 0x80))
SALT = bytes(range(16))
RECORD = bytes(range(0x80, 0xa0))
DIGEST = bytes(range(0xa0, 0xc0))
manifest = {"profile": "URMANAM1", "license": "CC0-1.0", "cases": []}


def add(left, right):
    if left is None:
        return right
    if right is None:
        return left
    x, y = left
    u, v = right
    if x == u and (y + v) % P == 0:
        return None
    slope = ((3*x*x) * pow(2*y, -1, P) if left == right else (v-y)*pow(u-x, -1, P)) % P
    z = (slope*slope-x-u) % P
    return z, (slope*(x-z)-y) % P


def multiply(scalar, point=G):
    result = None
    while scalar:
        if scalar & 1:
            result = add(result, point)
        point = add(point, point)
        scalar >>= 1
    return result


def uint(n, size):
    return n.to_bytes(size, "little")


def xonly(scalar):
    return multiply(scalar)[0].to_bytes(32, "big")


APPROVERS = sorted(xonly(s) for s in (11, 12, 13))


def genesis(mode, expiry, window, threshold, keys, rules=2):
    return b"\x00" + bytes([rules, mode]) + uint(expiry, 4) + uint(window, 2) + bytes([threshold, len(keys)]) + b"".join(keys)


def owner(op, name, target=TARGET, length=None):
    return bytes([op]) + REGISTRY + SALT + bytes([len(name) if length is None else length]) + name + target


def approve():
    return b"\x04" + REGISTRY + RECORD + DIGEST


def nameop(op, name):
    return bytes([op]) + REGISTRY + bytes([len(name)]) + name


def case(name, payload, outcome, profile=PROFILE, expect=None):
    data = HEADER + profile + payload
    (OUT / (name + ".record")).write_bytes(data)
    entry = {"name": name, "outcome": outcome,
             "record": {"file": name + ".record", "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}}
    if expect is not None:
        entry["expect"] = expect
    manifest["cases"].append(entry)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    display = lambda wire: wire[::-1].hex()
    case("genesis-open", genesis(0, 210240, 144, 0, []), "valid",
         expect={"mode": "open", "expiry_blocks": 210240, "reveal_max_blocks": 144, "threshold": 0, "approvers": []})
    case("genesis-administered", genesis(1, 210240, 144, 2, APPROVERS), "valid",
         expect={"mode": "administered", "expiry_blocks": 210240, "reveal_max_blocks": 144, "threshold": 2,
                 "approvers": [k.hex() for k in APPROVERS]})
    case("genesis-min-window", genesis(0, 2, 1, 0, []), "valid")
    case("genesis-max-approvers", genesis(1, 4320, 36, 255, sorted(xonly(s) for s in range(1, 256))), "valid")
    case("claim", owner(1, b"atelier"), "valid",
         expect={"op": 1, "registry": display(REGISTRY), "salt": SALT.hex(), "name": "atelier", "target": display(TARGET)})
    case("claim-reserve", owner(1, b"atelier", bytes(32)), "valid")
    case("claim-hyphens", owner(1, b"a--b-c"), "valid")
    case("claim-digits", owner(1, b"0"), "valid")
    case("claim-max-name", owner(1, b"x" * 63), "valid")
    case("update", owner(2, b"a"), "valid")
    case("renew", owner(3, b"z9"), "valid")
    case("approve", approve(), "valid",
         expect={"op": 4, "registry": display(REGISTRY), "record_txid": display(RECORD), "record_sha256": DIGEST.hex()})
    case("suspend", nameop(5, b"atelier"), "valid")
    case("restore", nameop(6, b"atelier"), "valid")
    invalid = [
        ("genesis-rules-01", genesis(0, 210240, 144, 0, [], rules=1)),
        ("genesis-mode-02", genesis(2, 210240, 144, 0, [])),
        ("genesis-expiry-equal-window", genesis(0, 144, 144, 0, [])),
        ("genesis-window-zero", genesis(0, 10, 0, 0, [])),
        ("genesis-open-with-approver", genesis(0, 210240, 144, 0, APPROVERS[:1])),
        ("genesis-open-with-threshold", genesis(0, 210240, 144, 1, [])),
        ("genesis-administered-threshold-zero", genesis(1, 210240, 144, 0, APPROVERS)),
        ("genesis-administered-threshold-high", genesis(1, 210240, 144, 4, APPROVERS)),
        ("genesis-administered-no-approvers", genesis(1, 210240, 144, 1, [])),
        ("genesis-approvers-unsorted", genesis(1, 210240, 144, 2, list(reversed(APPROVERS)))),
        ("genesis-approvers-duplicate", genesis(1, 210240, 144, 2, [APPROVERS[0], APPROVERS[0]])),
        ("genesis-approver-not-on-curve", genesis(1, 210240, 144, 1, [bytes([0xff]) * 32])),
        ("genesis-count-mismatch", genesis(1, 210240, 144, 2, APPROVERS)[:-1]),
        ("genesis-trailing", genesis(0, 210240, 144, 0, []) + b"\x00"),
        ("genesis-truncated", genesis(0, 210240, 144, 0, [])[:-1]),
        ("claim-empty-name", owner(1, b"")),
        ("claim-uppercase", owner(1, b"Atelier")),
        ("claim-leading-hyphen", owner(1, b"-a")),
        ("claim-trailing-hyphen", owner(1, b"a-")),
        ("claim-xn-hyphens", owner(1, b"ab--cd")),
        ("claim-name-64", owner(1, b"x" * 64)),
        ("claim-underscore", owner(1, b"a_b")),
        ("claim-space", owner(1, b"a b")),
        ("claim-utf8", owner(1, "știre".encode())),
        ("claim-trailing", owner(1, b"a") + b"\x00"),
        ("claim-truncated", owner(1, b"a")[:-1]),
        ("claim-length-mismatch", owner(1, b"abc", length=5)),
        ("update-empty-name", owner(2, b"")),
        ("renew-truncated", owner(3, b"abc")[:-1]),
        ("approve-short", approve()[:-1]),
        ("approve-long", approve() + b"\x00"),
        ("suspend-trailing", nameop(5, b"a") + b"\x00"),
        ("suspend-truncated", nameop(5, b"abc")[:-1]),
        ("restore-uppercase", nameop(6, b"A")),
        ("restore-empty-name", nameop(6, b"")),
        ("op-07", b"\x07" + REGISTRY),
        ("empty-payload", b""),
    ]
    for name, payload in invalid:
        case(name, payload, "invalid")
    case("foreign-profile", genesis(0, 210240, 144, 0, []), "foreign", profile=b"URMANAM2")
    case("zero-profile", genesis(0, 210240, 144, 0, []), "foreign", profile=bytes(8))
    (OUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")


if __name__ == "__main__":
    main()
