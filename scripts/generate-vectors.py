#!/usr/bin/env python3
# SPDX-License-Identifier: 0BSD
"""Generate URMA V0 known answers without Rust, an URMA SDK or network access.
Test secrets/padding only. Python stdlib handles hashes; OpenSSL handles AES.
The deliberately simple secp256k1 arithmetic below is for public vectors only.
"""
import hashlib
import hmac
import json
from pathlib import Path
import subprocess

OUT = Path(__file__).resolve().parents[1] / "tests/vectors"
ROOT = bytes(range(32))
OBJECT = bytes(range(32, 64))
CHUNK = 32768
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
manifest = {"protocol": "URMA", "version": 0, "license": "CC0-1.0", "private": [], "public": [], "proofs": []}


def sha(data):
    return hashlib.sha256(data).digest()


def mac(key, data):
    return hmac.digest(key, data, "sha256")


def uint(n, size):
    return n.to_bytes(size, "little")


def prefix(kind):
    return b"URMA\x00" + bytes([kind]) + b"\x00\x00"


def keys(object_id):
    prk = mac(object_id, ROOT)
    return [mac(prk, b"URMA/V0/private/" + label + b"\x01")[:size]
            for label, size in [(b"content", 32), (b"authentication", 32), (b"discovery", 16)]]


def record(data, index=0, *, object_id=OBJECT, hint=0, flags=0, length=None,
           count=None, iv=None, digest=None, padding=0xa7):
    length = len(data) if length is None else length
    count = (len(data) + CHUNK - 1) // CHUNK if count is None else count
    enc, auth, tag = keys(object_id)
    iv = index.to_bytes(8, "big") + bytes(8) if iv is None else iv
    chunk = data[index * CHUNK:(index + 1) * CHUNK]
    body = (sha(data) if digest is None else digest) + uint(length, 8) + uint(hint, 4) + uint(flags, 4)
    body += chunk + bytes([padding]) * (CHUNK - len(chunk))
    cipher = subprocess.run(["openssl", "enc", "-aes-256-ctr", "-nopad", "-nosalt",
                             "-K", enc.hex(), "-iv", iv.hex()], input=body, capture_output=True, check=True).stdout
    value = prefix(1) + object_id + tag + uint(index, 4) + uint(count, 4) + iv + cipher
    return value + mac(auth, value)


def container(records):
    return prefix(3) + uint(len(records), 4) + b"".join(uint(len(r), 4) + r for r in records)


def save(name, data):
    (OUT / name).write_bytes(data)
    return {"file": name, "bytes": len(data), "sha256": sha(data).hex()}


def private(name, records, outcome, original=None, root="root.bin", raw=None):
    case = {"name": name, "outcome": outcome, "root": root,
            "container": save(name + ".urma", container(records) if raw is None else raw)}
    if original is not None:
        case["original"] = save(name + ".original", original)
    manifest["private"].append(case)


def public(name, data, outcome="valid"):
    manifest["public"].append({"name": name, "outcome": outcome, "record": save(name + ".record", data)})


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


def be32(n):
    return n.to_bytes(32, "big")


def tagged(label, data):
    tag = sha(label.encode())
    return sha(tag + tag + data)


def sign(message, secret):
    point = multiply(secret)
    d = N-secret if point[1] & 1 else secret
    t = bytes(a ^ b for a, b in zip(be32(d), tagged("BIP0340/aux", bytes(32))))
    k = int.from_bytes(tagged("BIP0340/nonce", t + be32(point[0]) + message), "big") % N
    assert k
    r = multiply(k)
    if r[1] & 1:
        k = N-k
    challenge = int.from_bytes(tagged("BIP0340/challenge", be32(r[0]) + be32(point[0]) + message), "big") % N
    return be32(r[0]) + be32((k + challenge*d) % N)


def compact(n):
    if n < 253:
        return bytes([n])
    return b"\xfd" + uint(n, 2) if n <= 65535 else b"\xfe" + uint(n, 4)


def vector(data):
    return compact(len(data)) + data


def push(data):
    if len(data) == 1 and 1 <= data[0] <= 16:
        return bytes([0x50 + data[0]])
    if data == b"\x81":
        return b"\x4f"
    if len(data) <= 75:
        return bytes([len(data)]) + data
    if len(data) <= 255:
        return b"\x4c" + bytes([len(data)]) + data
    return b"\x4d" + uint(len(data), 2) + data


def proof(name, data, script_transform=None, outcome="valid", key=3):
    author = multiply(key)
    internal = (author[0], P-author[1]) if author[1] & 1 else author
    script = push(be32(author[0])) + b"\xac\x00\x63" + push(b"URMA")
    script += b"".join(push(data[i:i+520]) for i in range(0, len(data), 520)) + b"\x68"
    if script_transform:
        script = script_transform(script)
    leaf = tagged("TapLeaf", b"\xc0" + vector(script))
    tweak = int.from_bytes(tagged("TapTweak", be32(author[0]) + leaf), "big")
    assert tweak < N
    output_key = add(internal, multiply(tweak))
    control = bytes([0xc0 | (output_key[1] & 1)]) + be32(author[0])
    commit_script = b"\x51\x20" + be32(output_key[0])
    prevout = uint(50000, 8) + vector(commit_script)
    commit_input = bytes([0x22])*32 + uint(1, 4) + b"\x00" + uint(0xfffffffd, 4)
    commit = uint(2,4) + b"\x01" + commit_input + b"\x01" + prevout + bytes(4)
    commit_hash = sha(sha(commit))
    outpoint = commit_hash + bytes(4)
    sequence = uint(0xfffffffd, 4)
    payout = uint(1000, 8) + vector(b"\x00\x14" + bytes([0x33])*20)
    # BIP341 SIGHASH_DEFAULT, ext_flag=1, no annex; BIP342 extension.
    msg = (b"\x00" + uint(2,4) + bytes(4) + sha(outpoint) + sha(uint(50000,8))
           + sha(vector(commit_script)) + sha(sequence) + sha(payout)
           + b"\x02" + bytes(4) + leaf + b"\x00" + b"\xff"*4)
    sighash = tagged("TapSighash", b"\x00" + msg)
    sig = sign(sighash, key)
    inputs = b"\x01" + outpoint + b"\x00" + sequence
    outputs = b"\x01" + payout
    stack = b"\x03" + vector(sig) + vector(script) + vector(control)
    reveal = uint(2,4) + b"\x00\x01" + inputs + outputs + stack + bytes(4)
    txid = sha(sha(uint(2,4) + inputs + outputs + bytes(4)))[::-1].hex()
    manifest["proofs"].append({"name":name,"outcome":outcome,"commit":save(name+".commit",commit),
        "reveal":save(name+".reveal",reveal),"record_hex":data.hex(),"author":be32(author[0]).hex(),
        "txid":txid,"tapleaf":leaf.hex(),"sighash":sighash.hex(),"signature":sig.hex()})


def main():
    OUT.mkdir(exist_ok=True)
    save("root.bin", ROOT)
    save("wrong-root.bin", bytes([0xff])*32)
    enc, auth, tag = keys(OBJECT)
    manifest["kdf"] = {"root":ROOT.hex(),"object_id":OBJECT.hex(),"encryption":enc.hex(),"authentication":auth.hex(),"discovery":tag.hex()}
    one = b"URMA independent vector\x00\r\n" + "știre".encode()
    two = bytes(range(256))*128 + b"last\x00chunk"
    r = record(one, hint=1)
    pair = [record(two, i) for i in range(2)]
    private("private-text", [r], "complete", one)
    private("private-two", pair, "complete", two)
    private("private-shuffled-duplicate", [pair[1], pair[0], pair[1]], "complete", two)
    private("private-incomplete", [pair[0]], "incomplete")
    private("private-duplicate-missing", [pair[0], pair[0]], "incomplete")
    private("private-padding-conflict", [r, record(one, hint=1, padding=0xb8)], "conflict")
    private("private-type-conflict", [pair[0], record(two, 1, hint=1)], "conflict")
    private("private-mixed", [pair[0], record(two, 1, object_id=bytes([0x42])*32)], "invalid")
    private("private-wrong-root", [r], "unrelated", root="wrong-root.bin")
    for name, kwargs in [("length-zero",{"length":0}), ("length-overflow",{"length":2**64-1}),
                         ("length-count",{"length":32769}), ("type",{"hint":5}), ("metadata-flags",{"flags":1}),
                         ("iv",{"iv":bytes([1])*16}), ("digest",{"digest":bytes(32)})]:
        private("private-invalid-"+name, [record(one,**kwargs)], "invalid")
    for name, offset, value in [("version",4,1),("kind",5,255),("flags",6,1),("ciphertext",100,r[100]^1),
                                ("mac",32927,r[-1]^1),("index",56,1),("count",60,0)]:
        changed=bytearray(r);changed[offset]=value
        private("private-invalid-"+name,[bytes(changed)],"invalid")
    packed=container([r])
    private("private-truncated",[],"invalid",raw=packed[:-1])
    private("private-trailing",[],"invalid",raw=packed+b"\x00")
    private("private-wrapper-version",[],"invalid",raw=packed[:4]+b"\x01"+packed[5:])
    # Sparse maximum-count record: authentic metadata, no claim of complete recovery.
    maximum=record(bytes(CHUNK),index=2**32-2,count=2**32-1,length=(2**32-1)*CHUNK)
    manifest["maximum_record"]=save("private-maximum-count.record",maximum)
    post=prefix(2)+"  știre\x00\r\ne\u0301  ".encode()
    reply=prefix(4)+bytes(range(32))+b"reply"
    profile=prefix(5)+"Nume\x00 public".encode()
    avatar=prefix(6)+bytes(range(256))*2
    for name,data in [("post",post),("reply",reply),("profile",profile),("avatar",avatar),
                      ("post-empty",prefix(2)),("reply-empty",prefix(4)+bytes(32)),("profile-empty",prefix(5)),
                      ("post-max",prefix(2)+b"x"*32760),("reply-max",prefix(4)+bytes(32)+b"x"*32728),
                      ("profile-max",prefix(5)+b"x"*32760)]:
        public(name,data)
    for name,data in [("post-over",prefix(2)+b"x"*32761),("reply-short",prefix(4)+bytes(31)),
                      ("avatar-short",avatar[:-1]),("avatar-appended",avatar+b"x"),("unknown-kind",prefix(255)),
                      ("unknown-version",b"URMA\x01\x02\x00\x00"),("reserved-flags",b"URMA\x00\x02\x01\x00"),
                      ("invalid-post-utf8",prefix(2)+b"\xc0\x80"),("invalid-profile-utf8",prefix(5)+b"\xff"),
                      ("invalid-reply-utf8",prefix(4)+bytes(32)+b"\xff")]:
        public(name,data,"invalid")
    for name,data in [("proof-post",post),("proof-reply",reply),("proof-profile",profile),("proof-avatar",avatar),
                      ("proof-post-max",prefix(2)+b"x"*32760),("proof-private",r),
                      ("proof-segment-one",prefix(2)+b"a"*512+b"\x01"),
                      ("proof-segment-zero",prefix(2)+b"a"*512+b"\x00"),
                      ("proof-segment-negative",prefix(2)+b"a"*511+b"\xd0\x81")]:
        proof(name,data)
    proof("proof-extra-opcode",post,lambda script:script+b"\x61","invalid")
    proof("proof-nonminimal-push",post,lambda script:script[:41]+b"\x4c"+script[41:],"invalid")
    proof("proof-wrong-segmentation",prefix(2)+b"a"*513,
          lambda script:script[:41]+push((prefix(2)+b"a"*513)[:500])+push((prefix(2)+b"a"*513)[500:])+b"\x68","invalid")
    proof("proof-offline-container",prefix(3)+bytes(4),outcome="invalid")
    (OUT/"manifest.json").write_text(json.dumps(manifest,indent=2,ensure_ascii=False)+"\n")


if __name__ == "__main__":
    main()
