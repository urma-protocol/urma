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


def keys(object_id, root=ROOT):
    prk = mac(object_id, root)
    return [mac(prk, b"URMA/V0/private/" + label + b"\x01")[:size]
            for label, size in [(b"content", 32), (b"authentication", 32), (b"discovery", 16)]]


def record(data, index=0, *, object_id=OBJECT, hint=0, flags=0, length=None,
           count=None, iv=None, digest=None, padding=0xa7, tag=None, root=ROOT):
    length = len(data) if length is None else length
    count = (len(data) + CHUNK - 1) // CHUNK if count is None else count
    enc, auth, derived = keys(object_id, root)
    tag = derived if tag is None else tag
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


def recovery_vectors(one, two):
    """Separate recovery oracle: literal expectations, not Rust-produced answers.

    A valid MAC alone does not select an object ID: IV and metadata must also
    pass. Whole-object hash failures and fully valid conflicts are never skips.
    Record dispositions describe a full candidate scan; framing failures have
    no scan diagnostics. Failure diagnostics are not part of the recovery API.
    """
    (OUT / "recovery").mkdir(exist_ok=True)
    corpus = {"protocol": "URMA", "wire_version": 0, "schema_version": 1,
              "license": "CC0-1.0", "mode": "explicit-container-recovery",
              "root": "root.bin",
              "strict_status_note": "invalid means generic strict rejection, including unrelated, incomplete or conflicted inputs; it is not an error category",
              "failure_counts_note": "Counts describe candidate dispositions under a full scan of intact framing; the API returns counts only on success",
              "cases": [], "records": {}}
    values = {}
    other_id = bytes([0x42]) * 32
    other_data = b"Second fully valid object\x00\xff"
    original = save("recovery/text.original", one)
    pair_original = save("recovery/two.original", two)

    def add_record(name, value, disposition, reason):
        values[name] = value
        corpus["records"][name] = {"artifact": save("recovery/" + name + ".record", value),
                                   "disposition": disposition, "reason": reason,
                                   "mac_valid_for_root": hmac.compare_digest(
                                       mac(keys(value[8:40])[1], value[:-32]), value[-32:])}

    def mutate(value, offset, replacement=None):
        changed = bytearray(value)
        changed[offset] = value[offset] ^ 1 if replacement is None else replacement
        return bytes(changed)

    r = record(one, hint=1)
    add_record("text", r, "valid", "Canonical single-chunk text object")
    for i in range(2):
        add_record("two-" + str(i), record(two, i), "valid", "Canonical chunk of the two-chunk object")
    add_record("bad-mac", mutate(r, -1), "invalid", "Matching discovery tag, invalid HMAC")
    add_record("forged-duplicate", mutate(r, 128), "invalid", "Same O/index, altered ciphertext, stale HMAC")
    add_record("tag-modified", mutate(r, 40), "unrelated", "Damaged discovery tag is not evidence of a foreign object")
    add_record("foreign", record(other_data, object_id=other_id, root=bytes([0xff])*32),
               "unrelated", "Another recovery root, discovery tag does not match")
    add_record("foreign-bad-mac", mutate(values["foreign"], -1), "unrelated",
               "Discovery mismatch precedes MAC verification")
    add_record("wrong-id-bad-mac", mutate(record(other_data, object_id=other_id), -1),
               "invalid", "Matching discovery tag for another ID, invalid HMAC must not select that ID")
    add_record("wrong-tag-valid-mac", record(one, hint=1, tag=keys(other_id)[2]),
               "unrelated", "Discovery mismatch even though the supplied-root MAC verifies")
    add_record("non-urma", b"OTHER!!!" + r[8:], "unrelated", "No URMA magic")
    add_record("public-kind", prefix(2) + r[8:], "unrelated", "Public kind is not a private candidate")
    for name, offset, replacement in [("bad-header-version", 4, 1), ("bad-header-kind", 5, 255),
                                      ("bad-header-flags", 6, 1), ("bad-index", 56, 1),
                                      ("bad-count", 60, 0)]:
        add_record(name, mutate(r, offset, replacement), "invalid", "Malformed candidate header, stale HMAC")
    for name, kwargs in [("post-mac-iv", {"iv": bytes([1])*16}),
                         ("post-mac-length-zero", {"length": 0}),
                         ("post-mac-length-overflow", {"length": 2**64-1}),
                         ("post-mac-length-count", {"length": CHUNK+1}),
                         ("post-mac-type", {"hint": 5}),
                         ("post-mac-flags", {"flags": 1})]:
        add_record(name, record(one, **kwargs), "invalid", "HMAC verifies; IV or metadata is invalid")
    for name, kwargs in [("wrong-id-post-mac-iv", {"iv": bytes([1])*16}),
                         ("wrong-id-post-mac-length", {"length": 0}),
                         ("wrong-id-post-mac-type", {"hint": 5}),
                         ("wrong-id-post-mac-flags", {"flags": 1})]:
        add_record(name, record(other_data, object_id=other_id, **kwargs), "invalid",
                   "Matching tag and valid HMAC under another ID; invalid semantics must not select that ID")
    add_record("other-complete", record(other_data, object_id=other_id), "valid", "Second complete ID under the supplied root")
    add_record("other-partial", record(two, 0, object_id=other_id), "valid", "One valid chunk selects a second ID even when incomplete")
    add_record("padding-conflict", record(two, 1, padding=0xb8), "valid", "Same meaningful bytes and metadata, distinct authenticated padding")
    add_record("type-conflict", record(two, 1, hint=1), "valid", "Canonical chunk with conflicting content type")
    add_record("length-conflict", record(two, 1, length=len(two)+1), "valid",
               "Canonical chunk with conflicting L, same N, digest and type")
    add_record("count-conflict", record(one), "valid", "Same O, canonical N=1 conflicts with the N=2 object")
    add_record("digest-conflict", record(two, 1, digest=bytes(32)), "valid", "Canonical record carrying a conflicting file digest")
    add_record("final-hash-fail", record(one, hint=1, digest=bytes(32)), "valid", "Fully valid record, final whole-object digest does not match")
    for i in range(2):
        add_record("two-hash-fail-" + str(i), record(two, i, digest=bytes(32)), "valid",
                   "All records agree on a digest that fails after full reconstruction")

    def case(name, names, status, *, object_name=None, root="root.bin", raw=None,
             order_group=None, reason=None):
        expected = {"status": status}
        if status != "framing":
            dispositions = [corpus["records"][n]["disposition"] for n in names]
            if root == "wrong-root.bin":
                dispositions = ["unrelated" for _ in names]
            expected.update(skipped_unrelated=dispositions.count("unrelated"),
                            rejected_records=dispositions.count("invalid"),
                            valid_records=dispositions.count("valid"))
        if status == "complete":
            data, hint, descriptor = ((one, 1, original) if object_name == "text"
                                      else (two, 0, pair_original))
            expected["object"] = {"id": OBJECT.hex(), "count": (len(data)+CHUNK-1)//CHUNK,
                                  "total": len(data), "digest": sha(data).hex(),
                                  "content_type": hint, "original": descriptor}
        entry = {"name": name, "root": root, "records": names,
                 "container": save("recovery/" + name + ".urma",
                                   container([values[n] for n in names]) if raw is None else raw),
                 "expected": expected,
                 "strict_status": "complete" if status == "complete" and all(
                     corpus["records"][n]["disposition"] == "valid" for n in names) else "invalid"}
        if order_group:
            entry["order_group"] = order_group
        if reason:
            entry["reason"] = reason
        corpus["cases"].append(entry)

    case("complete", ["text"], "complete", object_name="text")
    case("raw-duplicate", ["text", "text"], "complete", object_name="text")
    case("shuffled-duplicate", ["two-1", "two-0", "two-1"], "complete", object_name="two")
    case("ordered-duplicate", ["two-0", "two-1", "two-1"], "complete", object_name="two")
    skipped = [name for name, value in corpus["records"].items() if value["disposition"] != "valid"]
    for name in skipped:
        for where, names in [("early", [name, "text"]), ("late", ["text", name])]:
            case("complete-" + name + "-" + where, names, "complete", object_name="text", order_group=name)
    case("complete-all-skips-early", skipped + ["text"], "complete", object_name="text", order_group="all-skips")
    case("complete-all-skips-late", ["text"] + list(reversed(skipped)), "complete", object_name="text", order_group="all-skips")
    case("zero-valid-invalid", ["bad-mac", "post-mac-iv", "wrong-id-post-mac-flags"], "no-object")
    case("zero-valid-unrelated", ["foreign", "tag-modified", "wrong-tag-valid-mac"], "no-object")
    case("zero-valid-mixed-skips", ["foreign", "bad-mac", "wrong-id-post-mac-type"], "no-object")
    case("wrong-root", ["text"], "no-object", root="wrong-root.bin")
    case("missing-unique-index", ["two-0", "two-0"], "incomplete")
    case("missing-first-index", ["two-1", "two-1", "bad-mac"], "incomplete")
    for name in ["padding-conflict", "type-conflict", "length-conflict", "count-conflict", "digest-conflict"]:
        case(name + "-early", ["two-1", name, "two-0"], "conflict", order_group=name)
        case(name + "-late", ["two-0", "two-1", name], "conflict", order_group=name)
        case(name + "-first", [name, "two-0", "two-1"], "conflict", order_group=name)
    for name in ["other-complete", "other-partial"]:
        case("mixed-" + name + "-early", [name, "text"], "mixed", order_group=name)
        case("mixed-" + name + "-late", ["text", name], "mixed", order_group=name)
    case("final-hash-fail", ["final-hash-fail"], "hash-mismatch")
    case("final-hash-fail-with-skips", ["bad-mac", "final-hash-fail", "foreign"], "hash-mismatch")
    case("two-final-hash-fail", ["two-hash-fail-1", "two-hash-fail-0"], "hash-mismatch")
    packed = container([r])
    for name, raw in [
        ("wrapper-count-zero", prefix(3)+bytes(4)),
        ("wrapper-zero-with-record", packed[:8]+bytes(4)+packed[12:]),
        ("wrapper-count-too-large", packed[:8]+uint(2, 4)+packed[12:]),
        ("wrapper-count-too-small", container([r, r])[:8]+uint(1, 4)+container([r, r])[12:]),
        ("wrapper-count-max", packed[:8]+uint(2**32-1, 4)+packed[12:]),
        ("record-length-zero", packed[:12]+bytes(4)+packed[16:]),
        ("record-length-short", packed[:12]+uint(len(r)-1, 4)+packed[16:]),
        ("record-length-long", packed[:12]+uint(len(r)+1, 4)+packed[16:]),
        ("record-length-max", packed[:12]+uint(2**32-1, 4)+packed[16:]),
        ("trailing", packed+b"\x00"), ("truncated-record", packed[:-1]),
        ("truncated-length", packed[:14]), ("truncated-header", packed[:11]),
        ("truncated-after-complete", container([r, r])[:-1]),
        ("trailing-after-skips", container([r, values["bad-mac"]])+b"\x00"),
        ("wrapper-version", packed[:4]+b"\x01"+packed[5:]),
        ("wrapper-kind", packed[:5]+b"\x01"+packed[6:]),
        ("wrapper-flags", packed[:6]+b"\x01"+packed[7:]),
    ]:
        case(name, [], "framing", raw=raw,
             reason="Malformed framing is fatal; completed earlier records cannot authorize export or resynchronization")
    (OUT / "recovery/manifest.json").write_text(json.dumps(corpus, indent=2)+"\n")


def public(name, data, outcome="valid"):
    manifest["public"].append({"name": name, "outcome": outcome, "record": save(name + ".record", data)})


def profile_vectors(profile):
    """Literal UTF-8 bytes exercise the kind-05 limit without normalization.

    NFD129 is invalid even though NFC would shorten it to 86 bytes. NFD128
    and its NFC spelling are both valid but must retain distinct wire bytes.
    The existing small profile, empty profile and invalid-UTF8 fixture keep
    their names and bytes. Only the old profile-max known answer is replaced.
    """
    cases = [
        ("profile", profile[8:], "valid", "Existing name includes U+0000"),
        ("profile-empty", b"", "valid", "Empty body is structurally valid"),
        ("profile-ascii127", b"x"*127, "valid", "ASCII below the byte limit"),
        ("profile-max", b"x"*128, "valid", "128-byte body, full record136"),
        ("profile-over", b"x"*129, "invalid", "129 ASCII bytes exceed the limit"),
        ("profile-utf8-two-byte128", bytes.fromhex("c899"*64), "valid", "64 U+0219 code points, 128 UTF-8 bytes"),
        ("profile-utf8-two-byte129", bytes.fromhex("c899"*64+"61"), "invalid", "65 code points, 129 UTF-8 bytes"),
        ("profile-utf8-four-byte128", bytes.fromhex("f09f9982"*32), "valid", "32 U+1F642 code points, 128 UTF-8 bytes"),
        ("profile-utf8-four-byte129", bytes.fromhex("f09f9982"*32+"61"), "invalid", "33 code points, 129 UTF-8 bytes"),
        ("profile-utf8-four-byte132", bytes.fromhex("f09f9982"*33), "invalid", "33 U+1F642 code points occupy132 bytes, never33 bytes"),
        ("profile-nfd128", bytes.fromhex("65cc81"*42+"6162"), "valid", "NFD spelling retained at exactly128 bytes"),
        ("profile-nfc86", bytes.fromhex("c3a9"*42+"6162"), "valid", "NFC spelling remains distinct from NFD128"),
        ("profile-nfd129", bytes.fromhex("65cc81"*43), "invalid", "NFC normalization must not turn an overlong body into an accepted one"),
        ("profile-nfc43", bytes.fromhex("c3a9"*43), "valid", "NFC equivalent of NFD129 fits in86 bytes"),
        ("profile-preserve", bytes.fromhex("200065cc810d0a20"), "valid", "Keep whitespace, NUL, combining mark and CRLF exactly"),
        ("invalid-profile-utf8", b"\xff", "invalid", "Existing invalid UTF-8 body"),
        ("invalid-profile-utf8-over129", b"\xff"*129, "invalid", "Invalid UTF-8 and overlong body cannot be accepted"),
        ("profile-utf8-truncated128", b"a"*127+b"\xc8", "invalid", "128-byte body ends inside a two-byte UTF-8 sequence"),
        ("profile-legacy32760", b"x"*32760, "invalid", "Old maximum body is rejected, never truncated or migrated"),
    ]
    reference = {"protocol": "URMA", "wire_version": 0, "kind": 5,
                 "encoding": "UTF-8", "maximum_body_bytes": 128,
                 "minimum_record_bytes": 8, "maximum_record_bytes": 136,
                 "normalization": "none", "truncation": "none", "cases": []}
    for name, body, outcome, reason in cases:
        value = prefix(5)+body
        public(name, value, outcome)
        proof_name = "proof-profile" if name == "profile" else "proof-"+name
        proof(proof_name, value, outcome=outcome)
        entry = {"name": name, "outcome": outcome, "reason": reason,
                 "body": save(name+".bin", body),
                 "record": {"file": name+".record", "bytes": len(value), "sha256": sha(value).hex()},
                 "proof": proof_name}
        try:
            entry["text"] = body.decode("utf-8")
        except UnicodeDecodeError:
            entry["utf8_valid"] = False
        else:
            entry["utf8_valid"] = True
        reference["cases"].append(entry)
    reference["equivalent_spellings"] = [
        {"left": "profile-nfd128", "right": "profile-nfc86", "relation": "canonically equivalent, retain distinct bytes"},
        {"left": "profile-nfd129", "right": "profile-nfc43", "relation": "canonically equivalent, different acceptance due to byte length"},
    ]
    manifest["profile_reference"] = save("profile-utf8-reference.json",
        (json.dumps(reference, indent=2, ensure_ascii=False)+"\n").encode())


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
    # Another object's discovery tag under a MAC that verifies: unrelated, not forged (§5.4 step 2).
    private("private-wrong-tag", [record(one, hint=1, tag=keys(bytes([0x42])*32)[2])], "unrelated")
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
    avatar_pixels=bytes(range(128))
    avatar=prefix(6)+avatar_pixels
    avatar_png_pixels=b"\x89PNG\r\n\x1a\n"+bytes(range(120))
    avatar_urma_pixels=prefix(6)+bytes(range(120))
    # Literal known answer: each row advances by three palette indices. This
    # distinguishes row-major traversal from transposition and nibble reversal.
    avatar_rows = [
        "0123456789abcdef", "3456789abcdef012", "6789abcdef012345", "9abcdef012345678",
        "cdef0123456789ab", "f0123456789abcde", "23456789abcdef01", "56789abcdef01234",
        "89abcdef01234567", "bcdef0123456789a", "ef0123456789abcd", "123456789abcdef0",
        "456789abcdef0123", "789abcdef0123456", "abcdef0123456789", "def0123456789abc",
    ]
    avatar_reference_pixels=bytes.fromhex("".join(avatar_rows))
    avatar_reference=prefix(6)+avatar_reference_pixels
    ega16 = [
        [0,0,0], [0,0,170], [0,170,0], [0,170,170],
        [170,0,0], [170,0,170], [170,85,0], [170,170,170],
        [85,85,85], [85,85,255], [85,255,85], [85,255,255],
        [255,85,85], [255,85,255], [255,255,85], [255,255,255],
    ]
    reference = {"protocol": "URMA", "wire_version": 0, "kind": 6,
                 "specification": "URMA V0, document revision 0.9, section 7.1", "palette": "EGA16",
                 "width": 16, "height": 16, "body_bytes": 128, "record_bytes": 136,
                 "packing": "high-nibble-first", "order": "row-major",
                 "indices_by_row": avatar_rows, "palette_rgb": ega16,
                 "pixels": save("avatar-ega16-reference.bin", avatar_reference_pixels),
                 "record": "avatar-ega16-reference.record", "proof": "proof-avatar-ega16-reference"}
    manifest["avatar_reference"] = save("avatar-ega16-reference.json",
        (json.dumps(reference,indent=2)+"\n").encode())
    manifest["avatar_inputs"] = [
        {"name": name, "outcome": outcome, "pixels": save(name+".bin", pixels)}
        for name,pixels,outcome in [
            ("avatar-raw128",avatar_pixels,"valid"),
            ("avatar-raw-png-prefix128",avatar_png_pixels,"valid"),
            ("avatar-raw-urma-prefix128",avatar_urma_pixels,"valid"),
            ("avatar-raw127",avatar_pixels[:-1],"invalid"),
            ("avatar-raw129",avatar_pixels+b"x","invalid"),
            ("avatar-raw-legacy512",bytes(range(256))*2,"invalid"),
            ("avatar-prefixed136",avatar,"invalid"),
        ]
    ]
    for name,data in [("post",post),("reply",reply),("avatar",avatar),
                      ("avatar-ega16-reference",avatar_reference),
                      ("avatar-png-prefix",prefix(6)+avatar_png_pixels),
                      ("avatar-urma-prefix",prefix(6)+avatar_urma_pixels),
                      ("post-empty",prefix(2)),("reply-empty",prefix(4)+bytes(32)),
                      ("post-max",prefix(2)+b"x"*32760),("reply-max",prefix(4)+bytes(32)+b"x"*32728)]:
        public(name,data)
    for name,data in [("post-over",prefix(2)+b"x"*32761),("reply-short",prefix(4)+bytes(31)),
                      ("avatar-short",avatar[:-1]),("avatar-appended",avatar+b"x"),
                      ("avatar-legacy512",prefix(6)+bytes(range(256))*2),("unknown-kind",prefix(255)),
                      ("unknown-version",b"URMA\x01\x02\x00\x00"),("reserved-flags",b"URMA\x00\x02\x01\x00"),
                      ("invalid-post-utf8",prefix(2)+b"\xc0\x80"),
                      ("invalid-reply-utf8",prefix(4)+bytes(32)+b"\xff")]:
        public(name,data,"invalid")
    profile_record=prefix(12)+b"URMANAM1"+bytes(range(256))
    for name,data in [("profile-record",profile_record),("profile-record-empty",prefix(12)+b"URMANAM1"),
                      ("profile-record-zero-id",prefix(12)+bytes(8)+b"unspecified profile"),
                      ("profile-record-unknown-id",prefix(12)+b"\xffZZZZZZ\x00"+b"unknown profile"),
                      ("profile-record-nested",prefix(12)+b"URMANAM1"+post),
                      ("profile-record-max",prefix(12)+b"URMANAM1"+b"x"*32752)]:
        public(name,data)
    for name,data in [("profile-record-short",prefix(12)+b"URMANAM"),
                      ("profile-record-over",prefix(12)+b"URMANAM1"+b"x"*32753)]:
        public(name,data,"invalid")
    for name,data in [("proof-post",post),("proof-reply",reply),("proof-avatar",avatar),
                      ("proof-avatar-ega16-reference",avatar_reference),
                      ("proof-avatar-png-prefix",prefix(6)+avatar_png_pixels),
                      ("proof-avatar-urma-prefix",prefix(6)+avatar_urma_pixels),
                      ("proof-post-max",prefix(2)+b"x"*32760),("proof-private",r),
                      ("proof-segment-one",prefix(2)+b"a"*512+b"\x01"),
                      ("proof-segment-zero",prefix(2)+b"a"*512+b"\x00"),
                      ("proof-segment-negative",prefix(2)+b"a"*511+b"\xd0\x81")]:
        proof(name,data)
    for name,data in [("proof-avatar-short",avatar[:-1]),("proof-avatar-appended",avatar+b"x"),
                      ("proof-avatar-legacy512",prefix(6)+bytes(range(256))*2)]:
        proof(name,data,outcome="invalid")
    proof("proof-extra-opcode",post,lambda script:script+b"\x61","invalid")
    proof("proof-nonminimal-push",post,lambda script:script[:41]+b"\x4c"+script[41:],"invalid")
    proof("proof-wrong-segmentation",prefix(2)+b"a"*513,
          lambda script:script[:41]+push((prefix(2)+b"a"*513)[:500])+push((prefix(2)+b"a"*513)[500:])+b"\x68","invalid")
    proof("proof-offline-container",prefix(3)+bytes(4),outcome="invalid")
    proof("proof-profile-record",profile_record)
    profile_vectors(profile)
    (OUT/"manifest.json").write_text(json.dumps(manifest,indent=2,ensure_ascii=False)+"\n")
    recovery_vectors(one, two)


if __name__ == "__main__":
    main()
