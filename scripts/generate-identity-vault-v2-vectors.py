#!/usr/bin/env python3
# SPDX-License-Identifier: 0BSD
"""Generate URMA Identity/Vault v2 vectors without Rust, an URMA SDK or network access.
PUBLIC TEST KEYS ONLY: never fund any address below. Requires argon2-cffi and cryptography.
BIP39, BIP32, BIP84, BIP85, BIP340 and BIP380 are reimplemented here and checked against
their published vectors before anything is written.
"""
import hashlib
import hmac
import json
import struct
import unicodedata
from pathlib import Path

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

OUT = Path(__file__).resolve().parents[1] / "tests/vectors/identity-vault-v2"
WORDLIST_SHA256 = "2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda"
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)
HARDENED = 0x80000000
XPRV, XPUB = bytes.fromhex("0488ade4"), bytes.fromhex("0488b21e")
TPRV, TPUB = bytes.fromhex("04358394"), bytes.fromhex("043587cf")
B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
BECH32 = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
DESC_INPUT = "0123456789()[],'/*abcdefgh@:$%{}IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~ijklmnopqrstuvwxyzABCDEFGH`#\"\\ "
CHAINS = [  # label, coin type, address HRP, mainnet versions
    ("bitcoin-mainnet", 0, "bc", True),
    ("litecoin-mainnet", 2, "ltc", True),
    ("bitcoin-testnet4", 1, "tb", False),
    ("bitcoin-regtest", 1, "bcrt", False),
    ("litecoin-testnet", 1, "tltc", False),
]


def add(left, right):
    if left is None:
        return right
    if right is None:
        return left
    if left[0] == right[0] and (left[1] + right[1]) % P == 0:
        return None
    if left == right:
        slope = 3 * left[0] * left[0] * pow(2 * left[1], P - 2, P) % P
    else:
        slope = (right[1] - left[1]) * pow(right[0] - left[0], P - 2, P) % P
    x = (slope * slope - left[0] - right[0]) % P
    return x, (slope * (left[0] - x) - left[1]) % P


def mul(scalar, point=G):
    result = None
    while scalar:
        if scalar & 1:
            result = add(result, point)
        point = add(point, point)
        scalar >>= 1
    return result


def compressed(point):
    return bytes([2 + (point[1] & 1)]) + point[0].to_bytes(32, "big")


def hash160(data):
    return hashlib.new("ripemd160", hashlib.sha256(data).digest()).digest()


def b58check(payload):
    data = payload + hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    number, text = int.from_bytes(data, "big"), ""
    while number:
        number, digit = divmod(number, 58)
        text = B58[digit] + text
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + text


def b58decode(text):
    number = 0
    for char in text:
        number = number * 58 + B58.index(char)
    data = number.to_bytes(82, "big")
    assert hashlib.sha256(hashlib.sha256(data[:-4]).digest()).digest()[:4] == data[-4:]
    return data[:-4]


class Node:
    def __init__(self, key, chain, depth=0, parent=b"\0" * 4, index=0):
        self.key, self.chain, self.depth, self.parent, self.index = key, chain, depth, parent, index

    def public(self):
        return compressed(mul(self.key))

    def fingerprint(self):
        return hash160(self.public())[:4]

    def child(self, index):
        data = b"\0" + self.key.to_bytes(32, "big") if index >= HARDENED else self.public()
        mac = hmac.new(self.chain, data + struct.pack(">I", index), hashlib.sha512).digest()
        tweak = int.from_bytes(mac[:32], "big")
        key = (tweak + self.key) % N
        assert tweak < N and key != 0
        return Node(key, mac[32:], self.depth + 1, self.fingerprint(), index)

    def derive(self, path):
        node = self
        for index in path:
            node = node.child(index)
        return node

    def serialize(self, version, private):
        body = self.key.to_bytes(33, "big") if private else self.public()
        return b58check(version + bytes([self.depth]) + self.parent + struct.pack(">I", self.index) + self.chain + body)


def master(seed):
    mac = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    return Node(int.from_bytes(mac[:32], "big"), mac[32:])


def words():
    data = (OUT / "bip39-english.txt").read_bytes()
    assert hashlib.sha256(data).hexdigest() == WORDLIST_SHA256
    return data.decode().split()


def mnemonic(entropy):
    bits = bin(int.from_bytes(entropy + hashlib.sha256(entropy).digest(), "big"))[2:]
    bits = bits.zfill(8 * len(entropy) + 256)[: 8 * len(entropy) + len(entropy) // 4]
    return " ".join(WORDS[int(bits[i : i + 11], 2)] for i in range(0, len(bits), 11))


def seed(phrase, passphrase=""):
    text = unicodedata.normalize("NFKD", phrase).encode()
    salt = unicodedata.normalize("NFKD", "mnemonic" + passphrase).encode()
    return hashlib.pbkdf2_hmac("sha512", text, salt, 2048)


def bech32_polymod(values):
    checksum = 1
    for value in values:
        top = checksum >> 25
        checksum = (checksum & 0x1FFFFFF) << 5 ^ value
        for i, generator in enumerate([0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]):
            checksum ^= generator if (top >> i) & 1 else 0
    return checksum


def segwit_v0(hrp, program):
    data, acc, bits = [0], 0, 0
    for byte in program:
        acc, bits = (acc << 8) | byte, bits + 8
        while bits >= 5:
            bits -= 5
            data.append((acc >> bits) & 31)
    if bits:
        data.append((acc << (5 - bits)) & 31)
    expanded = [ord(c) >> 5 for c in hrp] + [0] + [ord(c) & 31 for c in hrp]
    polymod = bech32_polymod(expanded + data + [0] * 6) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(BECH32[d] for d in data + checksum)


def descsum(text):
    def polymod(c, value):
        top = c >> 35
        c = ((c & 0x7FFFFFFFF) << 5) ^ value
        for i, generator in enumerate([0xF5DEE51989, 0xA9FDCA3312, 0x1BAB10E32D, 0x3706B1677A, 0x644D626FFD]):
            c ^= generator if (top >> i) & 1 else 0
        return c

    c, cls, count = 1, 0, 0
    for char in text:
        position = DESC_INPUT.index(char)
        c = polymod(c, position & 31)
        cls, count = cls * 3 + (position >> 5), count + 1
        if count == 3:
            c, cls, count = polymod(c, cls), 0, 0
    if count:
        c = polymod(c, cls)
    for _ in range(8):
        c = polymod(c, 0)
    c ^= 1
    return text + "#" + "".join(BECH32[(c >> (5 * (7 - i))) & 31] for i in range(8))


def bip85(root, path):
    k = root.derive(path).key.to_bytes(32, "big")
    return k, hmac.new(b"bip-entropy-from-k", k, hashlib.sha512).digest()


def tagged(tag, data):
    digest = hashlib.sha256(tag.encode()).digest()
    return hashlib.sha256(digest + digest + data).digest()


def schnorr_verify(public, message, signature):
    x = int.from_bytes(public, "big")
    y = pow(x**3 + 7, (P + 1) // 4, P)
    assert y * y % P == (x**3 + 7) % P
    point = (x, y if y % 2 == 0 else P - y)
    r, s = int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big")
    e = int.from_bytes(tagged("BIP0340/challenge", signature[:32] + public + message), "big") % N
    check = add(mul(s), mul(N - e, point))
    return check is not None and check[1] % 2 == 0 and check[0] == r


def schnorr_sign(secret, message, aux):
    assert 0 < secret < N
    point = mul(secret)
    d = secret if point[1] % 2 == 0 else N - secret
    public = point[0].to_bytes(32, "big")
    masked = bytes(a ^ b for a, b in zip(d.to_bytes(32, "big"), tagged("BIP0340/aux", aux)))
    k0 = int.from_bytes(tagged("BIP0340/nonce", masked + public + message), "big") % N
    nonce = mul(k0)
    k = k0 if nonce[1] % 2 == 0 else N - k0
    rx = nonce[0].to_bytes(32, "big")
    e = int.from_bytes(tagged("BIP0340/challenge", rx + public + message), "big") % N
    signature = rx + ((k + e * d) % N).to_bytes(32, "big")
    assert schnorr_verify(public, message, signature)
    return public, signature


def conformance():
    abandon = mnemonic(bytes(16))
    assert abandon == " ".join(["abandon"] * 11 + ["about"])
    assert seed(abandon, "TREZOR").hex() == "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04"
    assert master(seed(abandon, "TREZOR")).serialize(XPRV, True) == "xprv9s21ZrQH143K3h3fDYiay8mocZ3afhfULfb5GX8kCBdno77K4HiA15Tg23wpbeF1pLfs1c5SPmYHrEpTuuRhxMwvKDwqdKiGJS9XFKzUsAF"
    assert mnemonic(bytes([0x7F] * 16)) == "legal winner thank year wave sausage worth useful legal winner thank yellow"
    vector = master(bytes(range(16)))
    assert vector.serialize(XPRV, True) == "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"
    assert vector.derive([HARDENED]).serialize(XPRV, True) == "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7"
    assert vector.derive([HARDENED, 1]).serialize(XPUB, False) == "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"
    account = master(seed(abandon)).derive([84 | HARDENED, HARDENED, HARDENED])
    zpub = b58decode("zpub6rFR7y4Q2AijBEqTUquhVz398htDFrtymD9xYYfG1m4wAcvPhXNfE3EfH1r1ADqtfSdVCToUG868RvUUkgDKf31mGDtKsAYz2oz2AGutZYs")
    assert account.serialize(XPUB, False) == b58check(XPUB + zpub[4:])
    for path, address in [([0, 0], "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"), ([0, 1], "bc1qnjg0jd8228aq7egyzacy8cys3knf9xvrerkf9g"), ([1, 0], "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el")]:
        assert segwit_v0("bc", hash160(account.derive(path).public())) == address
    data = b58decode("xprv9s21ZrQH143K2LBWUUQRFXhucrQqBpKdRRxNVq2zBqsx8HVqFk2uYo8kmbaLLHRdqtQpUm98uKfu3vca1LqdGhUtyoFnCNkfmXRyPXLjbKb")
    root = Node(int.from_bytes(data[46:], "big"), data[13:45])
    assert [x.hex() for x in bip85(root, [83696968 | HARDENED, HARDENED, HARDENED])] == ["cca20ccb0e9a90feb0912870c3323b24874b0ca3d8018c4b96d0b97c0e82ded0", "efecfbccffea313214232d29e71563d941229afb4338c21f9517c41aaa0d16f00b83d2a09ef747e7a64e8e2bd5a14869e693da66ce94ac2da570ab7ee48618f7"]
    assert [x.hex() for x in bip85(root, [83696968 | HARDENED, HARDENED, 1 | HARDENED])] == ["503776919131758bb7de7beb6c0ae24894f4ec042c26032890c29359216e21ba", "70c6e3e8ebee8dc4c0dbba66076819bb8c09672527c4277ca8729532ad711872218f826919f6b67218adde99018a6df9095ab2b58d803b5b93ec9802085a690e"]
    assert bip85(root, [83696968 | HARDENED, 128169 | HARDENED, 64 | HARDENED, HARDENED])[1].hex() == "492db4698cf3b73a5a24998aa3e9d7fa96275d85724a91e71aa2d645442f878555d078fd1f1f67e368976f04137b1f7a0d19232136ca50c44614af72b5582a5c"
    for secret, aux, message, signature in [
        ("03", "00" * 32, "00" * 32, "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA821525F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"),
        ("B7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF", "00" * 31 + "01", "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89", "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE33418906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A"),
        ("C90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B14E5C9", "C87AA53824B4D7AE2EB035A2B5BBBCCC080E76CDC6D1692C4B0B62D798E6D906", "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C", "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1BAB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7"),
    ]:
        assert schnorr_sign(int(secret, 16), bytes.fromhex(message), bytes.fromhex(aux))[1].hex().upper() == signature
    assert descsum("raw(deadbeef)") == "raw(deadbeef)#89f8spxm"


def hkdf(salt, ikm, info):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b"\x01", hashlib.sha256).digest()


def chains(root):
    rows = []
    for label, coin, hrp, mainnet in CHAINS:
        account = root.derive([84 | HARDENED, coin | HARDENED, HARDENED])
        xpub = account.serialize(XPUB if mainnet else TPUB, False)
        origin = f"[{root.fingerprint().hex()}/84h/{coin}h/0h]{xpub}"
        address = lambda branch, index: segwit_v0(hrp, hash160(account.derive([branch, index]).public()))
        rows.append(dict(chain=label, path=f"m/84'/{coin}'/0'", hrp=hrp, account_xpub=xpub,
                         descriptors=[descsum(f"wpkh({origin}/0/*)"), descsum(f"wpkh({origin}/1/*)")],
                         external_0=address(0, 0), external_1=address(0, 1), internal_0=address(1, 0)))
    return rows


def slots(root):
    rows = []
    for slot in (0, 1, 63):
        k, entropy = bip85(root, [83696968 | HARDENED, 128169 | HARDENED, 32 | HARDENED, slot | HARDENED])
        scalar = int.from_bytes(entropy[:32], "big")
        assert 0 < scalar < N
        author, signature = schnorr_sign(scalar, DIGEST, AUX)
        rows.append(dict(slot=slot, path=f"m/83696968'/128169'/32'/{slot}'", k=k.hex(), entropy=entropy[:32].hex(),
                         scalar=f"{scalar:064x}", author=author.hex(), signature=signature.hex()))
    return rows


def payload(count, active, entropy, entries):
    data = struct.pack("<HH", count, active) + entropy
    for slot, name in entries:
        data += struct.pack("<HB", slot, len(name)) + name
    return data


WORDS = words()
conformance()
ENTROPY = bytes(range(16))
PHRASE = mnemonic(ENTROPY)
SEED = seed(PHRASE)
ROOT = master(SEED)
DIGEST, AUX = bytes(range(0xA0, 0xC0)), bytes(range(0xC0, 0xE0))
PASSWORD = "URMA public test password 2026"
VID, SALT, DEK = bytes(range(16)), bytes(range(16, 32)), bytes(range(32, 64))
PN, RN, DN = bytes(range(64, 76)), bytes(range(76, 88)), bytes(range(88, 100))
NAMES = [(0, b"main"), (1, b"reporter")]


def header(version=2, params=(65536, 3, 4)):
    base = b"URMAVLT\0" + struct.pack("<HHIII", version, 0, *params) + VID + SALT
    password_key = hash_secret_raw(PASSWORD.encode(), SALT, 3, 65536, 4, 32, Type.ID, 19)
    recovery_key = hkdf(VID, SEED, b"URMA/vault/v2/recovery-wrap")
    wrapped = PN + AESGCM(password_key).encrypt(PN, DEK, base + b"URMA/vault/v2/password")
    wrapped += RN + AESGCM(recovery_key).encrypt(RN, DEK, base + b"URMA/vault/v2/recovery")
    return base + wrapped, password_key, recovery_key


def envelope(plain, head=None):
    aad = (head or HEADER) + DN + struct.pack("<I", len(plain) + 16)
    return aad + AESGCM(DEK).encrypt(DN, plain, aad)


HEADER, PASSWORD_KEY, RECOVERY_KEY = header()
PLAIN = payload(2, 1, ENTROPY, NAMES)
VALID = envelope(PLAIN)
assert 232 <= len(VALID) <= 4516
other = bytes([ENTROPY[0] ^ 1]) + ENTROPY[1:]
negative = {
    "version-1": ("parse", envelope(PLAIN, header(version=1)[0])),
    "unfamiliar-kdf": ("parse", envelope(PLAIN, header(params=(65536, 4, 4))[0])),
    "trailing-file": ("parse", VALID + b"\0"),
    "bad-tag": ("unlock", VALID[:-1] + bytes([VALID[-1] ^ 1])),
    "entropy-24-words": ("unlock", envelope(payload(2, 1, bytes(32), NAMES))),
    "trailing-payload": ("unlock", envelope(PLAIN + b"\0")),
    "seed-wrap-mismatch": ("unlock", envelope(payload(2, 1, other, NAMES))),
    "active-out-of-range": ("unlock", envelope(payload(2, 2, ENTROPY, NAMES))),
    "duplicate-slot": ("unlock", envelope(payload(2, 1, ENTROPY, [(0, b"main"), (0, b"reporter")]))),
    "duplicate-name": ("unlock", envelope(payload(2, 1, ENTROPY, [(0, b"main"), (1, b"main")]))),
}
for stale in OUT.glob("*.vault"):
    stale.unlink()
(OUT / "valid.vault").write_bytes(VALID)
for name, (_, data) in negative.items():
    (OUT / f"{name}.vault").write_bytes(data)
manifest = dict(
    format="URMA Identity/Vault v2", warning="PUBLIC TEST KEYS: NEVER FUND",
    phrase=PHRASE, entropy=ENTROPY.hex(), seed=SEED.hex(), master_xprv=ROOT.serialize(XPRV, True),
    fingerprint=ROOT.fingerprint().hex(), chains=chains(ROOT), digest=DIGEST.hex(), aux=AUX.hex(), slots=slots(ROOT),
    invalid_phrases={"bad-checksum": " ".join(["abandon"] * 12), "fifteen-words": mnemonic(bytes(20)),
                     "twenty-four-words": mnemonic(bytes(32)), "eleven-words": " ".join(["abandon"] * 11)},
    vault=dict(password=PASSWORD, password_key=PASSWORD_KEY.hex(), recovery_key=RECOVERY_KEY.hex(), data_key=DEK.hex(),
               plaintext=PLAIN.hex(), active_slot=1, names=[name.decode() for _, name in NAMES], file="valid.vault"),
    negative={name: stage for name, (stage, _) in negative.items()},
    sha256={path.name: hashlib.sha256(path.read_bytes()).hexdigest() for path in sorted(OUT.glob("*.vault"))},
)
(OUT / "vectors.json").write_text(json.dumps(manifest, indent=2) + "\n")
print("identity/vault v2 vectors:", len(negative) + 1, "files,", len(manifest["chains"]), "chains,", len(manifest["slots"]), "slots")
