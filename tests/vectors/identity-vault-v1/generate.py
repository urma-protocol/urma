"""Independent fixed, PUBLIC TEST KEYS only. Requires argon2-cffi and cryptography."""
import hashlib, hmac, json, struct
from pathlib import Path
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
OUT = Path(__file__).resolve().parent

def hkdf(salt, ikm, info):
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    return hmac.new(prk, info + b'\x01', hashlib.sha256).digest()

entropy = bytes(32)
phrase = ' '.join(['abandon'] * 23 + ['art'])
password = 'URMA public test password 2026'
vid, salt, dek = bytes(range(16)), bytes(range(16, 32)), bytes(range(32, 64))
pn, rn, dn = bytes(range(64, 76)), bytes(range(76, 88)), bytes(range(88, 100))
base = b'URMAVLT\0' + struct.pack('<HHIII', 1, 0, 65536, 3, 4) + vid + salt
pk = hash_secret_raw(password.encode(), salt, 3, 65536, 4, 32, Type.ID, 19)
rk = hkdf(vid, entropy, b'URMA/vault/v1/recovery-wrap')
header = base + pn + AESGCM(pk).encrypt(pn, dek, base + b'URMA/vault/v1/password')
header += rn + AESGCM(rk).encrypt(rn, dek, base + b'URMA/vault/v1/recovery')
plain = struct.pack('<HH', 2, 1) + entropy + struct.pack('<HB', 0, 4) + b'main' + struct.pack('<HB', 1, 8) + b'reporter'

def envelope(payload):
    aad = header + dn + struct.pack('<I', len(payload) + 16)
    return aad + AESGCM(dek).encrypt(dn, payload, aad)

valid = envelope(plain)
(OUT / 'valid.vault').write_bytes(valid)
variants = {}
bad = bytearray(valid); bad[-1] ^= 1; variants['bad-tag'] = bytes(bad)
variants['trailing'] = valid + b'\0'
bad = bytearray(valid); bad[12:16] = struct.pack('<I', 0xffffffff); variants['unbounded-kdf'] = bytes(bad)
bad = bytearray(plain); bad[4] = 1; variants['seed-wrap-mismatch'] = envelope(bad)
bad = bytearray(plain); bad[43:45] = struct.pack('<H', 0); variants['duplicate-slot'] = envelope(bad)
variants['duplicate-name'] = envelope(struct.pack('<HH',2,1)+entropy+struct.pack('<HB',0,4)+b'main'+struct.pack('<HB',1,4)+b'main')
for name, data in variants.items(): (OUT / (name + '.vault')).write_bytes(data)
slots = []
order = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
for slot in (0, 1, 63):
    for counter in range(256):
        scalar = hkdf(b'URMA/identity/v1', entropy, b'secp256k1' + struct.pack('<II', slot, counter))
        value = int.from_bytes(scalar, 'big')
        if 0 < value < order: break
    key = ec.derive_private_key(value, ec.SECP256K1()).public_key()
    pub = key.public_bytes(serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint)
    slots.append(dict(slot=slot, counter=counter, scalar_hex=scalar.hex(), public_key=pub.hex(), author=pub[1:].hex()))
manifest = dict(format='URMA Identity/Vault v1', warning='PUBLIC TEST KEYS: NEVER FUND', phrase=phrase, password=password,
 entropy_hex=entropy.hex(), data_key_hex=dek.hex(), plaintext_hex=plain.hex(), password_key_hex=pk.hex(), recovery_key_hex=rk.hex(),
 slots=slots, active_slot=1, names=['main','reporter'], positive='valid.vault', negative=list(variants),
 sha256={p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(OUT.glob('*.vault'))})
(OUT / 'vectors.json').write_text(json.dumps(manifest, indent=2)+'\n')
print('independent identity/vault vectors:', len(variants)+1)
