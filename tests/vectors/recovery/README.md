# Explicit container recovery vectors

This corpus is separate from the strict corpus in `../manifest.json`. Run
`python3 scripts/generate-vectors.py` from the repository root to regenerate
both. Existing strict private/public/proof/avatar artifacts retain their bytes.
Python stdlib HMAC/SHA-256 and OpenSSL AES-256-CTR produce the known answers;
the generator never invokes the Rust encoder or recovery implementation.
All keys, originals and padding here are public test data.
This README is maintained manually and is not emitted by the generator;
directory-wide determinism checks also include this stable explanatory file.

`manifest.json` schema version 1 contains `records` and `cases`. Artifact `file`
paths are relative to `tests/vectors`; descriptors include length and SHA-256.
Each record has an expected `valid`, `unrelated` or `invalid` disposition under
`root.bin`, a reason and independently checkable `mac_valid_for_root`.

Each case supplies a packed kind-03 container, a root path and an expected
terminal status: `complete`, `no-object`, `incomplete`, `conflict`, `mixed`,
`hash-mismatch` or `framing`. For intact framing, counts describe a full scan
of candidate dispositions; the recovery API exposes counters only on success.
`valid_records` counts duplicates too, while object `count` is the number of
unique indices required. Complete cases include exact expected object metadata
and original bytes. `strict_status: invalid` means generic strict rejection,
including unrelated, incomplete and conflicted inputs, rather than one error
category. A recovered object does not establish validity of its source container.

Early, late and first conflict variants prevent an implementation from exporting
as soon as an object appears complete. Invalid candidates with another ID test
that only fully valid chunks select IDs. A second fully valid ID is fatal even
if incomplete. Altered discovery tags remain unrelated rather than proving that
a record is foreign. Post-MAC-invalid fixtures have valid authentication but
invalid IV/metadata; padding conflicts contain two individually valid records.
Framing failures remain fatal and must not permit resynchronization or export.

The core consumer is `urma-core/tests/recovery_vectors.rs`; CLI process tests
consume the same manifest separately. Independent record HMAC checks, strict
acceptance checks and expected error reasons accompany exact recovered bytes.
