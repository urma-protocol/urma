# URMA Node — implementation in progress

URMA Node is an optional background archive for URMA applications. Its engine
can also run inside a client. Existing publishing and recovery flows continue
to work without installing or starting this service. No wallet signing or
decryption keys belong in the archive.

This development branch currently provides a transactional SQLite archive,
an authenticated loopback status service, checkpoint-relative header ingestion
and full-block scanning. It preserves transaction encodings separately from
Bitcoin/Litecoin transparent projections. Selected headers, full-block scan
coverage, unresolved commit dependencies and retained bytes are separate state.
Selective transaction proofs commit to both TXID and witness; they cannot claim
that an interval has been fully scanned.

The archive requires an explicit chain and application-start height/hash. It
does not replace the application start with a recent checkpoint. The existing
Litecoin header backend cannot retrieve heights before its anchor. Historical
bootstrap context is still being implemented; starting the daemon is not
evidence of historical coverage.

The `Retention` configuration distinguishes pruned multipart roots from
unpruned record retention. On-demand recovery follows authenticated references,
using selective packages or full blocks at known transaction locations. Missing
commit dependencies remain visible and can be resolved later. Local clients can
share packages through the optional authenticated service; each receiving engine
verifies them against its own selected headers.

Successful reconstruction records exact object members separately from scan
coverage. `object_status` distinguishes historical verification, current local
availability and whether the recorded placements remain selected. `recover_and_pin`
atomically protects a complete object's evidence, including in pruned mode.
`set_pin` can protect an already verified object if all members remain local.
`prune_cache` explicitly evicts unpinned multipart leaf/data records only; roots,
application records, scan marks and transaction locators survive. Unpruned mode
does not evict. Pins retain orphan bytes after reorg without claiming confirmation.
Concurrent eviction can refuse recovery completion; it cannot publish a false
complete/pinned state. A pin cannot silently move to new member placements:
unpin explicitly before replacing its evidence after a reorg. Member hashes
survive eviction. Schema 1 archives migrate additively to schema 3 only after
configuration identity is checked. The interim schema 2 can migrate when all
member identities remain recoverable locally; otherwise it is refused without
discarding old evidence.

Automatic complete-object acquisition, background cache size limits, URMA peer
transport, application adapters and service packaging are not yet delivered.
Windows private-file ACL and existing runtime I/O
porting are also outstanding. This is not a release candidate.

## Local development

Build with `cargo build -p urma-node --locked`. A JSON config contains `chain`
(for example `litecoin-testnet`), `application_start` (`height` and `hash`) and
`retention` (`pruned` or `unpruned`). Choose an explicit supported start; there
is no fabricated project-start default.

`urma-node --data DIR --config CONFIG status` opens local state without
connecting to any peer. `create-token PATH` creates a new private bearer token.
`serve --token-file PATH` starts on loopback only, offline by default; `--p2p`
opts into the Litecoin source. `GET /v1/status`, `GET /v1/records/TXID` and
`POST /v1/shutdown` require
`Authorization: Bearer TOKEN`. Clients do not open the service database for
writing. The archive uses a process ownership lock and SQLite WAL/FULL on a
local filesystem.

Header validation is relative to the configured checkpoint and local cache.
Neither the light client nor inclusion proofs establish full scripts/UTXO/MWEB
consensus, independence of peer operators, or completeness of selective data.
The URMA V0 wire protocol and Names V0 semantics remain unchanged.
