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
Litecoin header backend cannot retrieve heights before its anchor. An explicit
bootstrap file can supply an earlier trusted anchor and its preceding context;
no historical anchor or application-start default is shipped. Starting the
daemon is not evidence of historical coverage.

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

Unpruned background rounds attempt a block scan, then at most one
incomplete object. Previously verified cached objects can complete even when
the current synchronization or scan attempt fails; synchronization and retention
errors are reported separately. A rotating root cursor lets later objects proceed when one
is unavailable or exceeds configured limits. CLI defaults are 64 MiB payload,
4,096 records and a cooperative 15-second acquisition budget per object; these
are resource settings, not protocol limits. Use `--max-object-bytes`,
`--max-object-nodes` and `--object-timeout-seconds` to configure them. In-flight
source calls and SQL commits are not forcibly interrupted. Failed acquisitions
remain incomplete and the local status reports the last retention error.
Pruned mode does not automatically download complete objects.

Background cache size limits, distributed peer discovery, application adapters and
service packaging are not yet delivered.
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
opts into the Litecoin source. `GET /v1/status`, `GET /v1/records/TXID`,
`GET /v1/objects/TXID` and
`POST /v1/shutdown` require
`Authorization: Bearer TOKEN`. Clients do not open the service database for
writing. The archive uses a process ownership lock and SQLite WAL/FULL on a
local filesystem.

`serve --p2p --header-bootstrap FILE` supplies an explicit checkpoint with
preceding context instead of the embedded legacy checkpoint. The bounded JSON
file has fields `version` (1), `chain` (matching the archive), `height`, `header`
(80-byte anchor encoded as 160 hex characters) and `ancestors` (header hex strings,
oldest first). Litecoin requires exactly `min(height, 2016)` ancestors. The
application start must be at or after this anchor. There is no default historical
anchor file: its chain membership and height are an explicit operator trust
decision. Ancestor hash links and PoW are checked before opening the separate
strict cache; every successor then gets difficulty and median-time checks with
the required context. Ancestors do not become scan coverage or selectable history.
This does not establish contextual consensus before the trusted anchor. Without
this option, the embedded legacy bootstrap still pins its first successor and
initially uses a truncated median-time window.

Header validation is relative to the configured checkpoint and local cache.
Insufficient local difficulty history is reported separately from an invalid
peer header. It does not justify deleting the header cache or banning the peer;
it also does not establish a successful header refresh.
Neither the light client nor inclusion proofs establish full scripts/UTXO/MWEB
consensus, independence of peer operators, or completeness of selective data.
The URMA V0 wire protocol and Names V0 semantics remain unchanged.

## Direct URMA peer exchange

The experimental overlay uses libp2p 0.56 with TCP, Noise and Yamux. It is
separate from the bearer-protected loopback API. An explicitly started peer can
serve selected locally retained record packages; it does not fetch on behalf of
inbound requests, serve wallet secrets, offer control commands or certify scan
coverage. A receiving engine verifies packages against its own selected headers.
`Missing` means only that this peer has no selected local package.

Use `create-peer-key PATH` to create a new private Ed25519 transport identity,
then opt in with `serve --peer-key PATH`. This identity is not a wallet or a
decryption key. There is no automatic key creation or peer startup. Add
`--urma-listen 0.0.0.0:28332` to accept inbound peer connections, or omit it for
outbound-only operation. Add explicit peers using
`--urma-peer /ip4/ADDRESS/tcp/PORT/p2p/PEER_ID` (IPv6 also supported). Addresses
and their origins are saved in the archive's bounded `peers.json`; identities
are authenticated during connection setup but are not authorities for URMA data.
The peer book has no implicit seed, DNS lookup or automatic replacement of
manual entries. Without `--peer-key`, normal offline/control-only operation does
not read the peer book or start this transport.

The service can use configured peers for unpruned background object recovery,
then fall back to full blocks at known locations. Full-block scanning remains
the independent completeness check. The standalone peer exchange is currently
by requested TXID; range discovery, address gossip, relay/DCUtR, distributed
discovery and two real consumer applications are still pending.

Wire messages use `/urma/node/record/1`, a 4-byte big-endian JSON length followed
by exactly one payload and stream EOF. Requests are capped at 256 bytes and
responses at 32 MiB. Connections are capped at eight (four each direction),
one per peer, with at most four pending handshakes per direction. Request-response
streams are limited to two per connection; Yamux uses its bounded 0.12 backend
with four streams and 256 KiB buffering per stream. Application queues, active
requests and archive-reader work are separately bounded. Serving permits 16
requests per second globally and four per peer identity with matching burst sizes.
Spent identity allowance survives reconnects; a maximum of 256 recent buckets
is retained, and only fully replenished buckets are forgotten. At capacity, new
identities are refused instead of evicting spent allowance. Response payload
allowance has a 64 MiB burst and 4 MiB/s refill; this does not count TCP, Noise or
framing overhead. Overload can refuse data.
These are operational limits, not changes to URMA V0.

Connect/handshake timeout is five seconds; the request-response stream timeout
is eight seconds after negotiation, and a caller has a ten-second total budget.
The latter also covers queueing. Cancellation does not release issued request
accounting until a terminal transport event; late replies cannot become success.
Shutdown joins owned workers. Already-running SQLite work and bounded codec CPU
work are cooperative rather than forcibly interrupted. These limits are not a
claim of a tested global memory ceiling or resistance to every denial of service.
