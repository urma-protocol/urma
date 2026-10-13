# URMA Node

The daemon and the desktop app are published standalone at
<https://github.com/urma-protocol/urma-node>, synced from this tree until the
libraries are on crates.io.

URMA Node is an optional background archive for URMA applications. Its engine
can also run inside a client. Existing publishing and recovery flows continue
to work without installing or starting this service. No wallet signing or
decryption keys belong in the archive.

It provides a transactional SQLite archive,
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

Unpruned retention keeps all verified URMA records and multipart content acquired
by the node. Pruned retention keeps every admissible individual record (`Private`,
`Post`, `Reply`, `Profile`, `Avatar`, `WirePost`, `WireReply`, and
`ProfileRecord`, including Names V0), all multipart `RootManifest` records, and
their referenced raw reveal/commit transactions. Only multipart components
`LeafManifest` and `DataPart` are eligible for omission during scanning or later
eviction when unpinned. Record size does not decide retention. Pruning also
collects raw transactions no longer referenced by any retained record or pending
dependency; it does not remove the transactions needed by individual records.
`Container` is an offline wrapper forbidden in on-chain reveals by V0; it is
rejected during verification, independently of retention mode.
On-demand recovery follows authenticated references,
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
survive eviction. Archives migrate to schema 4 only after
configuration identity is checked. The interim schema 2 can migrate when all
member identities remain recoverable locally; otherwise it is refused without
discarding old evidence.

The embedded Engine also exposes explicit Names V0 registration and incremental
projection: `register_names`, `names_step`, `names_status`, and `names_resolve`.
A registry starts at its authenticated genesis in a fully scanned selected block;
there is no default registry or implicit pre-application history. Each step applies
at most one consecutive fully scanned, dependency-resolved block, including empty
blocks. A Names record's commit needs a selected scanned TXID placement separately
from its authenticated raw bytes. Missing placement refuses the step. Reveals
whose known selected commit placements are all outside the registry's live
window are skipped, allowing the block and its expirations to advance.

Names state is stored per name and pending record, with per-block forward/undo
deltas and outcomes. The registry is restored once when needed, not serialized in
full on every block. Rollback, replacement state, checkpoint and event share one
SQL transaction under the archive coordinator. Reads refuse orphaned checkpoints
until a step reconciles them; an orphaned genesis is refused without rebinding.
The archive retains 1,000 undo frames plus their floor checkpoint; deeper reorgs
require an explicit rebuild. Resolution carries its projected block and separate
completion status. Authenticated local Names endpoints expose the same explicit
operations; reads never register or advance a registry. Synchronizing service
rounds maintain already registered projections in both retention modes, after
the scan/dependency round and before multipart recovery. A rotating cursor
inspects at most 128 registrations and attempts one Names step per round, even
if this round's acquisition failed. Errors advance the cursor and are exposed
separately as `last_names_error`; they do not register, rebind or reset a registry.
Offline service mode leaves advancement manual. These limits bound inspected
registrations and attempts, not SQL duration; cancellation cannot interrupt an
entered state/SQL operation. Optional CLI and gateway consumers use the paged
local-operator view described below; they do not register or step implicitly.

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

Peer discovery and the soft multipart cache target are described below. The
daemon targets Linux: `contrib/` holds a user-systemd unit and an operator
checklist, with no installer. Windows I/O/ACL porting, an installer and Windows
Service integration are not implemented.

The standalone foreground process handles Linux SIGINT, SIGTERM and SIGHUP as
cooperative stop requests, like authenticated HTTP shutdown. Inherited ignored
dispositions (for example SIGHUP under `nohup`) are replaced, so these three
signals always request cooperative shutdown. It waits for the Service worker
and URMA overlay threads before returning. A signal or HTTP 200
acknowledges a request, not completion: wait for process exit before reopening
the archive. Entered source I/O, HTTP handling and SQL are not forcibly interrupted.
Supervisor stop timeouts may still terminate the process; that is not a graceful
join. Embedded `Service` users can request its `shutdown_handle()` and wait for
`run` to return, without installing any process-global signal handler.

A [manual user-systemd template](contrib/systemd/README.md) uses this foreground
process with operator-supplied paths, an offline base invocation and a finite
supervisor stop timeout. It installs, enables and starts nothing automatically.

## Local development

Build with `cargo build -p urma-node --locked`. A JSON config contains `chain`
(for example `litecoin-testnet`), `application_start` (`height` and `hash`) and
`retention` (`pruned` or `unpruned`). Choose an explicit supported start; there
is no fabricated project-start default.

`urma-node --data DIR --config CONFIG status` opens local state without
connecting to any peer. `create-token PATH` creates a new private bearer token.
`serve --token-file PATH` starts on loopback only, offline by default; `--p2p`
opts into the Litecoin source. `--chain-peer IP:PORT` (repeatable, requires
`--p2p`) pins the Litecoin peers it syncs from instead of DNS seeds. `GET /v1/status`, `GET /v1/records/TXID`,
`GET /v1/objects/TXID`, `POST /v1/objects/TXID/pin`,
`POST /v1/objects/TXID/unpin`, `POST /v1/cache/prune` and
`POST /v1/shutdown` require
`Authorization: Bearer TOKEN`. Clients do not open the service database for
writing. The archive uses a process ownership lock and SQLite WAL/FULL on a
local filesystem.

The separate `urma-node-control` client accepts an explicit `--endpoint`
loopback address and `--token-file`, followed by `status`, `object TXID`,
`pin TXID`, `unpin TXID`, `prune`, `overlay-omissions` or `overlay-book`. It does not open an archive or start a
daemon. Commands print JSON; failures use stderr and a nonzero exit status.
Names commands use that same explicit connection and token:
`names-status GENESIS`, `names-register GENESIS HEIGHT HASH`,
`names-step GENESIS`, and `names-resolve GENESIS NAME`. Registration supplies
the actual genesis block placement; resolution requires an already canonical
Names V0 name. These commands call the local API once without automatic scans,
registration, stepping or retries beyond the operation explicitly requested.
Unregistered status prints JSON `null`; unavailable or stale state is an error,
not an unbound name. Resolution includes the projected block and completion
status, which callers must distinguish from the selected tip.
Pinning requires an already verified, fully local object; it does not download
missing content. Pruning reports child records removed, not bytes. Control
POST requests have an empty body and are never automatically retried: a lost
response can follow a successful database commit. Query object status before
deciding whether to repeat an operation after a transport failure.

`Engine::wire_page` and authenticated `GET /v1/wire?limit=N` read the shared
Wire index without another block scan. Pages contain at most 128 selected local
records in height/position order. For continuation, append `&cursor=HEX`, where
HEX encodes the JSON `next` cursor from the previous page. A changed archive or
engine restart refuses the old cursor with HTTP 409; discard the partial result
and restart traversal. Each page carries separate archive coverage. An empty
page or absent continuation means only that the local result set ended; imported
selective records can appear before their blocks have been fully scanned.
These are explicitly trusted local index results. Portable inclusion evidence
is available through record packages and requires independent verification.

Names uses the same bearer authentication and bodyless request rules:

- `POST /v1/names/GENESIS/register?height=HEIGHT&hash=BLOCKHASH` binds an explicit,
  already scanned genesis placement. Repeating the same binding is idempotent.
- `POST /v1/names/GENESIS/step` reconciles retained undo and applies at most one
  next fully scanned block. It never downloads missing history.
- `GET /v1/names/GENESIS` reports the registered projection; HTTP 404 means only
  that this registry is not registered locally.
- `GET /v1/names/GENESIS/resolve/NAME` returns local resolution at the reported
  projected block, with separate selected tip and completion status. NAME must
  already be canonical Names V0 ASCII; it is not normalized by the service.
- `GET /v1/names/GENESIS/view?limit=N[&cursor=HEX]` reads normalized name states
  and pending records, with chain identity, rules and projection status. `N` is
  1..128 total entries. Names sort by canonical ASCII before pending TXIDs sorted
  by their displayed hex. Unbound/suspended names and completed pending records
  remain present. The cursor is hex-encoded JSON `NamesCursor`, bound to the
  registry, engine instance, archive event revision and last emitted tagged key.
  Restart or any committed event invalidates continuation with 409; discard the
  partial traversal. Unregistered views are rejected with 422, never represented
  as empty registries. Orphaned projections/genesis are refused with 409.

View reads hold one archive lock across metadata and rows, without registration,
stepping or acquisition. Rules/state JSON is bounded to 64 KiB before decoding;
oversized entries or a serialized page over 16 MiB refuse the entire page. These
are allocation/result bounds, not a SQL execution deadline. Consumers must also
bound aggregate rows, bytes and traversal time, compare metadata across pages,
and publish only a fully traversed snapshot. Local traversal completion does not
establish `complete_to_tip`. A view supplies no autonomous scanner checkpoints,
commit window or undo; it must not be fabricated into a resumable `NamesIndex`.

Names mutations return typed JSON only on HTTP 200. Malformed fields on supported
routes return 400; unsupported paths or methods return 404 (including a register
path without its query). Unavailable context or stale selection returns 409,
and rejected operations 422. Internal
failures return a generic 500. A transport failure can follow a committed step;
do not automatically repeat mutations. These local operator results are not
portable chain proofs, and a partial projection is not a complete registry view.

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
Manual and seed entries are never replaced or evicted; see Peer discovery below
for seeds and learned addresses. Without `--peer-key`, normal offline/control-only
operation does not read the peer book or start this transport.

The service can use configured peers for unpruned background object recovery,
then fall back to full blocks at known locations. Full-block scanning remains
the independent completeness check. The standalone peer exchange is currently
by requested TXID or inventory range; relay/DCUtR, NAT traversal and two real
consumer applications are still pending.

Wire messages use `/urma/node/record/4`, a 4-byte big-endian JSON length followed
by exactly one payload and stream EOF. Requests are capped at 1 KiB and
responses at 32 MiB (inventory pages 256 KiB, peer gossip 32 KiB). Connections
are capped at sixteen (eight each direction),
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

The transport's network and archive-reader workers are joined at shutdown.
The pinned `futures-timer` dependency also maintains one process-global timer
thread until process exit; it is shared across successive network instances.

### Fast peer synchronization

With `serve --p2p --peer-key PATH`, each `run(true)` round takes one inventory
step after header synchronization and before the full-block scan, whatever the
header result. Peers come from the same peer-book entries as record and commit
sources, one per identity. Status reports three separate progress values:

- `selected_tip`: the locally selected header chain. Headers prove work and
  order, not which URMA records a block contains.
- `peer_synced_through`: heights where a peer listed every record it claims and
  each listed record was fetched and proof-verified against the local headers.
  This trusts the peer's completeness; it proves only what was listed.
- `indexed_through`: the contiguous prefix this node scanned itself from full
  blocks. It is the only completeness claim and stays independent of peers.

A step picks the next peer in rotation, skipping peers with recorded omissions.
It covers at most 4096 heights from that peer's persisted cursor, never past the
selected tip, through inventory pages of up to 512 entries. Records not already
present are fetched from the same peer and admitted; a placement that disagrees
with the proven record, a refused admission or an out-of-order page abandons the
range and is reported as that peer's `last_error`. Pages list only blocks at or
below the serving node's `indexed_through`, which pages report as
`scanned_through`; a scanned block still waiting on a dependency is not listed
yet, and a client drops any listed entry above that ceiling without blaming the
peer. A listed record the peer then answers Missing for stays listed-only: it
does not block coverage and is not retried within that range. Coverage is
recorded only when a range ends with every other listed record present, up to
the lower of the range end and the peer's own scanned height, and only for the
archive generation observed when the range was opened; a reorg in between makes
that claim stale and the range restarts. When the full-block scan later finds a
record inside a peer-covered range that the peer never listed, the omission is
recorded and that peer is no longer asked. A listed-only entry that our own
scan later finds is still recorded as that peer's omission (a rare
eviction/reorg race). `GET /v1/overlay/omissions` returns the newest (highest)
1024 omissions.

Per round and peer: one inventory page, at most 16 package fetches, at least
250 ms between requests to the peer (its serving bucket is four per second),
and a 20-second step deadline, with cancellation checked between requests. A
`Busy` reply or an empty inventory reply ends the step and the same range continues on the peer's
next turn. A listed block that differs from the local selected header at that
height, or a reorg during the step, drops the range quietly: no peer error and
no coverage.
The `overlay` status block (null without `--peer-key`) reports the peer ID,
listener, peer-book size, connected peers, records admitted and packages
rejected since start, and each peer's cursor, synced height and last error;
`last_inventory_error` reports a failed step. Top-level `chain_peers` counts the
Litecoin P2P peers the light client holds now (0 without `--p2p`).

### Peer discovery

Discovery works like Bitcoin's: seeds bootstrap a sparse book, then connected
peers exchange addresses. A successful dial proves only that a Noise identity
answered at that address, never chain membership, record availability or
honesty; inventory sync and full-block audit stay the data checks.

Seeds are multiaddrs with seed origin. Litecoin mainnet has the built-in
`/dnsaddr/ltc-seed.urma.rosint.org` and Litecoin testnet
`/dnsaddr/tltc-seed.urma.rosint.org` (their DNS records are the operator's job;
the node dials whatever they resolve to); regtest and the Bitcoin test chains
have none. Every dial ends with a chain probe, so a node on another chain never
counts as reached. `--urma-seed MULTIADDR` (repeatable) adds more, `--no-seeds` skips the
built-in ones. Seeds are dialed in random order at startup while fewer than
four book entries have ever been reached (ignoring backoff saved by an earlier
run), every round while no peer is connected, and every 600 rounds while below
target; outside startup a failing seed waits out its backoff.

Each `run(true)` round runs one discovery step before the inventory step: while
fewer than 8 peers are connected it dials up to 2 non-seed candidates, alternating
a never-tried entry (at random) with a tried one (oldest expired backoff first),
and every 30 rounds it asks one random connected peer for up to 32 addresses. A
round makes at most three network operations and checks cancellation between
them, each with a 10-second bound. A failed dial backs the entry off for
60 s × 2^(failures−1) (60 s after the first failure), capped at one day; a
success clears it. Each round also merges peers that identified themselves over
a connection (public literal addresses, same caps) and refreshes the snapshot
served to Peers requests from reached book entries. `--urma-announce MULTIADDR`
(repeatable, public IP/TCP) is advertised through identify, as are observed
addresses confirmed by two peers.

`peers.json` (format version 2; older files are refused, not migrated) holds up
to 1024 entries with identity (once learned), up to four addresses, origin
(manual, seed or gossip), last success, failure count and backoff. Gossip may
only add public literal IPs, at most two entries per IPv4 /24 or IPv6 /48;
loopback, private and DNS addresses come only from the operator. Gossip never
changes an entry already in the book: it cannot name an unidentified seed or
manual address (only a successful dial learns identities) nor add addresses to
a known peer; identify may add a known peer's own addresses. At capacity
the gossip entry with most failures and oldest success is evicted; manual and
seed entries never are. Peers with recorded omissions are neither dialed for
sync nor passed on, and the book never contains this node. Record and commit
sources are built from identified book entries at startup; the inventory peer
list follows the book every step, keeping each known peer's in-flight range.

`overlay.discovery` reports `seeds`, `book`, `reached` (last dial succeeded),
`reached_ever` (any past success),
`gossip`, and the last seed-round and gossip errors with their times;
`last_discovery_error` reports a failed step. `GET /v1/overlay/book` returns
the book entries (at most 1024) as `urma-node-client` `BookEntry` values;
without discovery it answers 404 `overlay disabled`, which `Client::overlay_book`
reports as `Error::Invalid("overlay disabled")`.

## Explicit peer probe

`cargo build -p urma-node --example peer_probe --locked` builds a two-process
probe with embedded public signed profile/post fixtures. Run the server with
`peer_probe --data FRESH_SERVER_DIR serve --listen 127.0.0.1:4001`, then pass its
printed IP/TCP/p2p address to
`peer_probe --data FRESH_CLIENT_DIR client --peer ADDRESS`. Send `shutdown` on
server stdin when finished. Its stdin wait is limited to 120 seconds; an
external process supervisor should bound the entire run.

The client checks exact commit/reveal bytes and package contents, independent
admission with zero scan coverage, refusal with a wrong expected identity,
reconnection using a fresh client identity, and an explicit full-block audit
that discovers the second record. Both processes check archive lock release.
Header selection is a synthetic fixture: this is not a live Litecoin consensus
test, a completeness claim from selective data, or a reconnect rate-limit test.
The wrong-identity request must fail, with successful controls before and after;
the probe does not classify the underlying handshake error.

Applications can depend on `urma-node-client` for the same bounded loopback HTTP
client and API data types without linking the daemon, SQLite, Tokio or libp2p.
It still depends on the URMA chain/proof and Wire data types. The Node `Client`
wrapper preserves its error API and implements the Node-local record-source
interface. Both clients treat index pages as local operator data; parsing is not
independent verification of author signatures or chain inclusion.

### Soft multipart cache target

Background `run(true)` rounds also maintain the pruned multipart cache, after
scan/dependency, Names and object work, even when another stage fails. The
operational `--cache-bytes` target defaults to 128 MiB; zero requests eventual
drainage over successive steps. It does not change persisted archive identity.
`run(false)` remains worker-free. Embedded/offline users can call
`Engine::maintain_cache(limit_bytes, cancelled)` explicitly.

The metric counts unpinned LeafManifest/DataPart `record` and `proof` bytes per
placement, plus raw transactions once per WTXID when no protected record or
unresolved dependency needs them. Already unreferenced raw backlog is included.
All individual records, roots, pinned exact members (including orphans), and
raw evidence referenced by retained records/dependencies remain protected.
Unpruned mode reports enforcement disabled and deletes nothing.

Each atomic step deletes at most 128 child placements in block-hash/position
order, then at most 512 currently unreferenced raw rows in WTXID order. This is
not LRU or a minimal eviction set. Shared raw survives until every remaining
record reference is gone; dependencies protect all witness variants of their
parent TXID. Scan coverage, locators, object identities/member hashes, pins and
Names projections survive. Mutation, including raw-only reclamation, writes an
event so prior paged snapshots become stale.

This is a soft target for reclaimable logical evidence, not total stored bytes,
SQLite/WAL size, RSS, or instantaneous admission capacity. Protected data may
grow beyond the target. SQL accounting work and duration are not bounded by the
deleted-row caps, and entered SQL is not preempted. Cancellation is checked
before and after acquiring the archive mutex. Recovery not yet atomically pinned
may lose cache under pressure and must refuse incomplete completion; its success
is not guaranteed under eviction. Existing pins remain protected.

HTTP status exposes `cache_limit_bytes`, independent `last_cache_error`, and
`last_cache_maintenance`: the last successful maintenance receipt, with before
and remaining bytes, actual deletion counts, enabled mode, and `over_budget`.
These are historical measurements, not live usage after later admission/pinning.
A failed step preserves the previous successful receipt and reports its error;
its database mutations roll back. Manual `cache/prune` retains its existing
all-unprotected-children behavior.

### Missing commit acquisition

Embedded owners can supply a `CommitSource` to
`Engine::resolve_next_dependency(source, cancelled)`. One call selects one
distinct missing parent from dependencies in the selected scanned view. An
in-memory cursor advances on misses and errors so unavailable parents do not
starve later ones; it is not persisted across restart. The source's configured
chain and the returned transaction's computed TXID must match the request.
The selected generation remains fixed across acquisition and verification;
a reorg refuses the attempted completion instead of adopting a newer branch.
At most 128 existing references are finalized atomically. When parent bytes were
retained, `resolve_cached_dependency` can finish remaining references locally.
Invalid candidates and omitted Pruned children do not retain the fetched parent;
remaining references can require another explicit source call.

Parent bytes are self-authenticating: the Engine recomputes the TXID and
re-verifies the reveal, so which source supplied them does not change this
evidence. They are auxiliary prevout evidence only; they add no parent
placement, inclusion, witness or scan-coverage evidence, and Names still
requires a selected commit placement. A miss or failure leaves the dependency
unresolved.

`CommitSources` tries labelled sources in order until one returns bytes; a
miss or error moves to the next source, and the set reports an error only when
every source failed. Returned bytes must decode for the chain and hash to the
requested TXID before the set accepts them; a mismatch counts as that source's
error. Each source keeps its own last error. A cancellation request is checked
before each source and returned without being recorded. Embedded `Service`
owners call `with_commit_sources(sources)`; an empty set or a source for
another chain is refused at configuration.

Litecoin Core is optional acceleration, not a requirement. Under `serve --p2p`
the daemon assembles, in this order:

1. `local-rpc`, only with `--commit-rpc-url URL --commit-rpc-cookie PATH` (both
   required together). `Node::connect` requires an `http` URL whose host is a
   loopback IP literal (`localhost` is refused), path exactly `/`, no userinfo,
   query or fragment, and cookie-file authentication. Absence is the typed
   Missing result or JSON-RPC code -5, which also covers lookups a node without
   `-txindex` cannot answer, so a synchronized `txindex=1` is required.
   The daemon starts without Core: startup checks only that both flags are
   present. Each lookup reads the cookie, and a new cookie (a restarted node)
   is connected and txindex-verified once; until then the entry falls through
   to the next source. Status probes it at most every 10 seconds (cookie read
   plus `getblockcount`), so `commit_sources` shows `local-rpc` flip between an
   error and `null` as litecoind stops and starts.
2. `overlay`, with `--peer-key`: the same peer-book entries used for record
   recovery. Peers serve only raw bytes they already retain and never fetch on
   behalf of others.
3. `public`, unless `--no-commit-public`: the chain's default public providers
   (a chain without defaults, such as regtest, gets no entry), with TLS pins
   under `DATA/providers` (mode 0700) and no light client. The providers are
   first contacted lazily on the first missing parent, so an offline start
   succeeds; a failed connection is not retried for 60 seconds.

Under `--p2p` the daemon therefore sends missing-parent TXIDs to URMA peers
and, unless `--no-commit-public`, to the chain's default public providers;
those operators can observe which transactions this archive is missing. Without
`--p2p` no commit source is constructed or called.

Each `run(true)` round, after scan/cached-dependency work and before Names,
calls `resolve_next_dependency` once, so at most one missing parent is fetched
per round, independent of that round's sync result. `run(false)` never calls a
source. Status reports `commit_sources` as an array of `{label, last_error}`
(empty when none is configured) and the overall `last_dependency_error`; an
error observed after a stop request is not recorded. A running fetch is not
interrupted by stop; shutdown waits for it.

The chain decoder limits raw input to 8,000,000 bytes. The runtime adapter checks
16,000,000 hex characters before its own decode, but `Node::call` may already
have allocated or decoded transport data. These are admission limits, not a
transport allocation or RSS bound. Sources own their I/O limits. Cancellation
is checked between callbacks/proof work and after the final archive lock;
entered source I/O or SQL is not preempted, and no global deadline is promised.
