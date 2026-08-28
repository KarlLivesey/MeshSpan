# Stage 4 and Stage 5 design decisions

Status: **accepted in discussion on 2026-08-28**.

This document records the detailed decisions for folder storage, shard lifecycle,
the protocol-neutral filesystem and access control. It is design evidence, not a
claim that the behaviour has been implemented. The roadmap exit gates still
determine when Stages 4 and 5 are complete.

## 1. Registered storage folders

- `--storage-path` is repeatable. Each occurrence registers one storage target;
  one daemon may own several differently sized targets.
- A registered folder may contain unrelated files and folders. MeshSpan creates
  and exclusively owns one hidden internal directory and never reads, changes or
  exposes its siblings.
- The internal directory must be empty on first registration or contain the exact
  valid marker for that target. An unknown non-empty internal directory fails
  closed.
- A folder is accepted by measured capabilities rather than by filesystem or
  mount-type allowlists. Local filesystems and remote mounts are eligible when
  probes prove the required atomic rename, durable flush, reopen and locking
  behaviour.
- The target marker and generation identify a returning target; its path, mount
  point and discovery order do not.
- One target has one live daemon owner. A marker plus an exclusive live lock
  rejects concurrent local owners.
- A target returning on its existing node reconnects automatically after marker,
  generation and capability probes pass.
- A target appearing on another enrolled node may relocate automatically only
  after its metadata authority grants a new incarnation and fences the old one.
  A simultaneous duplicate remains quarantined.
- When relocation authority is unavailable, already verified immutable shards
  may be served read-only. New shard writes and deletions remain fenced until a
  fresh incarnation is granted.
- Failure of one target takes only that target offline. A per-target circuit
  breaker retries capability probes with bounded backoff while the daemon and
  sibling targets continue serving.

## 2. Fast return after interruption

A returning folder does not wait for a blocking full scan:

1. validate its marker and incarnation;
2. recover its local SQLite journal and WAL;
3. replay only incomplete transitions since the durable checkpoint;
4. advertise journal-confirmed committed shards;
5. verify any requested shard on first read; and
6. reconcile inventory and scrub contents in parallel in the background.

Background verification prioritises data needed to restore recoverability, then
hot data, then cold inventory. Concurrency adapts to measured spare CPU, memory
and storage latency. Administrators may set ceilings, but ordinary operation does
not require tuning.

## 3. Encryption, integrity and trust

- All stored user data is encrypted at rest. There is no plaintext storage mode.
- A logical file is sliced and erasure-coded, then each resulting shard is
  encrypted independently.
- BLAKE3 is the canonical MeshSpan content, chunk and shard digest. External
  standards may retain their required digest, such as SHA-256 for BitTorrent v2
  adapter metadata.
- Key possession follows capability and trust, not a broad node-role label.
  Trusted nodes serving direct retrieval may unwrap keys for shards they host.
  Untrusted friend-to-friend backup targets may hold only opaque encrypted shards.
- An authorised client may receive decrypted shard bytes over authenticated TLS
  and reconstruct a file locally. It never receives persistent at-rest keys.
- Storage location, a prior checksum, an authenticated sender or a catalogue row
  is evidence only. Every consumer revalidates the exact identity, length,
  digest, generation, authority and bounds required by its operation.

## 4. Capacity and retention

- Every storage target has an explicit MeshSpan usage limit expressed as a
  percentage or fixed byte quantity. The ordinary default is 95%, and it is
  editable.
- Existing sibling files outside MeshSpan's private directory do not count as
  MeshSpan logical usage, although actual filesystem free space and `ENOSPC`
  remain hard physical boundaries.
- Reservations for in-flight writes, repair and movement are explicit and
  visible rather than hidden capacity deductions.
- File-version history is enabled by default.
- Retention supports a minimum age, optional maximum age, pressure cleanup and
  an optional eager mode. The ordinary minimum is 30 days and is
  pressure-breakable unless configured hard.
- Pressure reclamation proceeds in this exact order:
  1. already-due garbage, including expired tombstones and versions beyond the
     configured maximum, oldest first;
  2. previous or deleted versions between the minimum and maximum, oldest first;
  3. only when still necessary and permitted, versions inside a soft minimum,
     oldest first; and
  4. never the current live version or a hard-retained snapshot.
- Early pressure removal is audited and reported. Physical removal still needs
  an authoritative cleanup decision, exact removal permit and durable provider
  tombstone.

## 5. Chunking, layouts and deduplication

- Content uses fixed-size chunks within a recorded layout. Automatic
  power-of-two profiles increase chunk size as files grow, aiming for roughly
  1,024 chunks without making that a hard maximum.
- Chunk growth stops at a measured/configurable maximum; larger files then use
  more chunks.
- Large manifests are bounded, paged Merkle structures. No request must load an
  unbounded list of chunks.
- Files may be re-chunked asynchronously with hysteresis when their size changes
  materially. A complete protected and verified new layout is built before one
  atomic manifest switch. The old layout remains until safe cleanup.
- Re-chunking changes physical representation, not logical file identity,
  content identity or user-visible version history.
- Mesh-wide deduplication is required. Plaintext content has a global BLAKE3
  identity, while files, versions, permissions, owners and quota remain logical
  object concerns.
- Compatible references reuse existing encrypted layouts. Different trust,
  encryption, placement or protection requirements may produce several physical
  layouts for the same logical content.
- Deduplication never exposes a content-existence oracle.
- Quota charges logical file bytes. Physical deduplication savings are reported
  separately.
- Sparse holes read as zero and count towards logical quota. MeshSpan never
  exposes uninitialised storage bytes.

## 6. Scrub, repair and drain

- Scrubbing is continuous by default and may also be scheduled or requested for
  a scope. One bounded scheduler coordinates all verification work.
- Verification age, risk and protection debt determine priority. Scheduled work
  updates the same durable observations so continuous scrub does not reread it
  immediately.
- Repair urgency is risk-based. A healthy layout may debounce a brief flap, but
  imminent loss of recoverability starts repair immediately. Repeated flapping
  cannot postpone repair indefinitely.
- Any eligible storage node may execute repair under a short-lived fenced work
  lease. It pulls verified source shards directly and writes directly to the
  selected destination; metadata leaders and user gateways are not data-plane
  bottlenecks.
- Repairs are copy-on-write. A replacement is durable and verified before its
  location/layout record becomes authoritative; superseded bytes use the normal
  guarded cleanup path.
- Normal drain requires both data safety and continued satisfaction of the
  configured protection policy.
- An explicit temporary degraded drain may proceed once data safety is proved,
  even when it temporarily reduces promised redundancy, for example moving from
  two nodes to one. The reduced state remains visible and repair restores policy
  automatically when capacity returns.

## 7. Staged writes and multipart transfer

- Every writable handle uses a private copy-on-write staging overlay. Partial or
  random writes never alter a published immutable version.
- The protocol-neutral staging API has three distinct operations:
  `checkpoint` durably preserves progress, `commit` atomically publishes a
  complete version, and `abort` makes the stage eligible for guarded cleanup.
- SMB random writes, HTTPS resumable uploads, a future S3 multipart adapter and
  future access adapters share this staging service. Upload parts are not
  MeshSpan content chunks or erasure shards.
- Staged writes and durable handles may resume through another authorised gateway
  using an opaque handle identity and fencing generation.
- Every staged mutation carries an idempotency identity and fence. The staging
  authority durably orders overlapping writes while allowing non-overlapping
  parts to proceed in parallel.
- Concurrent requests with the same operation/part identity and digest coalesce
  into one physical effect and share its receipt. Reuse with different content,
  range or digest is rejected.
- Commit requires an exact final logical length and complete range map. Missing
  ranges fail validation unless explicitly declared sparse, in which case they
  are logical zeroes.
- Incomplete stages consume quota immediately, have a configurable inactivity
  expiry and may be renewed by an authenticated authorised client. Expiry never
  publishes partial content.

## 8. Filesystem namespace and copy-on-write behaviour

- Logical names are case-preserving and case-insensitive with one canonical
  Unicode comparison rule. Provider paths and host filesystem case behaviour do
  not affect namespace identity.
- Exact names that collide after canonicalisation during disconnected operation
  are both preserved. Reconciliation chooses one deterministic ordinary name and
  assigns a deterministic visible conflict name to the alternative.
- Invalid structural merges, including directory cycles, resolve to one valid
  deterministic tree. The affected alternative subtree remains reachable through
  a virtual **Recovered items** view.
- **Recovered items** is filtered through current permissions. It does not grant
  access merely because an object conflicted.
- Initial reconciliation never guesses byte-level merges. It chooses a
  deterministic current version and preserves every acknowledged alternative.
  A replaceable, versioned merge-handler boundary remains for future formats.
- A deleted directory entry disappears from new path lookup while its object and
  versions remain pinned by open handles, snapshots and retention.
- A deleted name may be reused immediately. Stable object identities and
  directory-entry generations ensure an old handle cannot affect its replacement.
- Same-volume move preserves explicit owners and grants while inherited
  permissions are recalculated from the new ancestry.
- A cross-volume move first produces a permission-transfer plan. Compatible
  owners and grants are preserved. Any drop, expansion or transformation is
  shown explicitly and requires an authorised choice; MeshSpan never silently
  strips or smuggles authority. The source remains until destination data,
  permissions and the global move decision are durable.
- A pure file copy creates a new logical object/version referencing the existing
  immutable content manifest. It does not copy shard bytes.
- Ordinary copy applies destination creation ownership and permissions. An
  explicit authorised preserve-metadata option may retain owners, grants, tags
  and timestamps.
- Recursive folder copy captures one immutable source namespace root, creates
  new logical namespace objects in bounded resumable work, continues referencing
  existing content, and reveals the completed destination atomically.
- A volume snapshot pins one exact committed namespace root. A coordinated
  multi-volume snapshot is an asynchronous operation with an explicit
  `in_progress` result.
- Routine key rotation rewraps content keys. Full shard re-encryption is a
  separate explicit, resumable and verified migration.

## 9. Handles, reads and permission changes

- Locks and share-mode reservations are leased and generation-fenced. Clients
  renew them automatically.
- During a genuine partition, locks govern only their reachable authority
  component. Independently acknowledged conflicting work remains preserved and
  reconciles; MeshSpan never claims a partitioned lock was globally exclusive.
- If a required permission is revoked, the affected handle or stage cannot
  continue, upload or commit. Its checkpoint remains temporarily recoverable and
  may resume after that permission is restored and reauthorised.
- An isolated gateway may continue honouring its last committed ordinary file
  permissions. High-risk administrative and activation-required access may
  require an unexpired offline authorisation lease. Remote instantaneous
  revocation and disconnected availability are explicitly incompatible.
- The filesystem exposes both an exact immutable-version read and a live-object
  read. HTTPS normally resolves the live object when a request starts and then
  pins that version for the response. SMB normally uses a coherent live-object
  handle.
- HTTPS uses strong version-derived ETags. Mutating a previously observed object
  requires `If-Match`; an unconditional replacement is a separate explicitly
  authorised intent.
- Directory enumeration pins an immutable namespace revision for stable paging
  while applying current permissions to every page.

## 10. Direct shard retrieval capabilities

- Ordinary HTTPS remains a standard file stream. Advanced HTTP and native
  clients may explicitly request a signed shard retrieval plan and reconstruct
  an exact immutable file version themselves.
- The capability is one transparent signed JWT for all shards belonging to one
  exact immutable file version, not one token per shard.
- The JWT binds the mesh/shard-service audience, principal/session, immutable
  file-version identity, manifest root, `shard:read` operation, authorisation
  revision, unique token identity and validity interval. It contains no keys or
  unbounded shard list.
- Storage nodes independently prove that a requested shard belongs to the bound
  version and that the request falls within the signed retrieval plan.
- Compact JWS uses a fixed Ed25519/`EdDSA` profile and an explicit MeshSpan token
  type. Algorithm, issuer, subject, audience, type, time and claim validation are
  mandatory; token-controlled key URLs are not followed.
- The default retrieval-token lifetime is five minutes and is configurable
  within a policy bound. Longer transfers refresh transparently.
- Exact-token, session, user and affected authorisation-revision invalidation are
  supported. Reachable nodes reject immediately. A partitioned node may continue
  accepting an already valid token until it expires because no design can deliver
  a remote revocation across a broken link.

This profile follows the validation and explicit-typing guidance in
[RFC 8725](https://www.rfc-editor.org/rfc/rfc8725.html) and the EdDSA JOSE mapping
in [RFC 8037](https://www.rfc-editor.org/rfc/rfc8037.html).

## 11. Time and non-consensus state

- UTC timestamps represent human time. Consensus revisions and hybrid logical
  clocks represent causal/distributed ordering; a host wall clock never decides
  history order or conflict victory.
- Join performs authenticated time calibration. MeshSpan derives known time from
  a voter quorum, informed and cross-checked by available PTP and NTP sources.
- A single host clock is not authoritative. MeshSpan asks the native platform
  time service to resynchronise when permitted and keeps retrying automatically.
- If the host clock cannot be corrected, MeshSpan uses the quorum-derived offset
  internally and clearly reports the skew, uncertainty, source observations and
  correction failure.
- If time quorum is temporarily unavailable, the last confirmed time advances
  through a monotonic clock while its uncertainty grows. Ordinary file IO and
  repair continue; time-sensitive irreversible work pauses once the uncertainty
  bound is exceeded.
- The UI distinguishes synchronised, internally compensated and unsafe time.
- File access time is optional and disabled by default. When enabled it belongs
  to non-consensus eventually consistent metadata rather than producing a
  consensus write for every read.
- State has four explicit authority/durability classes:
  - `committed`: authoritative under its required quorum policy;
  - `branch-durable`: acknowledged user work awaiting reconciliation;
  - `eventual`: locally durable metadata propagated by authenticated
    anti-entropy to deterministic convergence; and
  - `ephemeral`: replaceable observations such as connection presence and raw
    metrics.
- Eventual API fields include observation time and freshness/convergence status
  where known. Eventual and ephemeral state may never authorise access, destroy
  bytes, prove protection or report a user mutation as committed.

## 12. Anonymous access and future BitTorrent reads

- Discovery and authorisation are independent. `listed` versus `unlisted`
  controls discovery; `public-anonymous`, `authenticated` or an optional bearer
  capability controls access.
- An unlisted anonymous object does not require a secret. Anyone who knows its
  URL may access it, but MeshSpan does not advertise or enumerate it.
- Anonymous share links may be `live`, following the logical object's current
  version, or `pinned` to one exact immutable version. A transfer always resolves
  and pins one exact version before bytes move.
- BitTorrent read support is a required future adapter, not Stage 5
  implementation. MeshSpan will lazily expose an immutable file version or
  snapshot tree as BitTorrent v2 metadata and seed reconstructed pieces without
  materialising a complete temporary file.
- Torrent pieces and SHA-256 Merkle metadata are adapter concerns. They do not
  replace MeshSpan chunks, shards or BLAKE3 identities.
- MeshSpan does not ingest peer uploads through BitTorrent. Clients may exchange
  pieces of an already exported immutable version.
- Public DHT and peer exchange are allowed only for explicitly public and
  discoverable exports. Unlisted anonymous exports remain private-tracker-only by
  default.
- Standard BitTorrent does not provide MeshSpan session authentication or strong
  revocation. Authenticated private access therefore needs a later MeshSpan-aware
  extension or an explicitly accepted bearer-style export; the roadmap must not
  claim security properties ordinary clients cannot provide.

See [BEP 52](https://www.bittorrent.org/beps/bep_0052.html) for BitTorrent v2
piece metadata and [BEP 27](https://www.bittorrent.org/beps/bep_0027.html) for the
limits of private-tracker peer admission.

## 13. Deferred filesystem surfaces

Stage 5 implements directories, regular files, sparse/random writes, immutable
versions, snapshots and the adapter-facing filesystem service. Symbolic links,
hard links, extended attributes, named streams and special files are future
features. The initial model still reserves deliberate boundaries:

- directory entries are separate from file objects;
- object kinds are versioned and extensible;
- metadata extensions are bounded and typed; and
- provider paths are never logical namespace paths.

Future symbolic links resolve only inside the MeshSpan logical namespace and
never expose host/provider paths.

## 14. Remaining lock questions

Five substantive Stage 4/5 questions remain after this checkpoint:

1. exact dirty-close, flush and explicit-abort mappings for the protocol-neutral
   handle service;
2. bounded logical component, path-depth and encoded-path limits;
3. the optional access-time modes beyond the accepted off-by-default behaviour;
4. measurable fast-return, repair and degraded-read targets for the Stage 4 exit
   gate; and
5. measurable namespace, random-write and permission-evaluation targets for the
   Stage 5 exit gate.

Exact SMB dialect and optional-feature selection remains the later SMB-adapter
decision, not a Stage 5 filesystem-core decision. Exact automatic chunk and
Reed–Solomon profiles are selected from Stage 4 benchmarks rather than guessed in
documentation.
