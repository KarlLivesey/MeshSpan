# Stage 5 implementation evidence

Status: in progress, started 2026-08-28.

Stage 5 turns authoritative identity/metadata foundations into one protocol-neutral,
copy-on-write filesystem service. This document records executable evidence only.

## Delivered foundation

- `meshspan-filesystem` owns logical namespace semantics independently of HTTPS,
  SMB and provider paths.
- Namespace components preserve NFC display spelling and use full non-Turkic
  Unicode case folding plus NFC for deterministic case-insensitive uniqueness.
  Compatibility is therefore not delegated to a gateway locale or host
  filesystem.
- The portable appliance profile rejects ambiguous dot segments, separators,
  controls, trailing space/dot, reserved device stems and characters unusable by
  the initial access clients. An extended profile relaxes interoperability rules
  while retaining mandatory structural and allocation safety.
- Component bytes, root-relative depth and both display/canonical encoded path
  bytes have explicit per-volume limits beneath fixed implementation ceilings.
  Paths accept already-tokenised components so the filesystem never guesses an
  adapter's separator/escaping rules.
- Cross-form vectors prove composed/decomposed Unicode and full folds such as
  `Straße`/`STRASSE` collide without losing the chosen display spelling.
- The pure staged-write kernel fences resumed writers, independently verifies
  every range digest, coalesces exact operation retries, rejects conflicting ID
  reuse and orders overlapping writes deterministically. Checkpoints expose a
  merged range map; commit refuses holes unless sparse completion was explicit,
  in which case only logical zeroes fill them. This is the shared semantic oracle
  for the durable staging backend and is not itself claimed as persistence.
- The durable staging backend now journals stage identity and ordered accepted
  ranges in a dedicated SQLite-compatible WAL with `FULL` synchronisation, and
  stores each operation as an immutable, digest-verified part beneath the daemon
  state directory. A part is synced and its directory entry made durable before
  its journal acknowledgement; orphan parts are ignored until an exact retry
  adopts them. Executable restart tests cover overlapping writes, holes, sparse
  completion, expiry, corrupted parts, recovery of a missing stage directory,
  and process loss after durable part installation but before journal commit.
  Completion can now materialise overlapping random writes and stream the exact
  logical image through a fixed 64 KiB heap buffer, including large sparse
  extents, while rechecking every immutable part and hashing the complete
  output. A failed destination write publishes nothing and an exact retry
  reconstructs the same image. This removes file-size-proportional memory from
  the production completion path. It supplies the durable private-input half of
  gate 2; manifest construction and branch publication remain a separate
  receipt-bound transition into the branch database described next.
- The branch database persists complete verified manifest roots and immutable
  file versions. Its file-current pointer is now an internal projection updated
  only by the namespace publication transaction; the earlier unattached
  publication API and operation table were removed rather than leaving a path
  that could claim a file save without moving the namespace head.
- The directory-block semantic kernel is a content-addressed 16-way radix trie
  over the complete BLAKE3 canonical-name key. Every immutable node has bounded
  fanout, hostile true-hash collisions have a bounded sorted bucket, and one
  entry mutation path-copies at most 65 nodes regardless of directory size.
  Lookups revalidate every selected node; complete graph validation rejects
  digest mismatch, wrong-depth edges, cycles/shared-edge aliases, malformed
  ordering and keys placed under the wrong radix path. Historical roots retain
  unchanged subtrees. A 512-entry executable vector proves constant mutation
  work, while stale revision and stable-object replacement attempts fail without
  moving the root. Durable node persistence is described next; volume-head
  integration remains open.
- Branch schema v2 adds a bounded immutable directory-node repository without
  rewriting schema v1 history. Each canonical node encoding is decoded,
  structurally revalidated and rehashed before insertion and after every load;
  at most the 65 nodes produced by one path mutation enter a transaction. Exact
  retries coalesce, while different/corrupt bytes under a digest fail closed.
  Restart and deliberate-blob-corruption tests exercise the durable codec, and a
  database constructed at schema v1 migrates transactionally to v2 with both
  migration digests retained. The volume-head transaction can now consume these
  exact durable node identities without scanning or rewriting a directory.
- Branch schema v3 adds immutable file/root object revisions, causal namespace
  commits and branch/volume heads. The public root-file publication transaction
  loads and revalidates only the selected old radix path, independently
  recomputes its path-copy, inserts the manifest, file version, new nodes, both
  object revisions and commit, then compare-and-swaps both file and volume heads
  with one receipt. The request/record/commit/result digests bind every causal
  base and result. Restart replay, stale concurrent base, corrupt receipt/commit/
  object revision, and injected interruption after each of six internal phases
  prove exact old-or-new atomicity. Gate 2 remains open until durable stage
  completion and manifest construction are composed with this publication as
  one recoverable service operation.
- Branch schema v4 adds receipt-bound directory creation and generalises file
  publication from a root leaf to a validated root-relative path. Every existing
  ancestor is bound by stable object identity plus exact prior and replacement
  revision; the leaf is changed first and each selected directory is then
  path-copied back to the volume root in the same transaction. A production
  sequence creates `accounts`, creates `accounts/2026`, commits encrypted staged
  content at `accounts/2026/report.txt`, and verifies exact replay. Restart tests
  inspect every durable root-to-leaf edge. Corrupt receipts, cross-kind operation
  reuse, missing/stale ancestors and injected failure at every transaction phase
  all fail without a partial namespace transition.
- Branch schema v5 records one canonical replay intent in the same transaction
  as every new namespace commit. The intent preserves the validated display and
  case-folded path components, leaf object/revision, causal prior, name
  generation and typed file-version or directory mutation. Reconciliation can
  therefore replay only affected paths instead of scanning or diffing the whole
  namespace. Loads revalidate the stored Unicode key, aggregate path bounds,
  intent digest, commit, object-revision kind and selected file version. Restart
  and deliberate stored-path corruption proofs exercise the durable contract.
- Branch schema v6 extends every nested replay intent with the exact stable
  directory identity and prior/resulting revision at each source ancestor. This
  prevents a descendant from being replayed beneath the wrong same-named
  directory after a disconnected create conflict. Loads verify the full lineage
  length, ordering, identity, directory kinds and revision chain; restart and
  corrupted-lineage tests cover nested directory and file commits.
- The filesystem commit service now composes an exact fenced stage checkpoint,
  a replaceable durable-content publisher and the atomic namespace transaction
  under one operation identity. Content must resolve or become independently
  durable before a namespace head can move. A lost content reply publishes no
  name; exact retry resolves the durable manifest without rereading an expired
  stage, and a lost namespace reply resolves through the branch receipt.
  Conflicting retries and corrupt manifest identity/length/content evidence fail
  closed. A vertical real-IO proof drives the completed stage through the Stage
  4 registered-folder provider's reservation, packed-shard journal and receipt,
  then retrieves the exact stored bytes under an authenticated read permit,
  authenticates/decrypts them back to the staged plaintext and leaves sibling
  files untouched. Provider bytes are demonstrably not plaintext. The chunk
  codec uses a per-layout, drop-zeroised content key so routine protection-key
  rotation can rewrap that key rather than rewriting user data. Its XChaCha20-
  Poly1305 key, nonce and associated data bind manifest, format, chunk index,
  exact length and plaintext digest; ciphertext and recovered plaintext are
  independently rechecked. Per-layout content keys now have a fixed-width,
  manifest-bound authenticated envelope under a generation-fenced volume key.
  Envelope nonces mix fresh entropy with manifest, generation and content-key
  identity under a separate keyed domain. Rewrap proof changes only the envelope
  generation/bytes and produces byte-identical chunk encryption afterwards;
  neither plaintext content nor provider chunks are rewritten. Decrypted key
  buffers and owned key material are drop-zeroised. Cross-platform vectors cover
  deterministic output, wrong manifest/format/index/generation, forged digest/
  tag, invalid keys/bounds and unavailable entropy. The production initial
  publisher now streams a private durable spool into bounded encrypted chunks,
  appends immutable layout identities in pages of at most 1,000, seals the
  independently recomputed manifest and wrapped key, then records an exact
  provider receipt for every chunk before reporting the manifest durable. The
  initial layout is explicitly one-node and unprotected; Stage 8 replaces its
  placement/coding decision without replacing this lifecycle. A real registered-
  folder proof stages `helloworld` as three chunks, reads each ciphertext by
  authenticated shard identity and reconstructs the exact file. A second proof
  interrupts the second provider write, drops and reopens every filesystem and
  provider store, resumes only the missing receipts from the durable spool and
  reaches the same atomic namespace result. Absent, exact-retry and conflicting-
  operation catalogue lookups are separately exercised. Gate 2 is therefore
  closed.
- Branch schemas v10 and v11 establish authority-owned durable file handles,
  share reservations, leased byte-range locks and pending delete-on-close state.
  Open resolves a canonical logical path through the exact current immutable
  namespace root and binds the resulting object revision and file version; it
  never accepts or stores a provider path. Desired access and share permissions
  are checked bidirectionally across every live gateway handle in one immediate
  transaction. Exact retries survive restart, while stale namespace lineage,
  identity reuse and corrupt receipts fail closed. Lease renewal retains a
  fence; explicit gateway takeover advances it and transfers active locks so the
  old gateway can no longer mutate them. Shared/exclusive range overlap,
  adjacency, expiry, explicit unlock and close-time release have executable
  vectors. Delete-on-close first blocks new opens, then becomes ready only after
  the final live handle disappears. No physical or namespace deletion is
  authorised by this readiness record alone. Atomic creation, close-time commit,
  namespace rename and final unlink remain required before gate 5 can close.
- The common filesystem service now creates a bounded private stage before it
  returns any writable handle and durably orders each immutable range write in
  the handle-authority database before accepting the corresponding stage part.
  This explicit two-database transition means a crash can leave a replayable
  admission or an empty orphan stage, but cannot report unstaged bytes as
  written. Live foreign byte-range locks are checked in that authority
  transaction; exact write replay, changed-content reuse, forged gateway
  authority, restart and receipt corruption have service-level vectors. A
  writable-handle lease takeover preflights and advances the private stage to
  the same fence, so the former gateway cannot continue through either database.
  Handles retain the resolved namespace entry's case-preserved canonical path,
  not the caller's alternative casing and never a provider path. Handle flush
  now persists its exact namespace base, stage checkpoint and derived immutable
  identities before content work. It reconstructs a bounded private completion
  image by streaming the independently verified opened version and overlaying
  durable stage ranges in order; uncovered extension bytes fail unless sparse
  completion was explicit. Content becomes durable before one atomic namespace
  transition advances both the branch head and handle progress. Exact retry
  resolves the same receipt without rebasing, including after every filesystem,
  catalogue and folder-provider store is dropped and reopened. A real-folder
  proof publishes encrypted `helloworld` across three chunks, changes only its
  middle bytes through a handle, reads authenticated encrypted base shards,
  publishes the replacement and verifies `heZZoworld`. Substituted manifests,
  changed retries, corrupt plans, incomplete ranges, stale fences and missing
  content fail closed.
- The replicated metadata kernel now evaluates one connector-neutral access
  request against an authoritative digest-only session, active principal,
  exact gateway incarnation, namespace object/ancestor chain, nested groups,
  multiple owners, scoped allow grants, inheritance boundaries, time windows
  and activation evidence. An administrator role contributes no file rights.
  Membership removal, permission-grant revocation and activation revocation are
  audited state-machine transitions that immediately advance the identity
  fence; membership add/remove history remains append-only across intentional
  re-addition. Principal lifecycle is likewise explicit and append-only:
  suspension is reversible, retirement is terminal, the last active system
  administrator cannot be disabled, and any object that would lose its final
  active owner must receive its exact replacement owner set in the same
  transaction. Restart, exact replay, incomplete/contradictory schema evidence,
  every injected apply boundary and the complete access loss/restoration path
  are executable.
- The logical filesystem now exposes one replaceable operation-time authority
  contract rather than accepting a connector's claimed revision as proof. Its
  composed service resolves an existing path or live handle to a stable logical
  object, requests the exact protocol-neutral right set, rejects mismatched,
  expired, zero-revision or zero-evidence grants, and repeats the expected-object
  comparison inside final open admission. The same boundary fronts open,
  create-or-open, write, flush, dirty close, lease renewal/takeover, directory
  creation, rename and unlink. A focused durable proof opens a real branch file,
  revokes authority before a write, verifies that neither the handle admission
  nor private stage advanced, then restores authority and applies the untouched
  write at checkpoint sequence one. The cluster adapter drives the real
  replicated metadata evaluator: an owner session receives an exact bounded
  grant and immediate committed session revocation becomes a typed denial.
  Handle reads now revalidate `READ_DATA`, pin one exact private checkpoint and
  overlay its verified journal-ordered parts on the immutable opened version in
  at most 8 MiB of memory. Another handle continues to read only published
  bytes. Tests cover partial overlap, short EOF, zero-filled private extension,
  excessive requests, forged part bytes and revocation before content IO.
  Immutable `stat` now revalidates `READ_ATTRIBUTES` and independently checks
  directory-entry, object-revision, file-version and manifest relationships.
  Directory enumeration revalidates `LIST` before trie traversal, returns a
  deterministic page of at most 1,024 minimal child records and emits a cursor
  only when another entry exists. The cursor binds namespace commit, directory
  object/revision, last name hash and canonical component; a later namespace
  head fails stale rather than mixing pages. Tests prove one-entry paging,
  reauthorisation, revocation and stale continuation after mutation. Connector
  conformance remains open.
- The complete 13-bit protocol-neutral rights vocabulary now has an executable
  authority vector. Each right is granted independently on one exact object,
  evaluated through a freshly fenced real session, bound into a distinct
  capability digest and then evaluated together as `Rights::ALL`. This catches
  omitted bit handling and accidental aliasing rather than assuming read/write
  examples cover rename, delete, ownership or permission administration.
- Metadata schema v28 adds partial seek indexes and typed administration
  projections for an object's current immutable owner set, current grants by
  exact scope or subject, and nominally live activation records. Every page is
  explicitly bounded. Cursors are bound to their original object, scope or
  subject; owner pages also bind the exact object and owner-set revision, while
  activation pages bind the authoritative observation instant. Substitution or
  an ownership change fails stale. Revoked grants and explicitly revoked or
  expired activation records disappear from the current views, while activation
  records remain informational and never substitute for operation-time source,
  membership, policy and session evaluation. Migration digest, paging,
  revocation, expiry and stale-cursor behaviour are executable.
- The first true adapter-facing surface now covers existing-file open, bounded
  read, private write and flush. Its inputs contain no branch ID, principal,
  authorisation revision, gateway claim, content digest, retention sequence,
  manifest format, SQL or provider path. `BoundFilesystemAdapter` binds the
  daemon's local branch and publication policy, reloads the exact live handle
  identity/fence context and hashes untrusted write bytes itself. An external
  integration proof drives two independent in-process gateway translators
  through this trait: a missing credential fails before admission, incompatible
  sharing fails exactly, a second gateway sees only published bytes, a gateway
  substitution cannot write another gateway's handle, committed flush survives
  a complete filesystem-store restart, and the failed gateway's later
  uncommitted private write remains invisible. The proof compiles against public
  crate exports, so it cannot reach SQL or hidden provider-location state.

## Closure gates

1. [x] Protocol-neutral canonical component/path types and compatibility bounds.
2. [x] Persistent immutable versions, staged random writes and atomic CoW volume heads.
3. [x] Deterministic branch commits, disconnected reconciliation and recovered items.
   Durable branch commits now bind exact nested mutation lineage, and a pure
   bounded replay planner validates each commit-bound mutation-intent digest,
   the causal plan's exact headers and the affected-entry base before producing
   one digested action sequence. Merge commits have a distinct plan-digest
   payload and are proven to remain causal markers rather than replay actions.
   Tests prove delivery-order independence, same-name recovered copies, later edits
   following a recovered file, descendants following a recovered directory,
   and fail-closed handling of malformed intents, incomplete bases and commit
   substitution. A production SQLite applier now revalidates every commit and
   intent at apply time, path-copies the exact actions, materialises recovered
   copies under independently owned file versions, and atomically records the
   immutable multi-parent merge plus a digest-bound retry receipt. Real database
   proofs cover restart/idempotency, divergent roots, concurrent same-file edits,
   post-merge causal loading, receipt corruption and rollback at every injected
   transaction boundary. The cluster composition boundary now reloads the exact
   local receipt and immutable merge, proves the volume, root and prior converged
   parent, then constructs one canonical replicated command. The metadata state
   machine performs a per-volume compare-and-swap, appends immutable evidence
   history and its normal operation/audit receipt in one transaction. Local and
   replicated databases deliberately remain separate: a crash after the local
   commit leaves a resolvable receipt for exact retry, while a stale replicated
   head rejects without hiding or deleting the local merge. Tests cover the real
   cross-crate path, restart/lost response, conflicting evidence, stale bases,
   broken history and rollback at every metadata transaction boundary.
4. Snapshots, retention and restore-as-new-head. The first authoritative slice is
   implemented: a manual snapshot command pins the exact current converged
   commit and root in constant metadata work, records an idempotent audited
   receipt, rejects stale heads and elapsed expiry, survives restart, and exposes
   index-aligned bounded listing with a next cursor only when another page
   exists. Manual or due automatic expiry can now move an unprotected snapshot
   into an explicit expiring state behind an exact snapshot-revision CAS. The
   same transaction retains an immutable reason record and normal operation/audit
   receipt; restart, exact replay, premature automation, protected roots, stale
   revisions and every injected apply boundary are proven. An expiring snapshot
   can now drop its root only through a separate authoritative command bound to
   the exact snapshot revision, pinned namespace commit/root and accepted expiry
   operation. The atomic transition records immutable removal evidence plus the
   normal operation/audit receipt; substitution, stale state, restart/replay and
   every injected apply boundary are proven. It deliberately authorises no shard
   deletion. The metadata repository also exposes the complete converged-head
   plus active/expiring-snapshot root set as stable bounded pages tied to one
   exact catalogue revision. Any mutation between pages makes continuation fail
   stale instead of mixing root sets; an absent head or malformed root fails
   closed. This is the authority input for the separately durable filesystem
   graph scan. Fixed-interval schedules now use immutable configurations and
   one indexed authoritative due head. Due work is bounded and cursor-paged; a
   late run captures the exact converged head once, records its occurrence,
   derives its expiry, and advances beyond the current instant without replaying
   a storm of missed intervals. Sequence/due CAS, disabled and premature runs,
   stale heads, restart/replay, duplicated configuration corruption and every
   injected apply boundary are proven. Each successful run also receives a
   gap-free per-schedule sequence. Indexed bounded selection now finds exact age
   and “older than newest N” candidates, and the expiry mutation independently
   revalidates the typed reason against current retention state. Corrupt run or
   configuration ledgers fail closed. Whole-volume restore-as-new-head is now a
   two-phase cross-database transition: the filesystem store prepares an immutable
   single-parent restore commit without advancing its branch, the cluster boundary
   reloads and verifies the exact durable receipt, and replicated metadata validates
   the snapshot revision/source/root before one head CAS and immutable restore-history
   insert. Only that committed authority permits idempotent local activation. Lost
   responses, restart, stale heads, substituted roots/evidence, premature causal
   reconciliation and every injected local/metadata transaction boundary are proven.
   Every new volume now receives the
   accepted safe ordinary-history default: enabled, 30-day soft minimum,
   pressure-triggered reclamation and a
   separate 30-day conflict minimum. Policy changes append immutable per-volume
   revisions behind an exact sequence CAS; validation rejects zero counts,
   inverted ages, unsafe conflict minima and maximum-age mode without a maximum.
   The current policy is restart-safe and fails closed on sequence gaps. Branch
   schema v9 now records each superseded version's ordinary-history decision and
   exact policy sequence in the same transaction as its new version and namespace
   head. Reconciliation uses that same explicit decision and separately protects
   acknowledged concurrent alternatives. Bounded seek pagination selects
   preliminary candidates oldest first, excludes every current branch-file head,
   enforces minimum count/age, maximum-age, pressure and critical soft-minimum
   rules, and binds each result to both the selection policy and supersession
   policy sequences. Restart equality, disabled-history selection, conflict
   safety, pressure ordering, page bounds, corrupt lineage and transaction
   rollback are executable. No returned candidate authorises deletion. A durable
   bounded graph scanner now ingests the exact revision-bound retained-root set,
   adds node-local branch/handle/lifecycle roots, traverses immutable directory and
   object records across restart, and emits a terminal unreachable proof only if
   every root remains unchanged. Missing records, corrupt encodings, substituted
   roots and changed local heads fail closed. The cluster boundary preserves every
   proof field in a replicated cleanup proposal; the metadata transaction
   independently recomputes the current retained-root digest and count, validates
   the selected retention-policy sequence and terminal proof digest, then records
   one audited idempotent proposal. A proposal deliberately cannot issue removal
   permits. Each proposal now snapshots every admitted gateway and its exact
   incarnation. Nodes sign terminal local scan evidence with a separately
   rotating cleanup-attestation key; the metadata transaction verifies the key,
   signature, incarnation, terminal digest and operation-independent subject.
   Coverage is incomplete until every snapshotted gateway has attested, while
   its per-node scan request remains uniquely replay-safe. The graph proof also
   treats any reachable version sharing the candidate's immutable manifest as a
   live reference, preventing logical copies from authorising shared-shard
   deletion. Retention selection, scan evidence and replicated proposals also
   carry the immutable manifest root digest used by physical shard identities,
   preventing cleanup-item substitution across manifests. Storage providers
   also enforce a monotonically advancing applied-catalogue fence, so applying a
   newer revision permanently rejects an otherwise authentic older removal
   permit. Each node now atomically installs a durable manifest-root reference
   fence when it admits a reachability scan. File publication and reconciliation
   reject new references while the fence is active; a reachable result releases
   it atomically, while an unreachable proof remains loadable only with its exact
   active fence. Restart, parallel-scan exclusion, alternate manifest IDs sharing
   a fenced root, forged release state and subsequent permitted publication after
   a reachable result are executable. Scan evidence and replicated proposals now
   also carry a revision-independent digest of the exact ordered retained-root
   set. Tests prove that the digest survives unrelated global revision advances
   while the revision-bound digest does not. Whole-volume restore preparation is
   blocked while a volume has an active cleanup fence, closing the existing-root
   head-activation path without scanning every ordinary write. Replicated
   finalisation now has distinct `authorised` and `cancelled` terminal states.
   Authorisation revalidates the current policy, stable retained-root set,
   complete current gateway/incarnation membership, active key generations,
   terminal scan digests and every persisted Ed25519 signature in the same
   transaction as its audited terminal revision. Cancellation grants no deletion
   authority. Restart/replay, incomplete coverage, changed roots or policy,
   rotated keys, tampered persisted signatures and every injected transaction
   boundary are executable. The durable content catalogue now opens a
   borrow-scoped shard inventory only after independently revalidating the
   complete committed manifest once, then exposes exact provider receipts in
   bounded keyset pages without repeating that whole-layout scan. Missing receipt
   state and invalid bounds fail closed. Replicated inventories now accept only
   non-empty bounded contiguous pages of exact placements under the authorised
   manifest root. Every item has a globally reserved provider operation ID; an
   ordered rolling digest and immutable expected count must seal before bounded
   worker pagination becomes available. Tests cover gaps, changed totals, wrong
   roots, duplicate/reused operation authority, premature and post-seal
   mutations, restart/replay, missing or substituted rows, relational partial
   state and every injected transaction boundary. Replicated short-lived permit
   issue now derives only from an exact sealed inventory item, consumes its reserved
   operation identity on the first attempt, binds the resulting catalogue
   revision and persists the complete keyed capability before use. Same-epoch
   retries wait for expiry, epoch advances can fence immediately and later
   attempts reserve fresh operation identities. Restart/replay, stale seal,
   substituted mesh/item/revision, excessive lifetime, persisted corruption and
   every injected transaction boundary are executable. Provider tombstone
   receipts now cross into consensus only through exact committed-attempt and
   canonical-digest validation. Each completion binds the current reporting
   node incarnation, and the final item atomically creates an ordered terminal
   digest only after the sealed count is complete. Out-of-order arrival,
   restart/replay, duplicate completion, substituted receipts/attempts/seals,
   stale reporters, persisted corruption and every injected transaction
   boundary are executable. Every gateway can now load its independently
   signature-verified participant scan, join it with the exact authorised intent
   and terminal completion, and atomically install permanent local manifest-root
   retirement. Exact replay/restart, subject substitution, operation conflict,
   transaction interruption, persisted retirement corruption and deliberate
   damage to the older temporary fence are executable; publication and repeated
   cleanup scans remain blocked by the independent retirement record. Provider
   unlink now returns a distinct durable `ReclamationReceipt`, and exact replay
   returns its original time and byte count without double-accounting capacity.
   Replicated per-item reclamation accepts only the exact earlier tombstone,
   canonical digest, same authenticated node and current incarnation. Earlier
   items may be reclaimed before the terminal tombstone summary; the final
   reclamation transaction waits for every item, checks the byte sum and records
   an arrival-order-independent digest. Restart/replay, early and out-of-order
   results, forged/substituted receipts, stale reporters, persisted corruption
   and every injected transaction boundary are executable. Tombstone completion
   and permanent gateway retirement therefore never overclaim physical byte
   release. Replicated cancellation now produces exact per-gateway release
   authority for a local scan even when that gateway never completed attestation.
   One atomic branch transaction records the cancellation evidence and releases
   the temporary fence. Replay/restart, interruption, wrong subjects, operation
   conflict, stored corruption and both cancellation-after-retirement and
   retirement-after-cancellation are executable; permanent retirement cannot be
   weakened. A bounded cleanup-work catalogue now classifies sealed items as
   permit, tombstone, reclamation or complete work. Entries are independent and
   can run concurrently; each execution performs at most one provider transition
   before returning an exact command for consensus. A real registered-folder
   proof drops and reopens the provider after both a lost tombstone command and
   a lost reclamation command, recovering byte-identical commands without
   duplicate capacity accounting. Substituted dispatch authority fails before
   provider IO. Sealed inventory now binds every target generation to its exact
   owning storage node. The worker rejects another reporter before IO, the
   metadata state machine repeats the check against authenticated identity and
   migrated ownerless inventories fail closed. The asynchronous cleanup bridge
   resolves only that owner through a replaceable connection source, rejects a
   returned certificate peer other than the inventory owner before opening a
   stream, creates a bounded request deadline and returns the exact completion
   command. Non-provider work does not resolve a connection. Distinct bounded
   delete and reclaim messages carry canonical versioned authority, return exact durable receipts,
   preserve replayed time/byte accounting and reject forged removal permits.
   The server and multi-target router also require the authenticated peer and
   reject sender-node or incarnation impersonation in every request header. A
   real Quinn/mTLS test drives the worker through tombstone and reclamation
   against the real folder provider and verifies exact reporter identity and
   released-byte accounting; the full data-plane proof additionally drives put,
   get, forged sender/write/removal, tombstone replay and reclamation replay.
5. Authoritative handles, opens, share modes, locks, rename, delete-on-close and flush.
   Existing-file opens, cross-gateway share admission, leased/fenced handle
   takeover, byte-range locks and guarded delete-on-close readiness are durable
   and tested. Handle-bound random writes, their lock ordering and cross-database
   stage takeover are also durable and tested. Handle-bound flush publication is
   durable and tested through the real encrypted folder provider, including
   bounded base-version overlay and lost-response recovery after complete
   restart. Creation-capable dispositions now publish an empty first version and
   reserve the creator's handle in one final metadata transaction; exact restart
   replay, existing-path open-or-create, hostile plan rejection and rollback when
   handle admission fails are tested. Close now detects uncommitted private-stage
   work, publishes it before releasing authority, recovers a crash between flush
   and close, and leaves the handle live on incomplete content. Overwrite opens
   journal truncation as a replayable mutation, including empty close without a
   later write. Same-volume rename/move and final namespace unlink are atomic
   durable branch transactions. Both bind stable object/revision/generation
   evidence, update affected handle or pending-delete state in the same
   transaction, survive restart replay and roll back at every injected phase.
   The immutable directory trie now has a bounded exact-removal primitive with
   stale-revision rejection and historical-root preservation; persisted two-path
   rename intent now binds the source path and lineage, preserved entry
   generation, destination path and lineage, and the intermediate root between
   removal and insertion. Existing one-path intent digests remain byte-for-byte
   compatible across branch-schema migration v23. Deterministic replay now binds
   source removal and destination insertion in one digest-covered action, carries
   a concurrent content edit to the selected destination, recovers destination
   collisions, materialises a competing file rename as a distinct logical copy,
   rejects directory cycles, and produces the same plan for every delivery order.
   The reconciliation SQL applier performs the removal and insertion inside its
   existing all-or-nothing transaction, using the explicit intermediate root.
   The public branch-local rename and unlink transactions and their end-to-end
   durable replay proofs are complete.
6. Complete nested-group/owner/grant/time/activation permission evaluation.
   The authoritative evaluator, session fencing, revocation and principal
   lifecycle transitions are implemented and tested. Operation-time capability
   validation now fronts the implemented mutating handle and namespace service
   families plus bounded handle reads, immutable stat and directory enumeration
   through one metadata adapter. The complete 13-right vector is proven both
   independently and as one atomic requested set. Indexed bounded owner, active
   grant and nominal activation administration projections are implemented.
   Their operation-time-authorised filesystem composition remains part of gate
   7 so no connector can treat a repository read as access authority.
7. Adapter-facing filesystem contract and real two-gateway/restart/partition proofs.
   The semantic existing-file open/read/write/flush contract and two-gateway
   restart proof are complete. Creation, remaining namespace/handle operations,
   authorised administration views and the two-isolated-node service-level
   reconciliation proof remain open.

Stage 5 remains incomplete until every gate is checked and the complete local
suite passes together.
