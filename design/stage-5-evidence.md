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

## Closure gates

1. [x] Protocol-neutral canonical component/path types and compatibility bounds.
2. [x] Persistent immutable versions, staged random writes and atomic CoW volume heads.
3. Deterministic branch commits, disconnected reconciliation and recovered items.
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
   transaction boundary. The replicated converged-volume-head authority
   transition from this local receipt is still required before this gate closes.
4. Snapshots, retention and restore-as-new-head.
5. Authoritative handles, opens, share modes, locks, rename, delete-on-close and flush.
6. Complete nested-group/owner/grant/time/activation permission evaluation.
7. Adapter-facing filesystem contract and real two-gateway/restart/partition proofs.

Stage 5 remains incomplete until every gate is checked and the complete local
suite passes together.
