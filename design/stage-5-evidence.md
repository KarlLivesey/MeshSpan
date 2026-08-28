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
  independently rechecked. Cross-platform vectors cover deterministic output,
  wrong manifest/format/index, forged digest/tag, invalid keys and bounds. The
  deliberately simple single-chunk publisher remains test-only: gate 2 stays
  open until a production bounded/paged manifest publisher durably stores the
  wrapped content key and chunk receipts through the same boundary.

## Closure gates

1. [x] Protocol-neutral canonical component/path types and compatibility bounds.
2. Persistent immutable versions, staged random writes and atomic CoW volume heads.
3. Deterministic branch commits, disconnected reconciliation and recovered items.
4. Snapshots, retention and restore-as-new-head.
5. Authoritative handles, opens, share modes, locks, rename, delete-on-close and flush.
6. Complete nested-group/owner/grant/time/activation permission evaluation.
7. Adapter-facing filesystem contract and real two-gateway/restart/partition proofs.

Stage 5 remains incomplete until every gate is checked and the complete local
suite passes together.
