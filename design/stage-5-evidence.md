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
  This supplies the durable private-input half of gate 2; publication is a
  separate receipt-bound transition into the branch database described next.
- The separate branch database now persists complete verified manifest roots,
  immutable file versions and a branch-local current-version pointer in one
  `IMMEDIATE` ACID transaction. The request digest binds every identity, causal
  parent, manifest field, author and timestamp; an immutable result receipt
  retains the exact head sequence even after later versions advance. Tests prove
  exact retry after restart, stale-base and identity-conflict rejection,
  fail-closed receipt corruption, and rollback/retry after interruption at every
  manifest/version/head/receipt boundary. This closes the per-file atomicity
  part of gate 2; a verified persistent directory graph and atomic volume branch
  head are still required before the gate can close.
- The directory-block semantic kernel is a content-addressed 16-way radix trie
  over the complete BLAKE3 canonical-name key. Every immutable node has bounded
  fanout, hostile true-hash collisions have a bounded sorted bucket, and one
  entry mutation path-copies at most 65 nodes regardless of directory size.
  Lookups revalidate every selected node; complete graph validation rejects
  digest mismatch, wrong-depth edges, cycles/shared-edge aliases, malformed
  ordering and keys placed under the wrong radix path. Historical roots retain
  unchanged subtrees. A 512-entry executable vector proves constant mutation
  work, while stale revision and stable-object replacement attempts fail without
  moving the root. Durable node persistence and volume-head integration remain
  the next gate-2 transition.

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
