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
  This advances gate 2 but does not close it: immutable published versions and
  atomic volume-head publication remain to be implemented.

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
