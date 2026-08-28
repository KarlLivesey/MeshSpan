# Stage 4 implementation evidence

Status: in progress, started 2026-08-28.

Stage 4 turns registered existing folders into private immutable-shard providers.
This document records executable evidence only; accepted design prose is not an
implementation claim.

## Delivered foundation

- Headless configuration distinguishes one `--daemon-state-dir` from repeatable
  `--storage-path` values, retains native operating-system paths and rejects
  missing, duplicate, malformed or excessive inputs.
- Each target has an explicit percentage or fixed-byte usage ceiling; the
  appliance default is 95% rather than unrestricted consumption.
- `meshspan-storage` opens an existing folder through a capability-scoped handle,
  creates only `.meshspan`, and never reads or changes sibling content.
- A fixed checksummed marker binds mesh, target, positive generation and random
  marker material. Its fingerprint identifies returning media independently of
  path spelling, mount name or discovery order.
- One held operating-system file lock enforces a single live local owner. Folder
  registration and return perform real write, durable flush, reopen,
  atomic-rename and directory-flush probes before admission.
- New registration requires an otherwise empty private directory. Return
  requires the exact authority-expected identity and fingerprint. Corrupt
  markers and unknown private records fail closed and are never erased.
- One WAL/FULL-sync SQLite journal is stored beneath the daemon state directory
  and bound to the exact marker fingerprint and target generation. Immutable
  migration bytes are fingerprinted, structural/foreign-key checks run at open,
  and an existing journal reopens without generating replacement capability
  material.
- Capacity policy changes require a strictly newer authoritative revision.
  Foreground, repair and relocation reservations are distinct, idempotent and
  atomically accounted; foreground work preserves repair headroom while exact
  replay remains resolvable after reservation expiry.
- Canonical fixed-width shard identities back bounded seek pagination for both
  committed inventory and incomplete recovery work. Preparing a put pins its
  reservation; accepting independently durable pack evidence atomically commits
  inventory, the exact receipt and capacity counters. Exact committed replays
  remain resolvable after restart.

## Closure gates

1. [x] Repeatable headless paths, explicit capacity ceilings and separation of
   daemon state from provider folders.
2. [x] Stable marker identity, exclusive ownership, sibling isolation and real
   filesystem capability probes.
3. [x] Durable target journal, bounded inventory, reservations, recovery checkpoint
   and target-incarnation fencing.
4. Immutable packed shard put/get with exact replay, bounded read authority,
   durable receipts and independent integrity verification.
5. Exact removal permits, durable tombstones, guarded unlink and scrub
   observations that never become deletion authority.
6. Reusable provider conformance plus real IO/process proofs for restart,
   `ENOSPC`, short/partial writes, lost flush results, corruption, path/media
   replacement, stale incarnation and three-process remote transfer.

Stage 4 remains incomplete until every gate is checked and the complete local
suite passes together.
