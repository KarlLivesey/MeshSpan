# Stage 4 implementation evidence

Status: core provider/federation evidence passed on 2026-08-30; DAT-021 pack
bounds, rollover and CoW compaction reopened on 2026-09-07. See
[Stage 10 task 17](stage-tasks.md) for the remaining implementation and estimate.

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
- Provider bytes live in identity-bound SQLite pack segments beneath the private
  target directory rather than one operating-system file per shard. Exact puts
  are immutable, bounded and independently BLAKE3-verified after the WAL/FULL-sync
  pack transaction commits.
- The composed folder store publishes inventory only after both durability
  domains agree. A real restart test stops between pack commit and journal
  commit, then proves bounded recovery publishes the existing bytes exactly
  once without uploading them again.
- Read permits use one canonical domain-separated keyed BLAKE3 MAC shared by
  issuer and verifier code. Reads bind the operation, authority revision,
  deadline, mesh, target incarnation and exact shard; forged, expired or
  mismatched authority fails before independently length/digest-verified bytes
  leave the provider.
- Removal accepts only a current-epoch, exact-target keyed permit. It records a
  journal intent, durably tombstones the pack before removing inventory, and
  refuses physical unlink until the journal confirms the exact receipt. Restart
  proof stops between pack and journal commits, recovers once, rejects forged
  permits/receipts and releases capacity exactly once only after unlink.
- Bounded scrub rereads complete bytes and recomputes BLAKE3 instead of trusting
  either catalogue or an earlier checksum. Healthy evidence is compare-and-set
  onto unchanged inventory; corrupt, missing and unreadable findings remain
  typed observations with no deletion path. A WAL/FULL-sync per-target cursor
  advances only after a complete bounded page and resumes across restart.
- Capacity admission now obtains `statvfs` from the already-open folder
  capability; no caller-supplied free-space claim or replacement path can grant
  authority. The real folder store implements the replaceable provider contract
  directly, and fresh-folder conformance vectors cover reserve, put, authorised
  read, forged read, scrub, tombstone, guarded unlink and bounded inventory.
- Deterministic provider failpoints exercise three different ambiguous-write
  boundaries through the real pack and journal composition. Pre-write capacity
  exhaustion changes nothing; a short write rolls its pack transaction back;
  and a pack commit whose result is lost remains absent from public inventory
  until restart recovery verifies and publishes it exactly once.
- `meshspan-data-plane` converts opaque wire capabilities into canonical,
  fixed-width, operation/mesh/target/incarnation/shard/revision/expiry-bound
  records. A separately keyed write permit authorises reservation and bytes;
  location and mTLS identity alone never grant storage authority. Typed remote
  failures cannot be confused with durable receipts.
- One bounded target router serves several independent provider instances
  without weakening their target-generation fences. The real process proof
  starts three mTLS-authenticated Quinn storage processes, registers two folders
  with different capacity ceilings on each, transfers multi-frame shards to and
  from all six targets, rejects a forged write permit and proves ordinary sibling
  files remain unchanged.
- The authenticated Quinn adapter now also carries distinct tombstone and
  physical-reclamation operations. Its real folder-provider proof rejects a
  forged removal permit and proves exact tombstone and reclamation replay across
  different observed times without double-accounting released capacity.
- Provider-local quota slices are derived only from current replicated
  relationship, bilateral grant, allocation, node, target-incarnation and time
  authority. The node-local WAL/FULL-sync ledger reserves before IO, records the
  exact signed capability presentation, survives restart and resolves a lost
  response without spending capacity twice.
- Partner shard identities are derived from the remote mesh and opaque scope as
  well as the logical shard. Two tenants or scopes cannot collide in one target,
  and namespace names, users and volume keys never cross the storage boundary.
- Real Quinn/mTLS proofs execute encrypted put, verified read, repair, full-byte
  scrub, logical retirement and physical reclamation. Every operation receives a
  separately signed replay-safe receipt, and every exact retry returns its
  original durable result rather than performing the transition twice.
- A signed bounded inventory protocol pages only the authenticated tenant's
  active logical catalogue. Before publication, each record is revalidated
  against current replicated allocation authority and an exact provider-catalogue
  lookup. Malformed cursors, mixed tenants and catalogue disagreement fail
  closed.
- The real partner-provider proof enforces the effective 50-byte bilateral
  ceiling by rejecting a 51-byte request without a quota hold. A protection-only
  allocation accepts and durably stores an encrypted shard but cannot issue an
  ordinary-read capability; a read-serving allocation completes the full read
  cycle.
- The provider target is closed and reopened from its original marker, journal
  and packed bytes before inventory resumes. Relationship revocation then fences
  sessions and remote inventory immediately while the protection-only shard
  remains present and mutually consistent in both local catalogues. Removal does
  not claim those retained bytes erased.

## Closure gates

1. [x] Repeatable headless paths, explicit capacity ceilings and separation of
       daemon state from provider folders.
2. [x] Stable marker identity, exclusive ownership, sibling isolation and real
       filesystem capability probes.
3. [x] Durable target journal, bounded inventory, reservations, recovery checkpoint
       and target-incarnation fencing.
4. [x] Immutable packed shard put/get with exact replay, bounded read authority,
       durable receipts and independent integrity verification.
5. [x] Exact removal permits, durable tombstones, guarded unlink and scrub
       observations that never become deletion authority.
6. [x] Reusable provider conformance plus real IO/process proofs for restart,
       `ENOSPC`, short/partial writes, lost flush results, corruption, path/media
       replacement, stale incarnation and three-process remote transfer.
7. [x] Capability-scoped partner capacity with bilateral limits, distinct
       protection/read classifications, all six signed shard lifecycle operations,
       bounded exact inventory, target return and revocation-with-retention proof.

The listed 2026-08-30 gates were checked. The complete local suite, including the six-target
three-process proof and the real bilateral federation session, passes together;
the four-worker run completed in 126.28 seconds on 2026-08-30.

## Reopened pack lifecycle requirement

The provider originally selected `ACTIVE_PACK_SEQUENCE = 1` and opened one `PackStore`.
It provided immutable shard identity, exact replay, independent verification,
durable tombstones and guarded BLOB unlink. Those proofs do not establish the
explicit pack bounds and CoW compaction required by DAT-021. SQLite free-list
reuse is not a compaction cutover or a host-space reclamation receipt.

Rollover and indexed multi-pack routing are now implemented as described below.
Copy-on-write replacement is implemented below, retaining the same logical pack
sequence and record numbers under an exclusive reader/mutation fence.
Finish acceptance for reads during compaction, interruption
and restart at cutover, bounds and isolated pack corruption. The new pack-space
metrics report only current database extent and reusable pages; they do not
close these gates or authorise deletion.

## Journal-owned pack rollover

Target-journal migration 3 assigns an exact shard identity, length and digest to
one pack in the same transaction that prepares its put. New assignments roll to
another pack at **256 MiB of assigned payload or 4,096 shard records**. Retries
retain the original route and do not consume another assignment. Payload bounds
are not a claim about total SQLite/WAL/operation-log bytes. Existing v1/v2
inventory and incomplete puts migrate without relocating bytes; an oversized
legacy pack receives no further new assignments.

Put/recovery, authenticated reads, scrub, tombstone/recovery and unlink use that
indexed route. Reads of an older pack open it read-only and never search other
packs or create a missing database. The updater's exact compatibility report now
includes the storage-journal version, so an older report cannot silently stage
over this changed persistence format.

The new provider regression first failed with the previous single-pack path,
then passed: two 19-byte shards exceed its 30-byte fixture limit, one put loses
its result before journal commit, and restart recovers it from pack 1 after
pack 2 exists. Scrub verifies both, an authenticated read returns the original
bytes and guarded deletion removes only the older shard (quota 38 → 19).
Separate fixtures exercise record-count rollover, transactional preparation
failure and v2 migration with both committed and incomplete records.

The full local storage library suite passed **35 tests in 2.16 s** after a
**5.73 s** incremental build; affected storage Clippy passed in **35.21 s**.
The run also exposed a test comparing live host free-space samples for equality;
it now retains exact quota/identity/total checks and validates each independently
changing available-space observation. No test serialisation or retry workaround
was introduced. Daemon compatibility checks and compaction work follow.

## Automatically retried copy-on-write compaction

The existing daemon target-maintenance pass considers one pack per target every
30 seconds, skipping a target already locked for foreground IO. At least 1 MiB
and one-quarter of the database extent must be reusable before it copies the pack.
The work source is durable free-page evidence, so restart requires no administrator
or reconstruction of a lost in-memory queue. Failure contributes to the storage
cycle's failed-step observations without removing a healthy target from service.

Compaction uses the existing bundled SQLite backup facility to create a separate
private copy, vacuums only that copy, checks identity/schema structure and verifies
all remaining active/tombstoned shard bytes. It closes the copy, checkpoints and
closes the old connection, persists WAL-sidecar removal, then atomically renames
and directory-syncs the replacement. Logical pack sequences, record numbers,
tombstones and operation receipts remain unchanged. All provider reads finish
under the same exclusive target lock before physical replacement; this is not a
claim that foreground readers run concurrently with the copy.

An interrupted pre-publication copy leaves the original authoritative; its fixed
provider-private scratch files are rebuilt on retry. Failure after replacement
reopens whichever complete database is authoritative. No live pack is vacuumed
in place, no shard location grants deletion authority, and no unlinked receipt
claims that the filesystem/device has released an exact number of bytes.

The complete storage library suite passed **36 tests in 1.71 s** after a
**7.36 s** build. The new real-file test deletes a 2 MiB shard, preserves a
4,096-byte shard, injects failures before and after replacement with reopen after
each, verifies exact receipt replay and retained bytes, and observes at least
1 MiB less database extent with zero reusable pages. Quota remains exactly
4,096 bytes. These are controlled local interruption/reopen tests, not abrupt
host-power-loss or real-daemon maintenance acceptance.

Remaining work is explicit: operation-log growth bounds; oversized legacy packs
(copies above 512 MiB are currently refused); complete metrics beyond the
32-pack observation budget; reader contention, storage-exhaustion and actual
daemon-maintenance acceptance; and measured copy/amplification cost. Compatible
content deduplication remains the separately reopened Stage 5 requirement.
