# Data lifecycle and safety

Status: draft for review. Terms and identifiers come from
[`domain-model.md`](domain-model.md).

This document defines when an operation is durable, what may be retried, and
which authority may destroy bytes. An implementation is not allowed to infer
success from a connection closing or authorise deletion from a storage location
alone.

## 1. Common operation rules

Every mutating operation has:

- a client-generated `operation_id` used for idempotency;
- an authoritative metadata revision;
- a durable terminal outcome of `committed`, `rejected` or `aborted`;
- an explicit `unknown` client-side outcome when the reply is lost; and
- an operation-status query that resolves `unknown` without repeating effects.

`accepted` and `in_progress` are not success. A user-visible save is complete
only after the namespace mutation and its data durability requirements are
committed by the metadata quorum.

## 2. Write state machine

```text
requested -> staging -> data_durable -> publishing -> committed
                 |             |              |
                 +----------> aborted <-------+
```

1. The gateway authenticates the principal, resolves current permissions and
   opens a write transaction against an expected object revision.
2. The metadata leader creates a durable `staging` operation and returns a
   placement plan containing target IDs, shard IDs, generation, checksums,
   expiries and capability-bound write grants.
3. The gateway encodes and streams shards directly to the selected storage
   nodes. A target writes to a private temporary name, flushes bytes and required
   directory metadata, atomically installs the shard, then returns a signed or
   mutually authenticated durability receipt.
4. The gateway submits receipts. The leader verifies identity, generation,
   checksums, placement constraints and the requested failure budget.
5. Once sufficient valid receipts exist, the operation becomes `data_durable`.
6. One metadata transaction publishes the immutable manifest, updates the
   directory entry/version pointer, records quota usage and marks the operation
   `committed`.
7. Only that committed result may be reported as saved. A lost reply produces
   `unknown`; the caller queries by `operation_id`.

Retries with the same operation ID and content identity return the existing
result. Reuse with different inputs is rejected. Expired staging operations are
aborted durably before unreferenced shards become eligible for reclamation.

`fsync`/SMB flush success means the corresponding MeshSpan write is committed,
not merely buffered by a gateway.

## 3. Read state machine

1. The gateway authenticates and authorises the read at a committed metadata
   revision.
2. The leader or a sufficiently current read authority returns an immutable
   manifest and short-lived, object-bound read capabilities.
3. The gateway requests shards in parallel, verifies each length and checksum,
   and reconstructs once the coding threshold is met.
4. A corrupt, missing, stale or misdirected shard is never returned as valid
   data. The observation is recorded and deduplicated into the repair queue.
5. Failure is explicit when fewer than the required number of valid shards can
   be obtained before the deadline.

Read repair may improve a later read, but a read must not silently substitute an
uncommitted version or manufacture success.

## 4. Namespace deletion and byte reclamation

Deleting a name and destroying shards are separate operations.

1. An authorised namespace transaction removes a directory entry or creates a
   tombstoned version. Snapshots, open handles, retention rules and other links
   may keep the manifest reachable.
2. A quorum-owned reachability scan identifies a manifest with no live
   references. It creates a durable cleanup intent for a specific object,
   version, shard generation and expected catalogue revision.
3. Immediately before deletion, the worker obtains a short-lived
   `RemovalPermit` from the current metadata leader. The permit binds:
   `mesh_id`, target, object, version, shard, generation, catalogue revision,
   operation ID and expiry.
4. The storage node validates the permit, current leader epoch and local shard
   identity. It writes a local tombstone durably before unlinking bytes.
5. The node reports a typed result. The quorum records completion idempotently;
   a missing shard is success only when its identity and prior cleanup intent
   match.

A path, target ID, shard ID or peer identity by itself can never authorise
deletion. Expired permits and stale epochs fail closed.

## 5. Repair state machine

```text
queued -> claimed -> reconstructing -> replacement_durable
       -> catalogue_committed -> old_copy_cleanup -> complete
```

- Findings from reads, scrubs, membership changes and drains create deduplicated
  repair work.
- A worker claim is leased and fenced by term/epoch. Expiry permits another
  worker to continue safely.
- Reconstruction reads enough independently verified shards and checks the
  resulting content identity.
- Replacement shards use the normal staged-write and durability-receipt rules.
- A compare-and-swap catalogue transaction installs the replacement only if the
  source manifest and generation remain authoritative.
- Superseded shards use the normal cleanup-intent and removal-permit path.
- A late worker may upload redundant bytes, but cannot replace a newer catalogue
  entry or delete a current shard.

Repair priority considers data-at-risk level, remaining fault domains, access
heat, drain deadlines and available bandwidth. It is rate-limited so foreground
IO remains usable.

## 6. Scrubbing and bit rot

Each target maintains a durable scrub cursor. Scrubbing reads complete shard
contents, validates framing, length, checksum and authenticated identity, and
reports one of:

- `healthy`;
- `missing`;
- `corrupt`;
- `unreadable`;
- `unexpected` (present locally but absent from the current inventory view); or
- `deferred` with a typed local-resource reason.

Scrub reports are observations, never authority to delete. Suspicious bytes are
quarantined where practical until the quorum has decided repair or cleanup.

## 7. Target drain

1. An administrator requests drain of a target, node or fault group.
2. The quorum marks it `draining`; new placement excludes it.
3. A durable plan enumerates affected authoritative shards.
4. Normal repair creates and commits safe replacements.
5. The target becomes `safe_to_detach` only after a fresh catalogue check proves
   every affected object still meets the requested failure policy without it.
6. Physical cleanup, if requested, uses removal permits.

Loss during drain pauses work and resumes idempotently. A UI indication is never
proof that a folder is safe to remove; only the committed state is.

## 8. Node loss, return and stale state

- Absence first marks a node `suspect`, then `unavailable`; it does not erase its
  inventory immediately.
- Repair begins according to the volume policy and failure budget, not a single
  fixed timeout.
- A returning node presents its stable node identity and a fresh incarnation.
- Its inventory is reconciled against authoritative manifests. Current shards
  may be reused after verification; stale or unexpected shards cannot become
  authoritative merely by reappearing.
- A node restored from an old state directory must catch up consensus and local
  fencing state before it may serve mutations.

## 9. Resource and IO failures

- Reservations account for free space, safety margin and in-flight writes.
- `ENOSPC`, quota exhaustion and read-only filesystems are typed target failures;
  placement moves elsewhere when policy permits.
- Short writes, interrupted writes and checksum mismatches never produce a
  durability receipt.
- Temporary files are distinguishable from installed shards and are reclaimed
  only after the related operation is durably terminal.
- Directory removal, target replacement and path reuse require a new target
  incarnation so stale receipts cannot validate new storage.

## 10. Required proofs

Tests must demonstrate lost replies, duplicate requests, gateway crashes at
every numbered write/delete transition, partial writes, corrupt bytes, full
targets, stale repair workers, returning old nodes and concurrent unlink/write.
For each case the expected namespace revision, operation outcome, authoritative
shard set and reclaimable bytes must be asserted explicitly.
