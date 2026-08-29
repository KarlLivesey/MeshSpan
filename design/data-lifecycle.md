# Data lifecycle and safety

Status: draft for review. Terms and identifiers come from
[`domain-model.md`](domain-model.md).

This document defines when an operation is durable, what may be retried, and
which authority may destroy bytes. An implementation is not allowed to infer
success from a connection closing or authorise deletion from a storage location
alone.

All data is suspect at all times. Durable does not mean trusted forever:
consumers revalidate the identity, integrity, generation, authority, freshness
and bounds required for their operation. Verification evidence is recorded and
useful, but cannot be applied to a different object, revision, operation or
trust boundary.

## 1. Common operation rules

Every mutating operation has:

- a client-generated `operation_id` used for idempotency;
- a committed identity/policy revision and causal namespace base;
- a durable outcome of `branch_committed`, `globally_converged`,
  `policy_committed`, `rejected` or `aborted`;
- an explicit `unknown` client-side outcome when the reply is lost; and
- an operation-status query that resolves `unknown` without repeating effects.

`accepted` and `in_progress` are not success. A user-visible save is complete
only after the immutable branch mutation and every predicate required at its
declared receipt scope are durable. Only `policy_committed` satisfies a strong
publication request.

## 2. Write state machine

```text
requested -> staging -> local_data_durable -> branch_committed
                 |               |                    |
                 +------------> aborted               +-> reconciling
                                                         -> globally_converged
                                                         -> policy_committed
```

1. The gateway authenticates the principal, resolves current permissions and
   opens a write transaction against an expected object revision.
2. The filesystem service resolves the acknowledgement policy. The owning
   namespace leader supplies the plan when reachable; otherwise the local branch
   planner uses the last valid topology/policy revision and only reachable
   eligible targets. The plan binds target IDs, shard IDs, generations,
   checksums, expiries and capability-bound write grants.
3. The gateway encodes and streams shards directly to the selected storage
   nodes. A target writes to a private temporary name, flushes bytes and required
   directory metadata, atomically installs the shard, then returns a signed or
   mutually authenticated durability receipt.
4. The gateway verifies identity, generation, checksums and the policy predicates
   proved by those receipts.
5. Once its local acknowledgement threshold is met, one local ACID transaction
   publishes the immutable manifest/CoW roots, advances the local branch head,
   records quota/evidence/debt and marks `branch_committed`.
6. For an eventual write, that scoped receipt may be reported as saved. Peers
   later reconcile the branch and strengthen its scope automatically.
7. For a strong write, required-zone/protection work continues until every
   blocking predicate has evidence. The owning partition then performs one ACID
   metadata transaction that includes the branch, advances the converged head
   and marks `policy_committed`.
8. A lost reply produces `unknown`; the caller queries by `operation_id` and
   receives the exact durable stage and receipt.

Retries with the same operation ID and content identity return the existing
result. Reuse with different inputs is rejected. Expired staging operations are
aborted durably before unreferenced shards become eligible for reclamation.

`fsync`/SMB flush success means the corresponding MeshSpan write met its
configured acknowledgement policy, not merely that a gateway buffered bytes.
An adapter never silently weakens strong to eventual.

## 3. Read state machine

1. The gateway authenticates and authorises the read at a committed metadata
   revision.
2. The owning partition leader or a sufficiently current read authority returns an immutable
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

Deletion exposes three honest scopes: `branch_deleted` means the complete
mutation is durable and hidden on the named local/cell branch;
`globally_deleted` means every owning metadata partition committed the logical
transaction; `bytes_reclaimed` means guarded asynchronous cleanup removed all
known obsolete shards. An offline storage node does not block logical deletion
unless the acknowledgement policy explicitly requires it; it applies committed
tombstones and cleanup when it returns.

1. An authorised namespace transaction removes a directory entry or creates a
   tombstoned version. Snapshots, open handles, retention rules and other links
   may keep the manifest reachable.
2. A quorum-owned reachability scan identifies a manifest with no live
   references. Its operation-independent subject digest binds the candidate,
   retention selection and complete metadata-root authority; each node-local
   scan has a separate request/result digest. The replicated proposal snapshots
   every admitted gateway node and its exact incarnation.
3. Every snapshotted gateway signs a terminal unreachable result for the same
   subject after atomically installing a durable node-local reference fence and
   revalidating its own branch and lifecycle roots. While the proof remains
   usable, publication and reconciliation on that node reject any new reference
   to the logical manifest or its immutable root. A reachable result releases
   the fence in the same transaction as the terminal result; an unreachable
   result retains it until replicated completion or cancellation authority is
   applied. The proof binds both its enumeration revision and a canonical
   revision-independent root-set digest. Later attestation commands may advance
   the partition revision, but final authority still rejects any actual retained-
   root change. Whole-volume restore preparation is rejected while any cleanup
   reference fence for that volume remains active. Reachability
   follows both the selected version and any other retained version sharing its
   immutable manifest, so logical copies cannot lose shared shards. The subject
   and proposal bind both the logical manifest ID and its immutable root digest;
   cleanup items therefore cannot substitute another manifest's shard identity. An offline
   gateway delays physical reclamation, not logical deletion. A changed node
   incarnation or cleanup signing-key generation fails closed.
4. The metadata authority moves a pending proposal to `authorised` only after
   revalidating the current retention policy, the complete revision-independent
   retained-root set, every current gateway incarnation, every active cleanup
   key generation, and every stored signature. Any mismatch leaves the proposal
   pending without deletion authority. Cancellation is a separate terminal
   transition that can never authorise deletion.
   The owning content catalogue validates the complete committed manifest once,
   then enumerates its exact durable shard placements through bounded keyset
   pages while held under an immutable borrow. Enumeration never allocates or
   rescans the complete placement set for each page. Replicated inventory
   admission accepts only non-empty bounded contiguous pages under the proved
   manifest root. It reserves a distinct provider operation identity for every
   item and chains an ordered digest. No item is permit-eligible until the exact
   declared count and final digest are sealed atomically. Authorisation is the
   point of no return: later policy changes cannot revive the unreachable
   manifest after physical work may have begun.
5. Immediately before deletion, the worker obtains a short-lived
   `RemovalPermit` from the current owning metadata-partition leader. The permit binds:
   `mesh_id`, target, shard identity and generation, target generation, catalogue
   revision, operation ID, authority epoch and expiry. The exact attempt is
   replicated before use. Its lifetime is positive and has a compiled 24-hour
   ceiling, while policy may choose a shorter duration. The first attempt uses
   the inventory item's reserved provider operation ID. A retry in the same
   authority epoch waits for the previous attempt to expire; a higher epoch may
   fence it immediately. A lost response is resolved from the committed attempt
   instead of manufacturing different authority.
6. The storage node validates the permit, current leader epoch, a catalogue
   revision no older than the node's monotonically applied cleanup fence, and
   the local shard identity. Applying a newer catalogue revision permanently
   rejects older permits. It writes a local tombstone durably before unlinking
   bytes.
7. The node reports a typed result. The quorum records completion idempotently;
   a missing shard is success only when its identity and prior cleanup intent
   match. A durable tombstone receipt is accepted only when every field and its
   canonical digest match one committed permit attempt and the reporting node's
   current incarnation. Each item has one immutable completion. When—and only
   when—the completed count equals the exact sealed inventory count, the final
   item transaction also records an ordered completion digest. New permits for
   completed items are permanently rejected.

A path, target ID, shard ID or peer identity by itself can never authorise
deletion. Expired permits and stale epochs fail closed.

### Cross-partition atomic bulk mutation

A bulk manifest is assembled durably from bounded chunks, sealed by digest and
validated completely. Every owning partition prepares its exact changes and
preconditions without making them visible. The coordinator then commits one
replicated `commit` or `abort` decision. No participant publishes before that
decision; every participant recovers and finishes a committed decision after
crash or partition.

Preparation fences every affected record. An in-doubt participant blocks or
returns a typed pending/unavailable result for reads and conflicting mutations
of those records until it learns the decision; it cannot return its old value
after another participant may have exposed the committed transaction. This is
the availability cost of requested cross-partition atomicity and does not block
unrelated records.

If a required participant remains unreachable before the decision, the
coordinator keeps the operation pending to its declared deadline and, if it
retains authority, records an authoritative abort. Otherwise the transaction
remains in doubt until its decision can be recovered. A participant never
infers abort from its local timeout because a commit decision may already exist.
Unrelated records and partitions remain writable. Availability-first policy may
have already produced an explicitly scoped `branch_deleted` result, but it
cannot be reported as globally deleted.

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

Repeated loss and return do not create a new lifecycle or require an
administrator. Presence changes are debounced for user noise and repair cost,
but authority and IO failures take effect immediately. Grace periods may defer
expensive replacement while adequate protection remains; they never make an
unreachable shard count as available or delay urgent repair below policy.

## 9. Physical target and link churn

- Every provider operation tolerates the backing folder disappearing before
  open, during a stream, before persistence or after an indeterminate completion.
- Failure is isolated to that target and operation. Other targets and public
  services continue when their dependencies remain available.
- A returning folder is reopened from its durable marker, target ID and
  generation. Device names, mount points and enumeration order are observations
  only.
- A different device appearing at an old path is quarantined as an identity
  mismatch and is never initialised, adopted or erased automatically.
- Link flapping retires affected connections and streams without changing node
  identity. Quinn peers reconnect with a new connection but the same validated
  node/incarnation rules.
- In-flight mutations resolve through operation status and durable provider
  journals after reconnection; they are not guessed from socket failure.
- Repeated events are coalesced into bounded health/repair work so one loose
  cable cannot create unbounded tasks, logs, notifications or data movement.
- Once peers return, branch reconciliation and service strengthening are
  automatic. Converged/control work uses quorum; local branch work does not wait
  for it.

## 10. Resource and IO failures

- Reservations account for free space, safety margin and in-flight writes.
- `ENOSPC`, quota exhaustion and read-only filesystems are typed target failures;
  placement moves elsewhere when policy permits.
- Short writes, interrupted writes and checksum mismatches never produce a
  durability receipt.
- Temporary files are distinguishable from installed shards and are reclaimed
  only after the related operation is durably terminal.
- Directory removal, target replacement and path reuse require a new target
  incarnation so stale receipts cannot validate new storage.

## 11. Required proofs

Tests must demonstrate lost replies, duplicate requests, gateway crashes at
every numbered write/delete/branch/strong-barrier transition, partial writes,
corrupt bytes, full targets, stale repair workers, returning old nodes and
concurrent unlink/write.
For each case the expected namespace revision, operation outcome, authoritative
shard set and reclaimable bytes must be asserted explicitly.

The physical gate repeats random cable, host and device removals during every
slow lifecycle, including configuration rollout and certificate rotation. It
must prove continued eventual service wherever a local durable commit is
physically possible, honest pending strong barriers and automatic convergence,
protection and locality repair after return.
