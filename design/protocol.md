# Private node protocol

Status: draft for review. This is the logical protocol contract; it deliberately
does not expose the database layout.

## 1. Transport and encoding

- Every message is hostile input, including one carried over authenticated mTLS
  by an enrolled node or voter. Authentication establishes sender identity only;
  it does not establish authority, freshness, correctness or safe structure.
- Before allocation or state access, decode with canonical framing and hard
  size/count/depth limits. Then validate mesh and sender binding, protocol
  version, partition/routing scope, incarnation, epoch/revision, deadline,
  capability, authorisation, replay identity and message-specific semantics.
- A receiver independently verifies claims and payload integrity needed for the
  operation. It never trusts a sender's assertion that bytes were validated,
  stored, committed, authorised or current.
- Private node traffic uses QUIC implemented with Quinn.
- Every established peer connection uses mutual TLS and binds the certificate to
  one mesh ID and node ID.
- Cross-swarm federation uses a separate mutually authenticated connection and
  envelope which binds both autonomous swarm identities and one approved
  relationship. A same-swarm node certificate or request header cannot be
  reinterpreted as federation authority.
- Protobuf is the canonical control-message encoding. Bulk shard bytes use
  framed QUIC streams rather than embedding large payloads in Protobuf.
- Consensus, control and data use independent streams with bounded queues so a
  shard transfer cannot block heartbeats or votes. Separate connections remain
  an implementation option if measured isolation is insufficient.
- A node normally exposes one private UDP endpoint. Public HTTPS and SMB are
  separate access services.

## 2. Common request context

Every request carries, directly or through connection context:

| Field | Purpose |
| --- | --- |
| `protocol_major`, `protocol_minor` | Compatibility negotiation |
| `mesh_id` | Prevent cross-mesh requests |
| `partition_id` | Selects the one metadata/consensus authority for the operation |
| `routing_epoch` | Detects stale scope-to-partition routing |
| `sender_node_id` | Must match the mTLS identity |
| `sender_incarnation` | Fences a restarted or replaced process |
| `request_id` | Correlates one exchange |
| `operation_id` | Deduplicates one logical mutation |
| `deadline` | Rejects work that can no longer help the caller |
| `trace_id` | Correlation without carrying credentials |

Credentials, raw private keys, password material and database queries are never
placed in this envelope.

Federation traffic uses a separate `FederationHeader` containing relationship,
sender-swarm and recipient-swarm IDs, request and operation IDs, authority epoch,
deadline, trace ID and a 32-byte replay nonce. Both swarm IDs must differ. The
authenticated certificate, signed message and header identity must agree before
any state or expensive operation is consulted.

## 3. Outcomes and errors

Every completed request has one of:

- `branch_committed`: the named filesystem mutation is durable at the returned
  `node_local` or `cell_replicated` scope;
- `policy_committed`: every configured acknowledgement predicate is proved and
  the converged head includes the mutation;
- `globally_converged`: a prior branch operation is now included in the
  converged head but may still carry declared eventual placement debt;
- `rejected`: no matching mutation committed;
- `in_progress`: query again by operation ID;
- `redirect`: contact the identified leader/authority and term;
- `stale`: caller revision, epoch, capability or incarnation is obsolete; or
- `failed`: typed failure with retry class and safe diagnostic detail.

Transport loss has no implied outcome. Mutating callers use `OperationStatus`
before deciding whether to retry. Error codes are stable protocol values;
human-readable text is not parsed.

Malformed or unauthorised traffic produces only bounded, non-secret diagnostic
detail. Validation failure cannot partially mutate state, allocate from an
unbounded claim, panic the process or become a protocol oracle for credentials,
keys, paths, topology or record existence.

## 4. Connection messages

| Message | Essential fields | Result |
| --- | --- | --- |
| `NodeHello` | versions, mesh/node/incarnation, roles, component implementations, feature bits, limits | Authenticates and negotiates |
| `NodeWelcome` | selected version, peer identity, partition route/leader hints, limits | Opens normal streams |
| `Ping` / `Pong` | nonce, monotonic timings | Liveness and latency sample |
| `GoAway` | reason, retry hint | Graceful connection retirement |
| `ProtocolError` | stable code, offending request | Closes invalid traffic safely |

Certificate identity and `NodeHello` must agree exactly. Limits are the lower of
both peers' advertised safe bounds.

## 5. Consensus messages

The consensus library owns its algorithm-specific payloads. Each consensus
stream is bound to one partition ID; terms and log indices are meaningful only
inside that partition. The wire contract has only these families:

- `VoteRequest` / `VoteResponse`;
- `AppendRequest` / `AppendResponse`; and
- `SnapshotBegin`, `SnapshotChunk`, `SnapshotFinish` / `SnapshotResult`.

Terms, log positions, membership configuration and snapshot checksums are
explicit. Snapshot chunks are bounded and resumable. No application request may
bypass consensus by writing a peer database directly.

Replicated log commands have their own positive version. Membership command
version `2` uses the canonical `MSMC` record and only permits three shapes:

- admit exactly one authoritative identity as a non-voting learner, carrying
  its exact positive incarnation;
- promote exactly one existing learner, carrying its exact incarnation,
  committed log position and entry digest; or
- finalise the exact stable successor already proved by the active joint plan.

The record embeds source quorum-plan specifications, never trusted cached proof
output. Every receiver independently recompiles the plan, rejects trailing or
excessive bytes, checks the one-member set difference and verifies evidence
against its own committed history before changing the active membership.

## 5a. Federation messages

Federation never uses the node-control envelope and never joins consensus across
swarms. Its bounded Protobuf catalogue is:

- `FederationHello` / `FederationWelcome` for version/limit negotiation,
  recovery-root-chained identity generations and a signed two-nonce challenge;
- `FetchFederationAuthority` / `FederationAuthorityPage` for revisioned,
  cursor-paged relationship, governance, grant, revocation and recovery records;
- `FetchFederatedBranchPage` names exact namespace head IDs and already-held
  commit IDs; `FederatedBranchPage` returns bounded missing causal commits and
  referenced immutable-object digests;
- `ProposeFederatedBranch` / `FederatedBranchResult` for signed grant-use
  evidence and an outcome which separately represents accepting-swarm
  durability, owner-history acceptance, protection satisfaction or quarantine;
- `RequestFederatedStorageCapability` / `FederatedStorageCapability` for an
  exact grant, target generation, shard, action, byte ceiling, expiry and nonce;
- `FederatedStorageReceipt` for the exact capability/result digests, affected
  bytes, completion instant and provider signature; and
- `FetchFederatedStorageInventory` / `FederatedStorageInventoryPage` for bounded
  reconciliation of remotely retained encrypted shards.

Actual shard bytes continue to use the existing independently bounded data
frames. `PutShard`, `GetShard`, scrub, repair, retirement and reclamation accept
the exact federated capability; the federation envelope does not grow a second
bulk-data protocol. Signatures are verified over canonical, domain-separated
bytes in addition to structural Protobuf validation and mTLS identity binding.

## 6. Metadata commands and queries

`MetadataCommand` contains a closed, versioned `oneof`; it is not raw SQL, a KV
operation or an arbitrary serialized function. Initial command families are:

- mesh settings and feature activation;
- component instance, desired configuration, assignment, activation and
  retirement changes;
- join grants, node admission, role and voter-set transitions;
- host, node, target, fault-group and membership changes;
- availability-cell, metadata-partition route and fenced scope-handoff changes;
- volume, failure-policy, locality-policy and placement-policy changes;
- principal, group membership, owner, grant, authentication-method and session
  changes;
- namespace commit, object-version, snapshot, manifest and open-handle changes;
- write staging, durability receipt and publish/abort changes;
- repair, drain, scrub and cleanup state changes;
- certificate configuration, encrypted secret envelopes and rotation state; and
- audit/security event append and retention changes.

Each command includes its expected revision or precondition and returns the
committed revision plus a typed result.

`MetadataQuery` contains typed query variants for the corresponding read models,
including `OperationStatus`. Queries declare their required consistency:

- `linearizable` for authorisation, destructive permits and write decisions;
- `bounded_stale` for explicitly tolerant status views; or
- `snapshot_revision` for a repeatable multi-page result.

`MetadataWatch` starts after a committed revision and emits ordered,
domain-specific changes. A compacted cursor returns `snapshot_required` rather
than silently skipping history.

Component queries return desired configuration separately from per-node support
and observed active revision. The protocol never treats an observation as a
configuration mutation and never carries executable plugin code.

A stale partition route returns `moved` with a newer authenticated routing epoch
or `catalogue_refresh_required`. A gateway never broadcasts a mutation to find
its owner. Operation IDs are partition-scoped in storage but globally resolvable
through their encoded/recorded partition ID.

Routing/control message families are:

- `ResolveScopeRoute` / `ScopeRoute`;
- `FetchRoutingDelta` / `RoutingDelta` / `RoutingSnapshotRequired`;
- `BeginScopeHandoff`, `FreezeScope`, `ActivateScope`, `AbortScopeHandoff`; and
- `FetchIdentityProjection` / `IdentityProjection`, each signed and revisioned.

A `ScopeRoute` binds its permanent root partition, current owner partition,
ownership/routing epochs, operation family and exact key range. A
`BeginScopeHandoff` additionally binds eligible-member count, planned voter
count, independently compiled quorum-plan digest, capacity-normalised load
evidence digest and measurement instant. The destination is never activated from
source/destination IDs alone.

An identity projection is a bounded committed read model for cell isolation, not
a second writable identity database.

Branch/reconciliation message families are:

- `CompareBranchHeads` / `BranchHeadSummary` with bounded causal frontier;
- `FetchBranchCommits` / `BranchCommitBatch` with parent and operation digests;
- `FetchImmutableObjects` / `ImmutableObjectBatch` for missing CoW roots;
- `ProposeBranchInclusion` / `BranchInclusionResult` at current authority;
- `FetchMergeCommit` / `MergeCommitResult`; and
- `PublishConvergenceReceipt` with included operation IDs, achieved
  acknowledgement predicates and remaining debt.

`PublishIsolationDelegation` distributes signed bounded node/cell allocations;
`FetchIsolationDelegation` retrieves an exact current generation. An isolated
`PutShardBegin` names its delegation and allocation evidence in addition to the
operation-bound capability. Targets durably account use before issuing a
receipt, so replay cannot spend the allocation twice.

Every batch is resumable and content-addressed. A receiver validates the causal
graph, originating identity revision, signature, object bounds and immutable
digests before inclusion. Delivery order cannot change the resulting merge root.

Strong-barrier messages carry a closed set of required predicates and exact
durability evidence. Zones marked `eventual` never appear as blocking
predicates; `excluded` zones are rejected as placement targets.

## 7. Presence and inventory

| Message | Purpose |
| --- | --- |
| `PublishPresence` | Node incarnation, monotonic sequence, mesh-time lease, addresses, roles and health summary |
| `PublishComponentSupport` | Installed implementation IDs, contract ranges, capabilities and limits |
| `PublishComponentObservation` | Desired/active revisions and bounded apply status |
| `PublishTargetStatus` | Capacity, reservation, IO and filesystem observations |
| `InventoryBegin/Batch/Finish` | Reconcile locally present shard identities |
| `ScrubObservation` | Report verified health without changing authority |

Presence is a lease-backed observation. Its sequence is monotonic within one
authority-accepted process incarnation, and a new accepted incarnation fences
every observation from the previous process. Presence is not membership,
permission or proof of stored data.

## 8. Shard write stream

1. `PutShardBegin`: capability, target/object/version/shard/generation IDs,
   declared length and checksum.
2. `PutShardReady`: accepted reservation and maximum frame size, or typed reject.
3. `ShardData` frames: offset and bytes; offsets must be contiguous unless a
   negotiated resume mode says otherwise.
4. `PutShardFinish`: final length and checksum.
5. `PutShardResult`: durable receipt or typed failure.

The write capability is short-lived, operation-bound and target-bound. A receipt
is emitted only after atomic installation and required persistence barriers.

## 9. Shard read stream

1. `GetShardRequest`: read capability and exact shard identity.
2. `GetShardHeader`: authoritative local identity, length, checksum and frame
   size, or typed reject.
3. `ShardData` frames.
4. `GetShardResult`: complete, cancelled or typed failure.

The receiver verifies content independently. Range reads may be added only with
an integrity construction that proves the returned range.

## 10. Shard removal

Before any removal message exists, `ProposeVersionCleanup` records one exact
candidate and an operation-independent reachability-subject digest.
`AttestVersionCleanup` carries one required gateway node's incarnation, unique
durable scan request/result, unchanged local-root digest, cleanup key generation
and Ed25519 signature. All required snapshotted node incarnations must attest to
the same subject; per-node request digests are deliberately different. A node
may produce unreachable evidence only while its exact durable manifest-reference
fence remains active. The fence is installed atomically with scan admission and
prevents later local publication or reconciliation from invalidating an earlier
attestation. The subject binds both the revision-scoped root manifest and a
revision-independent digest of the same ordered root set, so finalisation can
distinguish harmless intervening attestation commands from a changed namespace
head or retained snapshot.

`AuthoriseVersionCleanup` names the exact proposal revision and common subject.
The replicated transition revalidates the current policy and retained roots,
the complete current gateway/incarnation set, active key generations, terminal
scan digests and stored Ed25519 signatures before it creates deletion authority.
`CancelVersionCleanup` terminates the same exact pending identity without
creating that authority. Neither command accepts a provider location or shard
identifier.

`AppendVersionCleanupItems` carries one non-empty bounded contiguous page. Each
item binds a distinct reserved removal operation ID, exact manifest-root shard
identity, target, target generation and owning storage node. The receiver
rejects gaps, overlap, duplicates, a different manifest root and changed total
count while extending a canonical rolling digest. `SealVersionCleanupInventory`
succeeds only when the declared count is complete and that final digest matches.
Building inventory pages cannot produce removal permits. Inventories migrated
from an older schema without an owner fail closed rather than accepting a
reporter inferred from message claims.

`IssueVersionCleanupPermit` records one exact attempt for one sealed inventory
item before provider work starts. It binds the sealed-inventory revision, item
index, strict attempt sequence and the complete keyed `RemovalPermit`. The
permit's catalogue revision is the command's committed revision. The first
attempt consumes the item's reserved provider operation ID; subsequent attempts
use fresh IDs and may not overlap in one authority epoch. An epoch advance may
fence an earlier attempt. The replicated record lets restart and lost-response
recovery reuse the exact committed capability.

`DeleteShardRequest` carries the exact shard identity and a quorum-issued
`RemovalPermit`. `DeleteShardResult` contains either the exact durable
`TombstoneReceipt` or a typed rejection; retrying the same operation returns the
same receipt. The sender identity and incarnation come from mTLS and must match
the request header rather than trusting payload claims.
A durable result is converted to `CompleteVersionCleanupItem` only if its
receipt exactly matches a committed attempt and its canonical tombstone digest
recomputes. The metadata state machine repeats those checks, requires the mTLS
reporter to be the exact storage node recorded in the sealed inventory,
validates its current incarnation and creates a terminal ordered summary only
after every sealed item has one completion.

`ReclaimShardRequest` carries that exact versioned tombstone receipt to the same
target generation. `ReclaimShardResult` contains either a distinct durable
`ReclamationReceipt` or a typed rejection; a tombstone receipt is never
interpreted as evidence that capacity was freed. The receipt binds the exact
completed tombstone, original provider-journal unlink instant, positive
released-byte count and canonical digest. `ConfirmVersionCleanupReclamation`
is admitted only for the matching completed item and same authenticated node at
a current incarnation. Per-item results may arrive while other tombstones are
still outstanding. The terminal reclamation summary appears only after the
terminal tombstone count and every per-item reclamation agree; it stores a
checked byte sum and canonical item-index-ordered digest.

The cleanup worker catalogue returns bounded keyset pages of sealed items and
classifies each from replicated state as `acquire_permit`, `tombstone`,
`reclaim` or `complete`. Entries share no worker-local mutable state and may be
dispatched concurrently. One execution performs at most one provider mutation
and returns the exact authoritative command to submit. Restart or a lost reply
re-reads metadata and replays the provider's immutable receipt; it never guesses
that either side committed.

Each gateway then reads its signature-verified `VersionCleanupParticipant` and
joins its local scan operation with the matching authorised intent and terminal
completion. `VersionCleanupRetirementAuthority` is applied only to that exact
still-active local fence. The resulting retired-root record is permanent and
independently rejects later publication, reconciliation, restore and scan
admission even if the temporary fence row is damaged.

A cancelled intent instead becomes `VersionCleanupCancellationAuthority` for
each gateway's exact local scan operation and common subject. Applying it
atomically records the replicated cancellation operation/revision and releases
only that temporary fence. It does not require an attestation to have reached
the metadata quorum, which lets a lagging gateway recover after cancellation.
An already retired root can never pass this transition.

Before acting, the storage node sends `ValidateRemoval` to the current metadata
authority unless the permit itself is a verifiable, unexpired capability from
the current epoch. Implementations must fail closed when authority is unknown.
Location alone is never a deletion credential.

## 11. Repair and drain coordination

- `ClaimWork` returns a leased, fenced repair/scrub/drain task.
- `RenewWork` extends the same claim only while its fence is current.
- `ReportWorkProgress` is advisory and bounded.
- `CompleteWork` submits receipts and expected revisions for the authoritative
  state transition.

The durable job remains in metadata; peer-to-peer messages do not create a
second scheduler truth.

## 12. Certificate and secret distribution

Only the elected, fenced certificate worker completes ACME HTTP-01 or DNS-01.
After issuance it submits a certificate bundle encrypted separately for each
authorised node identity. Messages are:

- `PublishCertificateBundle` with public metadata and per-node envelopes;
- `FetchCertificateEnvelope` for the caller's node and bundle generation;
- `AcknowledgeCertificateInstall` with the installed public fingerprint; and
- `RevokeCertificateEnvelope` / rotation state changes.

The private key is never broadcast in plaintext or made readable through a
metadata query. Public challenge settings and non-secret status may be
replicated normally.

## 13. Enrolment boundary

An unenrolled node has no private-protocol certificate, so initial enrolment is
an HTTPS API flow. It presents a short-lived, single-purpose join grant and a
locally generated public key. The quorum consumes the grant atomically, admits
the node and returns a mesh certificate chain plus bootstrap peers. The private
key never leaves the joining node. Subsequent activation and topology changes
use the private protocol.

## 14. Versioning and bounds

- Major-version mismatch refuses the connection. Minor versions negotiate
  explicit feature bits.
- Unknown fields are preserved or ignored according to Protobuf rules; unknown
  command variants are rejected, never guessed.
- Every repeated field, string, frame, stream count and in-flight byte total has
  a negotiated bound.
- IDs have fixed canonical byte forms. Timestamps are UTC instants plus explicit
  durations; wall clocks never order consensus events.
- Compression is opt-in per safe message family and never applied to secrets.

## 15. Implementation order

1. Generate message types and compatibility fixtures.
2. Establish mTLS identity binding and `NodeHello` negotiation.
3. Carry consensus over isolated streams.
4. Implement typed metadata command/query/status.
5. Implement branch summary, immutable commit exchange and deterministic merge.
6. Implement shard put/get with durability receipts and acknowledgement barriers.
7. Implement deletion permits, inventory and repair work.
8. Implement encrypted certificate envelopes.

Each step requires malformed-message, boundary, replay, stale-epoch, lost-reply
and cross-version tests before the next family is used by a frontend adapter.
