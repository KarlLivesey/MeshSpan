# Private node protocol

Status: draft for review. This is the logical protocol contract; it deliberately
does not expose the database layout.

## 1. Transport and encoding

- Private node traffic uses QUIC implemented with Quinn.
- Every established peer connection uses mutual TLS and binds the certificate to
  one mesh ID and node ID.
- Protobuf is the proposed canonical message encoding. Bulk shard bytes use
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
| `sender_node_id` | Must match the mTLS identity |
| `sender_incarnation` | Fences a restarted or replaced process |
| `request_id` | Correlates one exchange |
| `operation_id` | Deduplicates one logical mutation |
| `deadline` | Rejects work that can no longer help the caller |
| `trace_id` | Correlation without carrying credentials |

Credentials, raw private keys, password material and database queries are never
placed in this envelope.

## 3. Outcomes and errors

Every completed request has one of:

- `committed`: the named mutation is durably authoritative;
- `rejected`: no matching mutation committed;
- `in_progress`: query again by operation ID;
- `redirect`: contact the identified leader/authority and term;
- `stale`: caller revision, epoch, capability or incarnation is obsolete; or
- `failed`: typed failure with retry class and safe diagnostic detail.

Transport loss has no implied outcome. Mutating callers use `OperationStatus`
before deciding whether to retry. Error codes are stable protocol values;
human-readable text is not parsed.

## 4. Connection messages

| Message | Essential fields | Result |
| --- | --- | --- |
| `NodeHello` | versions, mesh/node/incarnation, roles, feature bits, limits | Authenticates and negotiates |
| `NodeWelcome` | selected version, peer identity, term/leader hint, limits | Opens normal streams |
| `Ping` / `Pong` | nonce, monotonic timings | Liveness and latency sample |
| `GoAway` | reason, retry hint | Graceful connection retirement |
| `ProtocolError` | stable code, offending request | Closes invalid traffic safely |

Certificate identity and `NodeHello` must agree exactly. Limits are the lower of
both peers' advertised safe bounds.

## 5. Consensus messages

The consensus library owns its algorithm-specific payloads, but the wire
contract has only these families:

- `VoteRequest` / `VoteResponse`;
- `AppendRequest` / `AppendResponse`; and
- `SnapshotBegin`, `SnapshotChunk`, `SnapshotFinish` / `SnapshotResult`.

Terms, log positions, membership configuration and snapshot checksums are
explicit. Snapshot chunks are bounded and resumable. No application request may
bypass consensus by writing a peer database directly.

## 6. Metadata commands and queries

`MetadataCommand` contains a closed, versioned `oneof`; it is not raw SQL, a KV
operation or an arbitrary serialized function. Initial command families are:

- mesh settings and feature activation;
- join grants, node admission, role and voter-set transitions;
- host, node, target, fault-group and membership changes;
- volume, failure-policy and placement-policy changes;
- principal, group membership, owner, grant, authentication-method and session
  changes;
- namespace, object-version, manifest and open-handle changes;
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

## 7. Presence and inventory

| Message | Purpose |
| --- | --- |
| `PublishPresence` | Node incarnation, addresses, roles and health summary |
| `PublishTargetStatus` | Capacity, reservation, IO and filesystem observations |
| `InventoryBegin/Batch/Finish` | Reconcile locally present shard identities |
| `ScrubObservation` | Report verified health without changing authority |

Presence is a lease-backed observation. It is not membership, permission or
proof of stored data.

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

`DeleteShardRequest` carries the exact shard identity and a quorum-issued
`RemovalPermit`. `DeleteShardResult` reports `removed`, `already_absent`,
`identity_mismatch`, `permit_expired`, `stale_epoch` or a typed local failure.

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
5. Implement shard put/get with durability receipts.
6. Implement deletion permits, inventory and repair work.
7. Implement encrypted certificate envelopes.

Each step requires malformed-message, boundary, replay, stale-epoch, lost-reply
and cross-version tests before the next family is used by a frontend adapter.
