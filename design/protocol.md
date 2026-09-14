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

| Field                              | Purpose                                                        |
| ---------------------------------- | -------------------------------------------------------------- |
| `protocol_major`, `protocol_minor` | Compatibility negotiation                                      |
| `mesh_id`                          | Prevent cross-mesh requests                                    |
| `partition_id`                     | Selects the one metadata/consensus authority for the operation |
| `routing_epoch`                    | Detects stale scope-to-partition routing                       |
| `sender_node_id`                   | Must match the mTLS identity                                   |
| `sender_incarnation`               | Fences a restarted or replaced process                         |
| `request_id`                       | Correlates one exchange                                        |
| `operation_id`                     | Deduplicates one logical mutation                              |
| `deadline`                         | Rejects work that can no longer help the caller                |
| `trace_id`                         | Correlation without carrying credentials                       |

Credentials, raw private keys, authentication secrets and database queries are never
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
  the mutation has entered the committed converged history;
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

Native metadata forwarding distinguishes transport delivery from authority
completion. Opening/writing a control stream and confirming its delivery use
the private peer-operation budget; a delivered request retains the longer
authority-response budget. A valid response can complete before a delayed QUIC
acknowledgement. Unconfirmed delivery evicts only that cached connection and
leaves the operation outcome unknown. The transport does not retry a mutation;
the metadata owner may resolve or resubmit its identical operation and digest.
Each delivery attempt receives a fresh bounded network deadline, independent of
the operation's original durable timestamp. Renewing delivery does not rewrite
canonical command bytes, audit context, operation identity or request digest.

Metadata command admission binds the forwarded request to its authenticated node,
incarnation and installed leaf certificate, and checks mesh, partition and deadline.
An audit actor embedded in canonical command bytes is not proof of the sender's
authority. Gateway services and current voters retain typed domain forwarding;
metadata eligibility alone does not grant it. A storage-only sender may register
only its own node's target, bound to its current host and server-resolved
registration actor. Other command families are rejected as unauthorised before
consensus submission, including attempts to create users/groups or change policy.
The narrow additional permission is acknowledgement of the sender's own committed
private-certificate candidate. It requires the current node/incarnation and
server-resolved actor, exact candidate generation/staging revision/fingerprint,
unexpired rotation and a valid node-key signature. The transport may use that
candidate or the still-active leaf; a staged leaf authorises no other command.
Installation does not distribute a CA key or grant metadata-write authority.
Certificate/role checks use the receiver's applied state; they are not by themselves
a linearizable revocation barrier or permission to use a disconnected projection
as fresh authority.

After a control request passes framing and peer validation, an unavailable or
expired application handler resets only that request's response stream. It does
not close unrelated multiplexed streams as invalid peer traffic. Stream failure
still conveys no successful or rolled-back operation outcome.
Local certificate rotation removes old connections from the reusable control
cache without cancelling in-flight callers. A handshake racing the rotation may
finish its existing request but cannot cache the obsolete local selection for
subsequent requests.

Native metadata-control streams carry exactly one envelope followed by FIN.
Handlers do not receive unfinished requests or envelopes with trailing bytes.
Stream reset/cancellation, including a late response to a cancelled request,
does not invalidate other streams on the authenticated connection.

Strong file-publication confirmation may use an exact retained committed head
transition, even when a background coordinator published it or a later transition
is now current. Confirmation binds the volume, predecessor, namespace commit,
root revision and original publication operation/request/result digests. It does
not require the metadata publisher to be the foreground caller, republish an old
head, or replace content-policy verification. On a conflicting or lost commit
response, only that exact committed evidence resolves the outcome as success;
absent evidence leaves the strong barrier pending.
An acknowledgement does not promise that another authorised write or restore
has not subsequently superseded the acknowledged version.

Malformed or unauthorised traffic produces only bounded, non-secret diagnostic
detail. Validation failure cannot partially mutate state, allocate from an
unbounded claim, panic the process or become a protocol oracle for credentials,
keys, paths, topology or record existence.

## 4. Connection messages

| Message                                          | Essential fields                                                                        | Result                                |
| ------------------------------------------------ | --------------------------------------------------------------------------------------- | ------------------------------------- |
| `NodeHello`                                      | versions, mesh/node/incarnation, roles, component implementations, feature bits, limits | Authenticates and negotiates          |
| `NodeWelcome`                                    | selected version, peer identity, partition route/leader hints, limits                   | Opens normal streams                  |
| `NodeActivationRequest` / `NodeActivationResult` | header identity, exact roles, capability digest, operation result and active revision   | Continues one HTTPS-admitted identity |
| `Ping` / `Pong`                                  | nonce, monotonic timings                                                                | Liveness and latency sample           |
| `GoAway`                                         | reason, retry hint                                                                      | Graceful connection retirement        |
| `ProtocolError`                                  | stable code, offending request                                                          | Closes invalid traffic safely         |

Certificate identity and `NodeHello` must agree exactly. Limits are the lower of
both peers' advertised safe bounds.

Activation is available only to a leaf certificate already staged by a committed
join-grant consumption. The request header must identify that same node and
incarnation; the role set must equal the staged grant result, and the server must
authenticate a reverse connection to the staged private endpoint before committing
activation. Activation does not itself promote a metadata learner or claim catch-up.

## 5. Consensus messages

The consensus library owns its algorithm-specific payloads. Each consensus
stream is bound to one partition ID; terms and log indices are meaningful only
inside that partition. The wire contract has only these families:

- `VoteRequest` / `VoteResponse`;
- `AppendRequest` / `AppendResponse`;
- `CommittedPrefix` for bounded recovery across a committed membership transition; and
- `SnapshotBegin`, `SnapshotChunk`, `SnapshotFinish` / `SnapshotResult`.

Terms, log positions, membership configuration and snapshot checksums are
explicit. Snapshot chunks are bounded and resumable. No application request may
bypass consensus by writing a peer database directly.

An authenticated member with a different membership phase receives only an exact
phase hint, not a vote, read acknowledgement or permission to advance current
authority. A node which durably applied that historical transition can respond
with `CommittedPrefix`: previous position/digest, contiguous entries, exact
commit limit, membership epoch and plan digest. It may serve only a prefix ending
at or before its durable transition boundary, at most 64 entries per exchange.
The commit limit must equal the last supplied position; speculative tails are
never replayed. Repeated phase hints retry loss without retaining volatile
transfer state, and applied canonical membership commands reconstruct the
boundary index after restart.

The receiver requires its exact current phase and an authenticated, current-
incarnation voter in that phase. It independently checks bounds, entry digests,
continuity and the previous digest, preserves committed entries and persists
any new bytes before emitting an apply effect. Replay carries neither a leader
term nor a read barrier. It does not elect its supplier, erase a newer durable
vote or count as current-plan quorum evidence. Followers can serve their durable
history before a replacement election succeeds. This uses the same explicitly
non-Byzantine voter model as the consensus contract; it does not authorise an
unknown node or learner merely because it has an mTLS connection.

The initial implementation retains the complete bounded consensus log in its
SQLite snapshots. Any later prefix-compaction implementation must preserve a
verified membership-history anchor and range retrieval before discarding those
entries. It must not silently disable membership catch-up after compaction.

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

Log version `65535` is reserved for the fixed current-term confirmation body
`4d 53 43 54 01` (`MSCT` followed by version byte `1`). Any other body under
that version is invalid. It is persisted, replicated and applied in log order
like other entries, but advances only the applied log position/term: no
application revision, user operation receipt or audit actor is manufactured.
A first read may need this entry when no command exists in the new leader's
term; subsequent read barriers do not append merely to read metadata.

## Fresh metadata read frontier

`FetchMetadataReadFence` uses a control stream with the common request header and
one fresh 32-byte nonce. `MetadataReadFenceResult` echoes that nonce and contains
exactly one outcome: a confirmed frontier or a typed `WireError`. Its response
header preserves request ID, operation ID, trace ID, routing epoch and deadline,
while binding the responding node's own authenticated identity.

- Only a currently admitted same-swarm node with its exact active certificate,
  incarnation and unexpired request may ask. The service rechecks admission after
  the barrier, because catch-up may have applied retirement or credential changes.
- The leader first confirms its current-term committed frontier and a fresh read
  quorum, then waits for local application. The result binds partition, leader,
  term, membership epoch, compiled plan digest, applied term/index/digest and the
  coherent application revision. Applied term equals the confirmed leader term.
- The transfer has a ten-second deadline; the underlying reactor read is bounded
  to five seconds. Queue exhaustion, follower state, timeout or lost authority
  produces no successful frontier. This read uses the fetch lane and never holds
  the application's mutation-serialization permit.
- A client checks every request/source binding, not just the returned log index.
  It selects a candidate from its trusted voter phase. A receiving passive replica
  must catch up to and independently verify the exact frontier before using its
  metadata for the requested check; it never treats a historical page as freshness.
- This result is not a reusable lease or permission to read/delete shards. Exact
  operation, current recipient, storage target, key epoch and committed permit
  checks remain separately required. The initial endpoint does not itself enable
  storage-only maintenance.

## Non-voting metadata history transfer

Storage-only nodes use `FetchMetadataReplicaPage` on a data stream, not an
`AppendRequest` or `CommittedPrefix`. Receiving history does not admit a node to
consensus or provide a fresh read/permission barrier.

- Request: common `RequestHeader` and an `after` cursor binding partition ID,
  membership epoch, plan digest, applied term/index and complete applied-entry
  digest. Genesis is term/index zero and a zero applied digest. The request ends
  immediately after its one control frame; trailing payload is rejected.
- Response: `MetadataReplicaPageHeader` binds the request ID, exact requested
  cursor, total body length, SHA-256 body digest and maximum data-frame size.
  A rejection instead contains one bounded `WireError` and no cursor/body fields.
- Success body: canonical Protobuf `MetadataReplicaBody`, format version `1`,
  repeats the exact cursor and carries at most 64 contiguous log entries with
  at most 16 MiB of aggregate command bytes. A 16 KiB additional encoded-header
  allowance is not additional command capacity. It is carried in offset-checked
  `DataFrame`s, at most 64 KiB each or the negotiated limit if smaller, then EOF.
  The existing 64 KiB control envelope limit remains unchanged.
- Each entry carries position, operation ID, complete entry digest and versioned
  canonical command bytes. The receiver checks both body and complete entry
  digests, versions and continuity; application separately validates the current
  membership phase, supplying voter/incarnation and command semantics.

The daemon checks current same-swarm certificate/incarnation, mesh, partition,
route epoch and deadline before asking the metadata owner for applied history.
It checks identity again before encoding. Recovery-installed active node records
are valid admission evidence; no legacy activation row, gateway role or gateway
key is required. The supplier only exports applied history ending at the current
phase's membership transition. Empty pages do not imply freshness.

The source has an independent two-transfer admission pool. Network IO is bounded
by a 30-second deadline and cycle cancellation. SQLite access and bounded large
encoding/decoding run on owned blocking workers whose completion is observed,
including during shutdown; cancelling a socket does not detach those workers.
The client revalidates the source against its live certificate registry after
decoding and requires the exact node/incarnation/fingerprint bound before IO;
rebinding the same certificate to a new incarnation cannot relabel old traffic.
It returns no partial page after corruption, interruption, an incorrect
cursor/request ID, excess frames or trailing bytes. A stale cursor is rejected
as `Stale`; unavailable history is not replaced with fabricated empty success.
Client shutdown also cancels pending network IO without waiting for that deadline;
any already-started decoding is still observed before the fetch returns. Retrying
uses the durable applied cursor with fresh transport correlation, not partially
received bytes or an inferred current head.

## Same-swarm publication replay

Same-swarm gateway history uses `PublishNamespaceHead` and the bounded history/
content-layout fetch messages. Source-branch head transitions atomically retain
delivery references in branch schema 43. An owned daemon worker discovers current
peers, resumes each peer's persisted cursor and advances it only after a durable
`NamespaceHeadAccepted` response matches the request operation and exact result
digest. Network failure and process restart do not discard the work. Local
delivery sequence is neither consensus order nor evidence of a converged head.

The receipt acknowledges durable history/content-layout retention, not activation
of the advertised live head. Replicated metadata may already name a newer commit
whose immutable history is still in the sender's delivery queue. The receiver
retains the older frontier and acknowledges it, allowing that queue to advance;
it does not adopt a live head while the current authority commit is missing.
An absent commit is distinguished from corrupt or wrong-volume history, which
still fails closed. Restore-ancestry checks remain mandatory before adoption.

Canonical namespace-history records carry ordinary mutations (local format 1,
federated format 3), multi-parent merges (format 4) and snapshot restores
(format 5). Format 4 retains the
existing domain and common commit/origin fields, uses payload tag 2 followed by
the replay-plan digest, and appends the causal-plan and result digests instead
of a mutation intent or federation acknowledgement. Merge parents are strictly
ordered, unique, bounded to 1,024 and cannot include the commit itself. The
commit and reconciliation-result digests are checked before import. Paged
transfer carries the complete referenced immutable root graph separately.

Import retains merge evidence transactionally, supports exact replay and never
advances a live branch or converged metadata head by itself. A merge cannot be
interpreted as a freshly authorised federated mutation. Root selection and
subsequent filesystem operations accept validated multi-parent commits; they
do not force them through a single-parent mutation receipt.

Format 5 uses the same common fields, payload tag 3 followed by the snapshot ID
and snapshot namespace-commit ID, then the common origin/commit digest and the
restore result digest. It has exactly one causal parent: the replaced head.
The snapshot commit is a separate immutable dependency and may belong to a
different branch. Both bounded export paths include that dependency; import
waits for it and checks its exact volume/root/revision before committing anything.
The canonical restore request, commit and result digests are independently
checked. Imported receipts stay unactivated and cannot be interpreted as signed
federation mutations. Before a native gateway adopts received history, its
replicated committed head must cover every restore in that lineage; an off-head
prepared restore or a later mutation on top of it cannot create authority.
Earlier record formats are unchanged; old decoders reject format 5.

Metadata command version 6 adds `ExtendVolumeKeyRecipients` (command kind 89).
Its bounded payload reuses the encrypted-secret/recipient encoding but has a
distinct request-digest domain and permits only additive envelopes for an
unchanged historical volume-key generation. This is an authority operation,
not a capability granted by namespace-history receipt.

Metadata command version 7 adds `AbandonUnrecordedMetadataBackupRun` (kind 90).
Its payload is the exact backup ID followed by the existing claim encoding:
claim generation, worker node ID, worker incarnation and fence. All counters
are nonzero. The authority accepts it only while that exact claim is expired,
the run remains claimed and no backup generation has been admitted. It atomically
records an incomplete outcome and makes the next occurrence due; the replacement
uses a new backup ID. Recorded generations instead retain their identity and
recover their original encrypted container. Renewal, replacement and admission
races reject a stale abandonment. Neither expiry nor this outcome authorises
physical deletion of a provider object. Existing canonical command byte layouts
are unchanged; that addition introduced private command forwarding version 7.

The local staging owner may reclaim its exact journal-owned container after
observing that terminal unadmitted state, no active claim and the matching source
partition. It removes and synchronises the private file before deleting its
journal record. This local cleanup is not a remote provider-delete capability.

### Federation commands in local consensus

Metadata command version **18** includes the federation operations
available through the owning swarm's consensus adapter. It does not combine
different swarms' consensus logs or grant authority merely because decoding
succeeds. Existing command bytes retain the `MSC\x04` prefix and layouts; the
forwarding version advertises the larger supported command set. The retained
grant-record format is unchanged. Version 9 adds invitation issuance and
cancellation with partition schema 94; kinds 91–115 were introduced in version 8.
Version 10 adds invitation consumption and retained signed peers in partition
schema 95, kind 118. Outbound intent retention adds schema 96, kind 119.
Relationship approval remains a separate command/revision.

Version 18 adds the complete version-cleanup lifecycle (kinds **126–134**),
without changing existing command layouts or the database schema. Each payload
follows the fields of its named Rust command in declaration order:

| Kind | Command                            |
| ---: | ---------------------------------- |
|  126 | `ProposeVersionCleanup`            |
|  127 | `AttestVersionCleanup`             |
|  128 | `AuthoriseVersionCleanup`          |
|  129 | `CancelVersionCleanup`             |
|  130 | `AppendVersionCleanupItems`        |
|  131 | `SealVersionCleanupInventory`      |
|  132 | `IssueVersionCleanupPermit`        |
|  133 | `CompleteVersionCleanupItem`       |
|  134 | `ConfirmVersionCleanupReclamation` |

IDs occupy 16 bytes; digests 32 bytes; attestation signatures 64 bytes. Counters
and revisions are unsigned big-endian 64-bit values, timestamps signed big-endian
64-bit values. A shard is manifest digest, stripe index (64-bit), shard index
(16-bit), generation (32-bit), in that order. Embedded permits and receipts follow
their contract field order, recursively. Append pages prefix placements with a
16-bit count, restricted to 1–1,000; their checked start-plus-count must not exceed
the declared inventory total. This check precedes placement allocation. Truncation,
trailing bytes and zero identifiers are rejected. The existing 1 MiB command bound
still applies. Decoding conveys no deletion authority: replicated validation must
check reachability, participant signatures, sealed inventory, permit generations
and exact completion/reclamation evidence. Older forwarding versions cannot send
these additions; this is not a rolling mixed-version upgrade guarantee.

Version 17 adds `BindBackupPublicationIntent` (kind **125**, partition schema
**103**). Its canonical payload is backup ID, destination ID, provider generation,
encrypted byte length, encrypted digest, store-operation ID, worker node ID,
worker incarnation, claim generation, claim fence and expected destination
revision, in that order. A live exact run claim and active exact destination
revision are required before provider IO. The first intent retains its object
and store operation across worker/claim changes; changing either is rejected.
Intents for different destinations of one backup must describe the same bytes.
This is not a stored-copy receipt, admission, verification or deletion authority.

The publisher derives the store-operation ID with the `store-provider.v2`
domain from the backup/destination and immutable source creation instant, not
the current attempt time. The folder provider's store-operation digest uses its
`operation.v2` domain and excludes attempt deadlines/current upload-authority
revisions, while binding the exact object, reference and operation. Current
request validity and caller authority remain mandatory. Delete digests retain
their existing domain and retirement-revision binding. Old pre-alpha store
digests are not reinterpreted as the new format; existing bytes remain readable,
but no replay compatibility for an old store operation is claimed.

Version 15 adds `RetireAbandonedBackupCopy` (kind **124**, partition schema **101**).
Its payload is the terminal run revision, provider receipt operation ID, backup ID,
destination ID, provider generation, byte length, object digest and bounded opaque
reference, in that order using the common encodings. Admission requires the exact
committed incomplete run with no live claim and no admitted backup. An expired
lease or missing catalogue entry alone is insufficient. The destination generation
must match; a federated object must also match its retained route. This commits
immutable exact-object retirement authority, not a stored backup or a deletion
acknowledgement. Unknown newer command versions remain rejected.

Version 16 extends `RecordBackupReclamation` (existing kind **74**, unchanged
payload) to exact abandoned-object retirement authority. Partition schema **102**
stores these completion receipts separately from admitted backup copies. The
provider operation ID, object identity and retirement revision must match; a
conflicting receipt cannot overwrite completion. Pending cleanup merges admitted
retired copies and abandoned retirements using bounded keyset pages. Provider
deletion without a committed receipt remains pending and retries the same exact
operation after restart. This does not discover unknown provider objects or infer
deletion from absence, timeout or lease expiry.

Version 12 adds `BindFederatedBackupRoute` (kind **120**, partition schema **97**).
It commits consumer routing intent before uncertain provider IO, not a stored
copy. Its payload is, in order: backup ID, destination ID, relationship ID,
consumer mesh ID, provider mesh ID, allocation ID, grant ID, provider node ID,
target ID; provider generation, byte length, target generation, relationship
authority epoch, grant revision, allocation revision; object digest; claim worker
node ID, worker incarnation, claim generation, claim fence, expected destination
revision. It uses the common scalar encodings below. The immutable SQL projection
prefixes that payload with record-version byte `1` and is bounded to 320 bytes.
Foreign grant/allocation revisions are observations, not local permission grants.
Every provider operation still obtains current signed remote admission. No new
cross-swarm message tag is required for this consumer-local command. This raises
the closed command admission version; mixed command-version replay/rolling
upgrade compatibility is not established by the schema migration test.

Version **13** adds route kind **121** with the immutable namespace grant
separate from renewable permission. Kind **120** keeps its original decoding.
Version **14** adds provider capacity seal kind **122** and node attestation-key
registration kind **123**. These are local consensus commands, not cross-swarm
permission grants. The seal signature has its own domain and binds the provider
mesh, immutable allocation/node/target, target generation, retained byte ceiling,
sequence, node incarnation, key generation and seal time. Its signing order is
defined in `RecordFederationStorageSeal::signing_payload`; wire order is below.
Only the provider's permanent local admission fence can justify signing it.
Consensus acceptance does not delete retained objects or revoke their read authority.

After the common command context, each payload begins with a big-endian `u16`
kind. Fields below are in wire order. IDs occupy 16 bytes, counters/revisions
are `u64`, instants are signed `i64` microseconds, digests are 32 bytes and
Ed25519 signatures are 64 bytes. Strings/byte blocks use a `u32` byte length.
Options use a strict `0`/`1` tag followed by the value only for `1`.

|  Kind | Operation                                   | Payload after kind                                                                                                                                               |
| ----: | ------------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------- |
|    91 | Propose relationship                        | relationship ID, remote mesh ID, name, relationship kind, governance direction                                                                                   |
|    92 | Approve relationship                        | relationship ID, expected authority epoch, local identity, remote identity, optional governance proof                                                            |
|    93 | Rotate identity                             | relationship ID, expected authority epoch, identity owner, identity                                                                                              |
| 94–97 | Restrict/recover/revoke/retire relationship | relationship ID, expected authority epoch, new authority epoch, reason                                                                                           |
|    98 | Issue grant                                 | grant-definition block                                                                                                                                           |
|    99 | Replace grant                               | predecessor grant ID, grant-definition block, restricts-authority boolean, reason                                                                                |
|   100 | Revoke grant                                | grant ID, expected authority epoch, reason                                                                                                                       |
|   101 | Issue storage allocation                    | allocation ID, grant ID, provider node ID, target ID, target generation, maximum bytes, validity start/end, expected grant revision                              |
|   102 | Revoke storage allocation                   | allocation ID, expected allocation revision, reason                                                                                                              |
|   122 | Record provider capacity seal               | provider mesh ID, allocation ID, provider node ID, target ID, target generation, ceiling bytes, sequence, seal time, node incarnation, key generation, signature |
|   123 | Register node attestation key               | node ID, key generation, 32-byte Ed25519 verifying key                                                                                                           |
|   103 | Create local assignment                     | assignment ID, grant ID, subject principal ID, rights, optional validity start/end, optional activation policy ID                                                |
|   104 | Revoke local assignment                     | assignment ID, reason                                                                                                                                            |
|   105 | Activate assignment                         | activation ID, principal ID, assignment ID, policy ID, reason, duration, session expiry, assurance, authentication digest                                        |
|   106 | Revoke assignment activation                | activation ID, principal ID, reason                                                                                                                              |
|   107 | Record actor attestation                    | relationship ID, home mesh ID, principal ID, actor kind, name, actor state, identity revision, authority epoch, signer generation, signature                     |
|   108 | Designate successor                         | succession fence, ordered ancestry, signer generation, signature                                                                                                 |
|   109 | Accept successor                            | succession fence, designation digest, signer generation, signature                                                                                               |
|   110 | Activate successor                          | succession fence, designation digest, acceptance digest, reason                                                                                                  |
|   111 | Revoke successor designation                | succession fence, designation digest, signer generation, reason, signature                                                                                       |
|   112 | Retain mutation quarantine                  | quarantine ID, signed acknowledgement                                                                                                                            |
|   113 | Admit mutation                              | namespace commit ID, signed acknowledgement                                                                                                                      |
|   114 | Surface quarantine                          | quarantine ID, source operation ID                                                                                                                               |
|   115 | Resolve quarantine                          | quarantine ID, source operation ID, resolution, reason                                                                                                           |
|   116 | Issue pairing invitation                    | relationship ID, issuing node ID, authentication-root generation, material verifier, HTTPS origin, certificate fingerprint, exclusive expiry                     |
|   117 | Cancel pairing invitation                   | relationship ID, expected invitation revision, reason                                                                                                            |
|   118 | Prepare connection                          | relationship ID, inviting mesh ID, material verifier, optional invitation revision, local signed peer, remote signed peer                                        |
|   119 | Begin outbound connection                   | relationship ID, inviting mesh ID, material verifier, remote HTTPS origin, certificate fingerprint, expiry, local signed peer                                    |

The two invitation commands remain local-swarm control authority. Issuance
persists public material and a 32-byte verifier, never the connection secret.
It requires an active gateway and an existing protected authentication-root
generation. Cancellation requires the exact pending revision and cannot revoke
an established relationship. Both mutations commit an ordinary audit/operation
receipt. Inviting another swarm does not enrol a node or grant file rights.

Native HTTPS exposes `POST /api/latest/admin/federation/invitations` and
`POST /api/latest/admin/federation/invitations/cancel`. Both authenticate a current
system manager before reading at most 2,048 body bytes, validate the Rust-authored
schema and reauthenticate before committing. Responses are validated and
`Cache-Control: no-store`. Issuance accepts 60–3,600 seconds; the simple-client
default is 900. Exact retries reproduce the original committed outcome without
extending validity; changed intent conflicts. Cancelled material cannot be
reissued by replaying its original operation.

Connection material is a distinct, bounded format, not a node join grant:

```text
meshspan-federate-v1.<mesh>|<relationship>|<issued>|<expires>|<pin>|<secret>|<https-origin>
```

The fields use strict lowercase hexadecimal: mesh/relationship 32 digits,
issued/expiry 16 digits, fingerprint/secret 64 digits. Times are nonnegative
microseconds. The origin is at most 512 bytes, without user information, path,
query or fragment; the entire code is at most 763 bytes. The origin and pin are
bound into deterministic HMAC-SHA256 issuance along with mesh, administrator,
operation and original lifetime. Issuance uses a separate authentication-root
derivation domain, not node identity keys. A verifier is SHA-256 over the domain
`meshspan.federation.pairing.verifier.v1\0` and the complete encoded material.
Parsing or time validity alone does not establish authority.

`POST /api/latest/federation/pairings/accept` authenticates exactly one
`Authorization: MeshSpan-Pairing <code>` header and rejects cookies. It checks
current invitation validity, cancellation, verifier, issuing node and the
issuer's current manager authority before reading its bounded 26 KiB JSON body.
The body carries an operation UUID and an unpadded base64url signed peer record.
Preparation atomically consumes the invitation and retains both peers; a separate
approval advances the relationship at a later committed revision. An exact retry
returns the original approval, while a changed operation or peer conflicts.
Restricted/revoked/retired relationships cannot be reactivated through pairing.
The response proves only the issuing side's approval, never data access, node
enrolment, the remote side's commit or live transport health.

A signed peer is `MSFP` followed by version byte `1`, mesh ID, node ID, name,
HTTPS origin, TLS certificate DER, Ed25519 public key, validity start/end and
signature. Names/origins/certificates are length-prefixed with limits of
256/512/16,384 bytes; the canonical record is at most 18 KiB. The signature binds
the relationship, inviting mesh, full invitation verifier and every peer field
under the `meshspan.federation.pairing.peer.v1` digest and
`meshspan.federation.pairing.signature.v1\0` signing domains. No private key is
transmitted.

`POST /api/latest/admin/federation/connections` takes a current manager's
operation UUID, connection code and reachable local HTTPS origin. It commits
the exact signed local peer and public invitation routing/verifier in the local
partition before making any remote request. The connection secret is not stored.
The existing TLS 1.3 client pins the invitation's exact HTTPS leaf; there is no
redirect or unpinned fallback. No service lock spans network IO. The daemon
validates the returned identity, relationship, operation and approval revision,
rechecks current manager authority, then separately prepares and approves the
local relationship. On the initiating side, preparation must match its retained
intent, including actor, peer, invitation, destination and unexpired deadline.
Intent/preparation use internal domain-separated operation IDs. The caller's
operation ID belongs to final local approval, so merely saving intent cannot
resolve that operation as a successful connection. During an interrupted attempt
that public receipt may be absent; absence is not proof of remote failure.

A lost or unusable reply leaves an unknown outcome, not successful connection.
An exact retry before invitation expiry reuses the original signed peer and
approval receipts after reopening local state. Changed local intent rejects
before a network request. Both approvals mean relationship establishment only:
no file grant, storage allocation, local node enrolment or live QUIC session is
implied. Recovery after invitation expiry and recovery-root certificate
chaining/rotation remain unfinished.

### Native federation session lifecycle

The daemon binds a separate QUIC socket on UDP at its actual HTTPS TCP
address/port. Its only ALPN is `meshspan-federation/1`; within-swarm
`meshspan-private/1` is not accepted even with a trusted certificate. The socket
starts with no admitted peers. Active/restricted pairing records hosted by this
eligible gateway supply the exact remote certificates; installing or withdrawing
trust does not rebind the socket. TLS admission alone never grants file or backup IO.

The lower mesh ID initiates each relationship's session, avoiding two competing
routine diallers. The owner refreshes committed local authority every five
seconds, retires closed or obsolete sessions, and retries missing sessions.
Concurrent handshakes are bounded separately from established connections.
DNS, TLS and signed-session exchanges each have a ten-second deadline. Replay
admission is shared, but its lock covers synchronous validation only, never
network waits. QUIC keepalives use a five-second interval. Shutdown closes the
endpoint, cancels owned handshake tasks and observes their results.

Every handshake reloads the relationship and exact local/remote identities;
unreadable authority withdraws admission rather than retaining a permissive
fallback. Background revocation takes effect when the committed local projection
is observed, not instantaneously across disconnected swarms. The current native
implementation uses the daemon's existing UTC source; quorum-derived time and
identity rollover are not established by this session proof. No data stream is
served yet: native signed grants/capabilities and other-swarm backup delivery
remain separate task 7 work. Private identity keys stay local.

Names are canonical `RecordName` display strings, bounded to 256 UTF-8 bytes;
reasons are bounded to 512 bytes. Enum tags occupy one byte: horizontal/governance
are `1/2`; governance direction is none/local-governs/remote-governs `0/1/2`;
identity owner is local/remote `1/2`; actor kind is user/group/service `1/2/3`;
actor state is active/suspended/retired `1/2/3`; assurance is single/multi/recent
step-up `1/2/3`; resolution is restore/restore-as-copy/discard `1/2/3`.

An identity is generation, certificate fingerprint, verifying key and validity
start/end. Governance proof is remote authority epoch, `u16` ancestry count,
ordered parent/child mesh-ID pairs, signer generation and signature. Succession
fence is succession ID, relationship ID, retiring mesh ID, successor mesh ID,
expected authority epoch and succession epoch. Succession ancestry uses a `u16`
count followed by ordered retiring/successor mesh-ID pairs. Both ancestry
collections are bounded to 4,096 edges before allocation; graph validity and
signature authority are still checked by the state machine.

The grant-definition block is bounded to 16,384 bytes. Its domain is
`meshspan.federation.grant-definition\0\x01`; it uses the retained grant codec's
grant/resource/policy layout, followed by a `u16` restriction count (2–64) and
ordered imposing-mesh-ID/policy entries. It deliberately contains no fabricated
committed revision, lifecycle state or termination evidence. The authority
recomputes the bilateral restriction intersection when applying the command.

A signed acknowledgement contains source operation ID; grant ID; relationship
ID; actor home mesh ID and principal ID; accepting mesh ID; resource scope;
authority epoch; accepted-at time; required rights; storage bytes; payload
digest; signer generation; signature. Resource tags are volume `1` (owner mesh,
volume), subtree `2` (owner mesh, volume, root object), file `3` (owner mesh,
volume, object) and storage `4` (provider mesh). Assignment/acknowledgement rights
occupy `u64` on this wire and must fit the known `u32` rights mask. The original
actor and accepting relay are never collapsed into one identity.

The complete command remains bounded to 1 MiB. Unknown tags, invalid IDs,
noncanonical names, oversized fields, truncation and trailing bytes are rejected.
Decoding never replaces current administrator/session checks, signature
verification, grant narrowing, quota checks, epoch fencing or authoritative
reconciliation. Those remain the existing typed state machine's responsibility.

The source replay implementation does not yet close divergent-head convergence,
retired-history catch-up/compaction, or transitive replay after the original
source is lost. Those remain required before availability-preserving rolling
restarts can use namespace delivery as complete workload coverage.

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
  exact grant allocation, target generation, shard, action, byte ceiling,
  expiry and nonce;
- `FederatedStorageReceipt` for the exact allocation, capability/result
  digests, affected bytes, completion instant and provider signature; and
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

| Message                       | Purpose                                                                                    |
| ----------------------------- | ------------------------------------------------------------------------------------------ |
| `PublishPresence`             | Node incarnation, monotonic sequence, mesh-time lease, addresses, roles and health summary |
| `PublishComponentSupport`     | Installed implementation IDs, contract ranges, capabilities and limits                     |
| `PublishComponentObservation` | Desired/active revisions and bounded apply status                                          |
| `PublishTargetStatus`         | Capacity, reservation, IO and filesystem observations                                      |
| `InventoryBegin/Batch/Finish` | Reconcile locally present shard identities                                                 |
| `ScrubObservation`            | Report verified health without changing authority                                          |

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

## 11. Remote metadata-backup provider streams

An authority-fenced backup worker may use a registered target on another swarm
node through the same authenticated QUIC data-stream class as shard IO. Backup
control messages never contain the encrypted backup body. The body uses
independently bounded `DataFrame` messages, and the receiver counts and hashes
the complete stream itself.

Every operation names the exact backup ID, destination ID, provider generation,
encrypted-container length and digest. Store, read and verify also carry the
positive catalogue revision that authorised the operation. Delete instead
carries the exact positive retirement revision. A provider object reference is
bounded opaque data returned by a successful store; it is never interpreted as
authority and cannot authorise deletion by location alone.

Store uses this sequence:

1. `StoreBackupBegin` declares the exact object and authority revision.
2. `StoreBackupReady` returns a bounded reservation and maximum frame size, or
   a typed rejection with no reservation.
3. Contiguous `DataFrame` messages carry the encrypted container.
4. `StoreBackupFinish` repeats the final length and digest.
5. `StoreBackupResult` returns a durable, operation-bound object receipt or a
   typed failure with no success evidence.

Read uses `ReadBackupRequest`, `ReadBackupHeader`, bounded `DataFrame` messages
and `ReadBackupResult`. The final receipt repeats the independently observed
length and digest. Verify uses `VerifyBackupRequest` and
`VerifyBackupResult` without returning object bytes. Delete uses
`DeleteBackupRequest` and `DeleteBackupResult`; both its request and receipt
bind the exact object and retirement revision.

Receipt recovery uses `LookupBackupRequest` / `LookupBackupResult`,
`DataControlEnvelope` tags **62–63**. The request carries the exact object and
positive retained upload-intent revision, but no provider reference or byte body.
The replaceable provider returns its opaque reference bound to that object and
the current lookup operation. This is durable catalogue evidence, not a new
integrity verification, backup admission or deletion permission. Same-swarm
authority checks the current authenticated node, target binding and intent;
the requester must own the live publishing claim, or the run must already be
authoritatively abandoned, terminal and unadmitted with no remaining claim.

The cleanup worker pages such abandoned intents, looks up their exact provider
evidence, commits receipt-bound retirement, then uses ordinary exact deletion
and durable reclamation completion. Missing objects, timeouts and rejected
receipts stay pending: an older in-flight upload could still finish. The worker
never derives an opaque reference from a folder layout or treats absence as
permission to delete or as completed cleanup.

Retries reuse the same operation ID. A receiver rejects changed reuse, stale
provider generations, elapsed deadlines, revision mismatch, non-contiguous
frames, short or long bodies, digest mismatch and success results without exact
receipts. Session handling additionally checks that every response receipt and
finish message matches its initiating request; structural wire validation does
not substitute for that conversation-state check.

### Cross-swarm metadata-backup authority boundary

The implemented provider contract now distinguishes `FederatedBackupRequest`
store/read/verify/delete/lookup operations from shard capabilities. Each request embeds
the existing complete backup operation: operation ID, contract version, deadline,
consumer catalogue revision, exact encrypted object identity, and (where
applicable) opaque reference and retirement revision. Missing and zero revisions
have distinct canonical encodings; neither is valid provider authority.

`FederatedBackupScope` binds the bilateral relationship, consumer/provider swarms,
current permission (`grant_id`), immutable allocation origin (`namespace_grant_id`),
allocation, provider node, target incarnation, relationship epoch and exact
grant/allocation revisions. Request digests use BLAKE3 with domain
`meshspan.federation.backup-request.v1`; provider-only keyed permits use
`meshspan.federation.backup-permit.v1`, separate from shard permits. The capability
interval is inclusive at issuance and exclusive at expiry, at most five minutes
and no later than the request deadline. The MAC does not replace fresh metadata
and authenticated-session checks, nor the signed federation envelope/receipt.

Gateway and relayed-owner backup permission checks read their related metadata
from one short-lived committed database view. Unrelated root commits cannot turn
that check into a stale-revision failure or mix allocation and identity histories.
Each transfer/completion boundary opens a new view, so revocation and identity
changes remain visible to subsequent checks. No view spans provider or network IO;
it is not a permission lease or a substitute for a consensus read barrier.

The complete operation deadline and an individual exchange deadline are distinct:
an hour-long export uses replay-bounded exchanges of at most five minutes. The
signed envelope deadline must not exceed the embedded operation deadline, and
permit expiry must not exceed either. Capability issuance also respects the
current allocation lease. Shortening an exchange never rewrites the operation's
identity or payload, extends authority, or makes an interrupted attempt successful.

Provider storage maps a logical destination to an opaque namespace bound to the
consumer, relationship, allocation, originating grant and exact target. It uses the target's
physical generation while keeping the original logical identity on federation
requests and receipts. Permission succession and revisions do not rename retained bytes. The
provider catalogue still rejects changed payloads under one immutable backup ID.

Scope field **12** carries the mandatory 16-byte `namespace_grant_id`; absent or
malformed origins fail wire validation. Both grant identifiers are authenticated,
and provider admission checks the origin against the immutable allocation while
checking the current grant against its renewable authority projection. Discovery
returns the current permission and effective lease interval; its size predicate
uses the original allocation ceiling so retained objects remain discoverable after
quota narrowing. New writes still pass the current lower quota at admission.

Saved routes are immutable physical intent, not reusable permission. Before an
ordinary retained-object operation, the native consumer obtains current signed
grant and allocation discovery, accepting only the same allocation, origin,
provider, target and incarnation. Only permission ID/revision and relationship
epoch may refresh. It does not reroute an uncertain upload or rewrite its route.
An initially admitted upload retains its exact prepared capability instead.
Discovery and refresh have bounded pages and an overall operation deadline.

Local schema **14** adds backup-object capacity records using the same allocation
counters as shards; it does not create another copy of the quota. Holds precede
IO, exact retries charge once, durable publication converts held to used bytes,
and confirmed physical removal releases used bytes. Exclusive local recovery may
cancel an unpublished hold after proving absence. Expiry, disconnection, a missing
remote catalogue entry or a caller's claim never provides that absence proof.
These accounting transitions are local provider-owner calls, not remote APIs.

`FederatedBackupCapacityBudget` rechecks the current allocation, grant and
relationship on every reservation, including retries. `IntersectedBackupCapacity`
composes that budget with the actual folder budget: allocation admission precedes
physical admission; physical completion/cancellation precedes allocation
completion/cancellation. Failures retain conservative charges rather than assuming
a failed call had no durable effect. Exclusive provider recovery pages the bounded
union of both sets of holds, rejects contradictory identities, and settles only
verified publication or absence. It can settle existing charges after revocation
without authorising new IO. Missing allocation evidence for catalogued federated
bytes fails closed; recovery does not invent uncharged capacity.

`NamespacedBackupProvider` maps the consumer destination/generation to the physical
provider identity for each operation and checks receipts before returning logical
identities. It is a routing adapter, not an authorisation boundary. The dispatcher
must authenticate and revalidate authority before reads and deletion too; direct
provider-owner recovery calls are not remote requests.

#### Same-swarm storage-owner relay

`DataControlEnvelope` tags **90–92** define `ForwardFederatedBackupRequest`,
`ForwardFederatedBackupReady` and `ForwardFederatedBackupResult`. These messages
belong to the provider swarm's node-mTLS data stream, not a foreign node enrolment
or a second federation relationship. Existing data-control tags are unchanged.

The request carries a normal same-swarm routing header, exact provider node,
maximum data-frame size and the consumer's original `encode_federation_frame`
bytes. Both the outer control frame and embedded signed frame have independent
negotiated bounds. The inner message must be `ExecuteBackup`; capability minting,
discovery and nested forwarding are rejected. Owner identity, mesh, request ID,
operation ID and trace must agree across the wrapper and signed operation. The
relay deadline may narrow, but never extend, the consumer deadline or permit expiry.

Transport authentication binds the wrapper's sender/incarnation to the real
same-swarm mTLS peer, then independently verifies the original consumer signature,
current federation identity lifetime and replay nonce. Failed authentication does
not consume a valid request's nonce. This proof is not storage admission: the
owner must additionally revalidate current relay enrolment/certificate, routing,
its own target ownership and the live bilateral grant/allocation before IO.

The gateway retains its federation signing key and permit-MAC key. Neither key
is forwarded. The owner replies through its authenticated node connection; the
nested ready/result signature field must be empty on this hop. Conversely an
external federation ready/result must still have a valid signature. The gateway
must correlate owner replies with the exact forwarded request and verify permit,
action, object, deadline and receipt before signing its external response.

Reply `request_digest` is SHA-256 over the NUL-terminated domain
`meshspan.federation.backup-owner-relay.v1` followed by the complete canonical
`encode_data_control_frame` bytes of the forwarding request, including its frame
prefix. Thus the original signed request, current hop identity/routing header,
provider and frame limit all participate in correlation.

Successful store readiness must follow owner-side allocation and physical-folder
admission. Lost replies leave the upload outcome unknown and retain its exact
route and conservative capacity charge. They do not authorise rerouting.

**Implementation status:** framing, original-consumer transport authentication
and owner-side current-authority admission are implemented. The owner checks
the receiving node, current enrolled relay certificate/incarnation, local mesh,
partition and active routing epoch, original consumer authority and permit
lifetime. A revision check rejects an authority projection changed during admission.
It uses no gateway private key and reserves no capacity itself. Real node-mTLS
and daemon consensus-enrolment tests exercise this boundary. The owner execution
service now shares the direct execution state machine for provider IO, framing,
exact upload FIN/digest verification and receipts. It rechecks owner authority at
the same IO/completion boundaries, narrows frames to the relay's offer and limits
the operation by both the permit and relay deadlines. Real directory/QUIC tests
cover rejected capacity, truncated upload, reopen, successful upload and replay.
The daemon data dispatcher now sends forwarded requests to the lifecycle-bound
native owner. It uses the same registered-folder catalogue, intersected allocation
and physical-folder budgets, replay window and bulk admission as direct federation
execution. The route epoch comes from the local private-network configuration,
not the incoming header. The cycle observes the deadline-bounded blocking worker
through completion before replacing folder ownership. Real QUIC/native-provider
tests cover retained interrupted-upload reservations, successful retry and replay,
read, verify, delete and direct/forwarded catalogue reuse.
Gateway reply validation and bounded byte forwarding are now connected in code:
the daemon resolves the exact other-node route through its private network,
and rechecks owner certificates and bilateral authority throughout forwarding.
Capability issuance may target another node in the same swarm; direct provider
execution still requires local ownership. Owner readiness/result phases bind the
full forwarding digest, permit, operation, object, action and time. The gateway
verifies bytes and upload FIN, then signs validated replies with its own key.
Transport rejection vectors and the existing direct/native-owner regressions pass.
The complete consumer/gateway/different-owner workflow and independent-process
failure proof remain unverified; the existing native-owner test dispatches after
real frame reception and does not exercise the new gateway's forwarding branch.

#### Signed backup conversation

Allocation discovery precedes capability issuance. `FetchFederatedBackupAllocations`
and `FederatedBackupAllocationPage` use envelope tags **55–56**. The consumer
selects a storage grant from signed authority pages and requests allocations
large enough for one complete encrypted object. The request contains the grant,
required bytes, optional opaque continuation and maximum page size. The signed
reply binds the canonical request digest and exact metadata revision, returning
complete backup scopes, quota ceilings and validity intervals. It contains no
provider paths, decryption material, free-space promise or storage receipt.

Discovery uses the existing grant/state/interval/allocation index and revisits
current bilateral authority for each candidate. It does not reserve capacity.
Results are ordered by interval start, interval end and allocation ID. The opaque
canonical continuation binds relationship, authority epoch, grant, required size,
snapshot revision and the last visited key. A changed revision invalidates the
continuation; a stale grant never becomes permission merely because its cursor
was previously valid. Ineligible candidates may produce a short or empty page
with a continuation, which still advances beyond the examined candidates.

Allocation-fetch, allocation-page and query-digest signatures/hashes use separate
NUL-terminated domains `meshspan.federation.backup-allocation-fetch.v1`,
`meshspan.federation.backup-allocation-page.v1` and
`meshspan.federation.backup-allocation-query-digest.v1`. Signed header correlation,
current peer identity, replay, per-record scope, page ordering and monotonic
continuation are validated. Request/reply framing shares the negotiated session
bounds; page sizing also reserves room for the signed envelope and cursor.
Discovery identifies non-local provider nodes without pretending that the paired
gateway is their owner. Native execution/routing to those nodes remains an
implementation requirement, not an implicit local-only restriction.

`FederationEnvelope` tags **50–54** carry `RequestFederatedBackupCapability`,
`FederatedBackupCapability`, `ExecuteFederatedBackup`, `FederatedBackupReady`
and `FederatedBackupResult`, respectively. They never contain a same-swarm
`RequestHeader` or an invented shard identity. The request includes the complete
scope and operation; its embedded operation ID and deadline must equal the signed
federation header. The provider response binds the exact request digest, and
execution presents the complete provider-MACed permit.

Ed25519 signatures use these distinct domains (each terminated by a NUL byte):

- `meshspan.federation.backup-capability-request.v1`
- `meshspan.federation.backup-capability.v1`
- `meshspan.federation.backup-execute.v1`
- `meshspan.federation.backup-ready.v1`
- `meshspan.federation.backup-result.v1`

The signed bytes are the domain, big-endian u64 canonical-header length, canonical
header, big-endian u64 unsigned-body length and canonical body with only its outer
signature cleared. Capability-response correlation is SHA-256 over the separate
NUL-terminated `meshspan.federation.backup-capability-request-digest.v1` domain and
the u64-length-prefixed unsigned request. This transport digest is distinct from
the BLAKE3 request/MAC contract above. Peer identity, current relationship,
correlation, lifetime and replay checks precede acceptance. Results cannot bypass
the successful-ready phase; receipts must match the requested action and object.

Capability issuance holds no capacity. Execution rechecks the provider MAC and
current relationship/grant/allocation before provider IO. A store's allocation
and physical capacity admission must precede its successful ready response.
Issuing a capability or sending ready is not durable storage evidence.

Execution uses one federation bidirectional stream. After signed execution and
successful ready, store/read bodies use existing bounded `DataFrame` records with
contiguous offsets, not Protobuf control-message payloads. For uploads, the exact
declared length and digest plus the sender's clean QUIC FIN are required before
the provider receives end-of-input. Truncation, extra bytes, reset, wrong offsets
or a mismatched digest are not a successful upload. Exact stored retries may
avoid another disk write but still validate the presented stream. Reads finish
with a signed exact measured result after the declared bytes; verify/delete
return signed results without a byte body. A rejected ready never invites bytes.
Lookup follows the same capability, ready and signed-result sequence without
bytes: `RemoteBackupAction` **5**, request-digest action tag **5**, and
`FederatedBackupResult.looked_up` outcome tag **15**. Its reference must be empty
and retirement revision absent in the request. The response must match lookup,
its operation and its exact object; a store/verify receipt cannot substitute for
the lookup outcome. Current bilateral authority and physical-owner checks still
apply, including when a gateway relays to a distinct provider node.

The blocking-worker execution adapter bounds each frame and every network wait.
It rechecks current authority, including the complete peer and local signing/TLS
identity bindings, during transfer, before exposing end-of-input and before
sending a result. Rotating either identity fences already authenticated requests;
an unchanged relationship epoch or valid permit MAC does not preserve a retired
key's authority. Its monotonic deadline also prevents a stalled peer
from waiting forever when an injected mesh clock does not advance. Provider IO
must remain under a bounded owned worker; cancelling a network wait never implies
that durable effects were undone.

**Integration status:** signed wire validation, transport authentication, current
metadata capability issuance/admission and the blocking provider execution adapter
are implemented. Native paired sessions dispatch allocation discovery, capability
issuance and execution against allocations on their own node. Discovery and
issuance share authority-fetch control workers; byte execution has a separate
CPU-derived bulk-worker budget and metadata-reader pool. Their
node-local process MAC key is retired on restart: consumers obtain a fresh
permit before an exact retry; that retirement does not invalidate durable
provider receipts. Native execution resolves only an exact live registered target,
checks its health and shares its actual folder-capacity owner. Allocation and
physical budgets are intersected before inviting upload bytes. A bounded cache
retains one exclusive catalogue per physical backup namespace; its identity is
independent of permission revisions. A changed authority scope reopens that same
namespace under the exclusive owner. Withdrawn targets retire idle catalogues;
in-flight owners finish before retirement. Busy namespaces reject admission
rather than occupying workers waiting behind another transfer. Neither inventory
nor maintenance locks span network IO.

Provider maintenance now provisions allocations from already approved storage
grants and eligible live folders, one grant/target decision per tick. Planning
is read-only; an existing typed consensus command with a metadata revision fence
commits the allocation. Discovery never mutates authority. Allocated quota remains
charged until safe reconciliation; measured free space is advisory until transfer
admission. Consumers select an admitted allocation and retain immutable routing.

Reconciliation of assigned quota, forwarding to other provider nodes, automatic
cross-swarm process-level delivery/restart/failure acceptance remain open. Local execution is an
implemented slice, not a local-only product restriction. The supplied clock must
be trustworthy mesh time; the current native OS-clock composition does not yet
establish clock quorum itself.

### Update readiness observations

`ProbeUpdateReadiness` and `UpdateReadinessResult` use control envelope tags
**118–119**. Requests name an active signed rollout, the exact root quorum-plan
digest and a minimum applied log index. The normal header binds mesh, root
partition, current mTLS sender/incarnation and the operation. Request lifetime
is at most five seconds; responders do not forward requests or append to Raft.

The response echoes the rollout and reports the current node/incarnation, active
plan, applied/committed positions, persistence-blocked state, listener-bound
state, observation time and the canonical executable runtime report (at most
8 KiB). Applied position cannot exceed committed position. The runtime report
contains public build/format information, never private keys or configuration.
The sender's current certificate/incarnation and active publisher trust are
checked before a fresh observation is obtained from the actual reactor.
The responder rejects a changed plan or an unmet minimum applied index.

Response field **11**, `local_content_scan`, optionally carries the update
worker's historical local-catalogue progress. It binds the excluded candidate
node/incarnation, preparation sequence/log index, source metadata revision and
scan observation time, with checked volume/publication/stripe counts, the current
volume (if any) and excluded target count. States are `checking`,
`local_content_checked` and `unavailable`; unspecified/unknown states, malformed
identities, zero binding fields, a barrier beyond the responder's applied index
and a scan timestamp after the enclosing observation are rejected.

The responder omits a scan whose rollout, candidate, incarnation, preparation
sequence/barrier or metadata revision no longer matches its local authoritative
view. Missing means unknown, not ready. Reading this projection never starts
provider work or waits for a scan; the control path copies bounded state from
the separately owned update worker. These counters cover that node's committed
content catalogue only. Even `local_content_checked` is historical, not a fresh
publication fence, decryption/gateway proof, whole-mesh inventory or restart grant.

These are **observations, not restart authorisation**. Listener-bound state
means the current service cycle bound HTTPS, HTTP-01 and SMB; it is withdrawn
before normal shutdown and on exceptional exit. It does not prove that every
volume remains decodable, that a remote gateway is reachable by a particular
client, that the caller has a quorum, or that the selected new executable is
running. Coordinators must bind response identity and operation, apply a local
request deadline and independently enforce the restart/data-availability gates.
Remote wall-clock timestamps alone do not establish freshness. A response timeout
is absent evidence, never a successful probe.

Restart preparation is a separate replicated `Preparing` checkpoint (metadata
command format **5**, phase discriminator **6**). Its actual committed log index
is retained as the node's fixed catch-up barrier. It reserves the single restart
slot but does not stop services. `Restarting` requires that preparation and fresh
observations meeting its fixed index and the current quorum plan. Unrelated later
writes do not move the barrier. A failed preparation can be retried without
claiming a process restart; an already admitted ambiguous restart retains its
reservation until verification. These root-log checks do not replace workload,
locality or delegated-group availability checks.

The initial coordinator probes surviving stable/joint voters concurrently under
one two-second monotonic deadline. A failed/cancelled read evicts its uncertain
cached connection; one retry of that read may use the remaining half-budget after
a peer's self-exec. Only identity/operation/plan/barrier-bound serving observations
enter the witness, never timeouts. This does not retry metadata mutations. The
automatic installation path currently requires explicit interruption consent;
uninterrupted installation awaits the separate all-scope availability gates.

### Signed executable distribution

Software-update bytes use the same private data stream, not consensus payloads
or shard capabilities. `GetUpdateArtifactRequest` (envelope tag 80) carries a
normal request header and `UpdateArtifactIdentity`: rollout UUID bytes (16),
signed platform (one of the four supported Linux/macOS architecture targets),
positive byte length (at most 8 GiB) and SHA-256 digest bytes (32).

The source validates the current same-swarm node/incarnation and leaf certificate,
root partition, deadline, selected candidate signature and current publisher
enablement before opening a cached executable. The request identity must equal
the signed manifest's platform entry; an advertised location/hash alone is not
authority. No host path or executable URL is accepted from the requester.

`GetUpdateArtifactHeader` (81) repeats that exact identity. Contiguous bounded
`DataFrame` records carry the bytes. `GetUpdateArtifactResult` (82) repeats the
identity after the sender has independently counted/hashed the stream. The
receiver requires exact header/result bindings, length, offsets, hash and EOF
before publishing its local fsynced cache entry. Transport loss/reset means no
complete transfer, not successful installation. A new attempt starts the bounded
immutable transfer again; partial-range resume is not claimed by this version.

Only a subsequent authoritative source-publication command advertises the new
cache. Neither the transfer result nor that source receipt marks a node ready to
restart or proves software installation. A cancelled rollout or disabled signer
cannot authorise new transfer preparation/publication.

## 12. Repair and drain coordination

- `ClaimWork` returns a leased, fenced repair/scrub/drain task.
- `RenewWork` extends the same claim only while its fence is current.
- `ReportWorkProgress` is advisory and bounded.
- `CompleteWork` submits receipts and expected revisions for the authoritative
  state transition.

The durable job remains in metadata; peer-to-peer messages do not create a
second scheduler truth.

## 13. Certificate and secret distribution

Private node renewal is separate from public endpoint issuance. The version-4
authoritative command envelope carries these closed command kinds:

| Kind | Command                                  | Ordered payload after the kind                                                                                          |
| ---: | ---------------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
|   77 | `StageNodeCertificate`                   | node ID, incarnation, previous generation, new generation, issuer generation, bounded leaf DER, valid-from, valid-until |
|   78 | `AcknowledgeNodeCertificateInstallation` | node ID, incarnation, generation, leaf fingerprint, staging revision, bounded node signature                            |
|   79 | `RetireNodeCertificate`                  | node ID, incarnation, rotation generation                                                                               |

IDs and fingerprints are fixed 16/32-byte fields; counters are big-endian u64;
times are signed microseconds aligned to seconds. DER is at most 65,536 bytes;
the canonical P-256 DER signature is at most 72 bytes. Existing envelope context,
operation/digest replay, authority checks and trailing-byte rejection apply.
Durable operation kinds are 141–143. Unrecognised kinds fail closed; there is no
mixed-version compatibility promise.

Staging requires the next generation, exact current incarnation, unchanged
node-owned public key, current online issuer, exact node DNS name and an explicit
lifetime of at most 30 days. It does not select the new local identity. The
installation signature covers the domain-separated node/incarnation/generation/
fingerprint/staging-revision statement. Acknowledgement selects the replacement
and starts one hour of old-leaf overlap; retirement cannot run before that deadline
or before installation. An expired uninstalled candidate can instead be abandoned;
the previous active leaf is left unchanged. A subsequent attempt uses the next
unused generation, not the abandoned number. No private node key enters a command. The transport accepts
only the exact current and optional overlap fingerprint for that incarnation.
Automatic voter and storage-only renewal/restart evidence is recorded in
[Stage 10](stage-10-evidence.md#storage-only-private-certificate-renewal); those
scenarios are not proof of every certificate/recovery failure lifecycle.

Only the elected, fenced certificate worker completes ACME HTTP-01 or DNS-01.
After issuance it submits a certificate bundle encrypted separately for each
authorised node identity. Messages are:

- `PublishCertificateBundle` with public metadata and per-node envelopes;
- `FetchCertificateEnvelope` for the caller's node and bundle generation;
- `AcknowledgeCertificateInstall` with the installed public fingerprint; and
- `RevokeCertificateEnvelope` / rotation state changes.

HTTP-01 gateways also use `FetchHttp01Challenge` and `Http01ChallengeResult` on
the authenticated same-swarm control stream. A request contains one base64url
token (1–128 bytes). A result echoes that token and contains either no proof, or
its bounded ASCII key authorisation (at most 512 bytes) plus original exclusive
expiry. Body and expiry must be present together. Replies bind the request's
operation ID and exact token; transport binds node, incarnation and swarm.
These messages expose no account key, provider settings or full order checkpoint.

Gateways serve the local publisher's catalogue or an indexed projection of an
already replicated publication checkpoint. Only published/notifying/polling
material is projected: preparation, cleanup and retirement are not permission
to republish. A local miss may query the known leader; during leader discovery,
the bounded durable voter set is queried, not every storage node. Responders
only read their own checkpoint and never forward, preventing relay loops.
There are no CA requests or Raft mutations on this path. Anonymous lookup work
has bounded admission and a two-second total deadline. Unavailable routing
returns `503`, not fabricated absence. Startup certificate installation status
does not by itself establish private-route readiness. This public proof lookup
is not a linearizable metadata read or a grant to perform certificate work.

The private key is never broadcast in plaintext or made readable through a
metadata query. Public challenge settings and non-secret status may be
replicated normally.

## 14. Enrolment boundary

An unenrolled node has no private-protocol certificate, so initial enrolment is
an HTTPS API flow. It presents a short-lived, single-purpose join grant and a
locally generated public key. The quorum consumes the grant atomically, admits
the node and returns a mesh certificate chain plus bootstrap peers. The private
key never leaves the joining node. Subsequent activation and topology changes
use the private protocol.

## 15. Versioning and bounds

- Major-version mismatch refuses the connection. Minor versions negotiate
  explicit feature bits.
- Unknown fields are preserved or ignored according to Protobuf rules; unknown
  command variants are rejected, never guessed.
- Every repeated field, string, frame, stream count and in-flight byte total has
  a negotiated bound.
- IDs have fixed canonical byte forms. Timestamps are UTC instants plus explicit
  durations; wall clocks never order consensus events.
- Compression is opt-in per safe message family and never applied to secrets.

## 16. Implementation order

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
