# Federation between autonomous swarms

Status: **accepted contract; Stages 0–5 complete**.

Federation lets independently administered MeshSpan swarms share selected data,
write authority and storage without combining their consensus groups or user
databases. A business may operate one swarm across every site, several autonomous
shop swarms governed by a head-office swarm, horizontal partner swarms, or a
mixture of those arrangements.

## Simplicity contract

The ordinary product flow is:

1. connect another swarm with a short-lived, mutually approved code;
2. select a volume, folder or file;
3. select the other swarm and choose `view`, `edit` or `manage`; or
4. offer remote capacity and choose whether it may serve ordinary reads.

Backup/protection placement uses the same remote-capacity model. A policy such as
“store in at least three partner swarms” may spread encrypted shards across five
eligible partners without asking the user to place individual chunks. Detailed
rights, quotas, offline duration and placement constraints live under advanced
controls. Users never choose federation logs, merge heads, keys, leases or
consensus roles.

## Relationship graph

Federation is a graph of explicit relationships:

- **horizontal** relationships connect autonomous peer swarms;
- **governance** relationships let one governing swarm place mandatory ceilings
  and policy on one subordinate swarm;
- **mixed** deployments combine both forms.

A subordinate has at most one immediate governing parent. Governance may have
several levels but must be acyclic. Horizontal sharing and storage relationships
may be bidirectional or cyclic because they grant capabilities, not authority over
the peer's consensus state.

Every swarm keeps its own consensus, metadata partitions, users, groups,
authentication methods, encryption roots and recovery material. Consensus never
spans a federation relationship. One swarm being unavailable cannot prevent an
otherwise authorised peer from committing work inside its durable offline grant.

## Scale-out boundary

Federation is also the deliberate scale-out path for deployments whose combined
metadata, membership or failure-domain load should not live in one consensus
system. Ordinary operations contact only the accepting swarm's local authorities;
they never synchronously enter every related swarm's log. Signed branches,
receipts and policy updates cross federation links asynchronously.

There is no fixed size at which a user must federate. A swarm starts with one root
control Raft owning every scope and may later delegate loaded operation families,
volumes or explicit subtrees to independently routed groups when it has enough
eligible members. The root retains swarm-wide authority but does not confirm
delegated mutations. A larger organisation may additionally distribute ownership
among several swarms. A heavily shared scope still creates merge and ACL work for
its owning swarm, so federation does not make that authority free.

## Identity, trust and restrictions

Every swarm has a globally qualified identity and rotating federation-signing
identity chained to its recovery root. Users authenticate only with their home
swarm; API keys, factors and raw sessions are never copied to another swarm.

Connecting swarms requires approval by an administrator on both sides and
verification of the remote swarm identity. Each side may impose restrictions.
Effective authority is the intersection of:

- the owning swarm's export and resource policy;
- every governing-swarm ceiling in the delegation chain;
- the consuming swarm's local policy; and
- the exact remote user's or group's active grant.

For example, one swarm may offer 100 GB while the other limits itself to 50 GB;
the effective limit is 50 GB. A subordinate may make narrower local decisions
without asking its parent, but neither it nor a peer may expand an upstream or
remote grant.

A share from Swarm A targets Swarm B rather than importing B's principal
directory into A. B decides which of its users and groups receive equal or
narrower rights. B may re-export through B to Swarm C within the same or narrower
envelope, because B could already copy readable data; C does not thereby gain a
direct relationship or connection right to A. Every hop remains attributable and
inherits upstream expiry, revocation, ownership and restrictions.

The B↔C relationship authenticates only that immediate transport and service
hop. The immutable route still begins at owner A. C persists the opaque upstream
grant identity but does not import A's or B's consensus rows; B must retain and
validate its full upstream authority before issuing the child grant. Consequently
C can request the shared resource only from B, while B remains accountable to A.

## Resource ownership and multi-writer operation

Every swarm is the intrinsic root principal for each volume, folder, file and
version it owns. From that root authority it may grant rights directly to its
local users and groups, delegate constrained rights to another swarm, or do
both. Those are sibling delegations: ownership is not represented by a synthetic
self-federation relationship or self-grant. Every external re-delegation remains
an explicit, narrowing hop.

Every shared resource retains exactly one such owning swarm. The owner is the
authority for its ACL policy and canonical converged history independently of
where data is stored or which authorised swarm accepted an edit.

The owner also remains authority for the canonical protection promise. A peer
may keep stronger local caches or redundant copies but cannot redefine that
promise. The owner may adopt the peer's signed receipts as evidence.

An `edit` grant permits users from another swarm to create and modify data. While
connected, the swarms exchange authenticated operations normally. While
disconnected, the remote swarm may acknowledge a locally durable signed branch
inside its last valid offline delegation. Reconnection transfers only the missing
causal pages and referenced immutable records, validates the full delegation and
identity history, and reconciles every admissible edit deterministically.

Receipts and status distinguish:

- durable on the accepting swarm;
- accepted into the owning swarm's canonical history; and
- currently satisfying the requested federated protection/availability policy.

No response may collapse those states into an unqualified success.

## Revocation and quarantine

Federation grants carry an offline-validity interval. The simple UI supplies a
safe default and offers shorter, longer or indefinite access; advanced policy may
set an exact duration. Connected swarms renew automatically.

Known revocation stops new access immediately. A disconnected swarm cannot learn
about a revocation until reconnection or expiry, so it may have acknowledged later
local work under the previously valid grant. When authoritative history proves
that work was outside the grant's effective interval, reconciliation must not make
it visible. The immutable content is quarantined for a bounded, audited recovery
period rather than silently destroyed. Only expressly authorised recovery can
restore it as a new operation.

## Federated storage

A storage relationship grants bounded remote capacity rather than namespace
authority. Its placement contract states whether it:

- counts towards a requested remote-swarm/location protection predicate;
- may serve ordinary verified reads; and
- is protection/recovery-only and therefore not counted as immediate availability.

Storage-only swarms receive encrypted shards, integrity metadata and bounded
put/get/retire capabilities. They receive no volume decryption key and cannot
infer filenames or user metadata. Readable data sharing is separate: only
authorised gateways receive scoped, revocable decryption material.

Placement chooses among eligible partner swarms automatically while respecting
each side's quotas, fault independence, restrictions and availability class.
Location alone never grants retrieval or deletion authority. Every accepted
remote write, read, scrub and retirement has a signed, replay-safe receipt.

## Recovery and removal

Loss of contact is not proof that a swarm is permanently gone. Another swarm must
never take ownership merely after a timeout. Owner recovery requires either the
owning swarm's offline recovery material or an explicitly pre-authorised successor
swarm. Both paths create a signed, audited ownership transition that fences the
old authority if it later returns.

Removing a relationship stops known access immediately. Encrypted remote data is
retained or reclaimed according to the agreed retention and cleanup policy; the
relationship's removal is not itself proof that physical bytes were erased.

## Stage retrofit map

| Stage | Required addition                                                                                                   | Implementation evidence                                                                                                                                                                                                          |
| ----- | ------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 0     | Lock federation terminology, authority, simple presets, failure semantics and record/message contracts.             | Complete: logical records, canonical encodings, message catalogue and cross-document threat/flow review are locked.                                                                                                              |
| 1     | Add federation-qualified IDs, rights, restrictions, receipts and versioned replaceable contracts.                   | Complete: domain transitions, hostile vectors, canonical Protobuf fixture and deterministic graph/policy tests pass.                                                                                                             |
| 2     | Persist relationships, trust roots, governance, grants, quotas, recovery succession, quarantine and exact outcomes. | Complete: migrations, typed commands, indexes, atomic receipts, exact historical reads, backup/restore and command/apply crash-boundary proofs pass.                                                                             |
| 3     | Authenticate swarms and carry bounded federation control/data streams over Quinn without joining consensus groups.  | Complete: mutual mTLS connection and identity rotation, durable signed authority synchronisation, replay/fencing, independently framed history objects and a stopped/restarted non-empty import pass over real Quinn.            |
| 4     | Treat partner capacity as a capability-scoped remote provider with placement and availability classifications.      | Complete: encrypted cross-swarm shard IO, bilateral quota enforcement, protection/read classification, signed lifecycle receipts, exact inventory and returning/revoked-provider tests pass over real Quinn/mTLS.                |
| 5     | Authorise remote principals and reconcile signed multi-writer branches into the owning swarm.                       | Complete: real home-session and bilateral-grant admission, signed disconnected edits, restart, paged Quinn history exchange, deterministic preservation, exact encrypted-content healing and durable revocation quarantine pass. |

Stages 6 and later expose these contracts through the appliance UI and access
services, place/repair federated shards, and add full multi-process, churn, power,
soak and performance evidence. They must not invent a second federation model.
