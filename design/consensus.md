# Consensus and quorum system

Status: draft for review.

MeshSpan uses a small, owned, leader-based replicated-log core for authoritative
metadata partitions. Existing Raft implementations and published quorum systems
are design references and adversarial test sources, not assumed to satisfy this
contract.

The core has one job: order bounded, versioned metadata commands safely. It does
not merge filesystem branches, authorise users, transfer shards, run SQL, choose
placement or expose storage to clients.

## Composition boundary

The implementation is a library of small cooperating pieces, not a daemon
framework and not a generic-parameter maze:

- the deterministic core consumes validated events and emits explicit effects;
- quorum compilation and transition proof are pure independent modules;
- membership planning composes proved quorum plans without owning transport;
- a persistence driver durably applies effects before returning confirmations;
- a transport adapter maps authenticated bounded messages to core events; and
- the MeshSpan daemon composes clocks, timers, storage, transport and metadata
  application at its outer boundary.

The current crate may use MeshSpan's opaque identifier types, but it MUST NOT
interpret MeshSpan records or acquire dependencies on SQL, Quinn, Protobuf,
filesystem, storage or API crates. If the core is published independently, its
small identity dependency can be extracted without changing the algorithm or
effect model. Publication, a stable public API and compatibility promises are
not Stage 1 requirements.

## Why a MeshSpan core

MeshSpan requires two capabilities that stock OpenRaft and `raft-rs` do not
currently provide:

- topology-aware flexible and hierarchical quorums; and
- separate election, consensus-write and linearizable-read quorum families,
  including useful even-sized voter sets.

OpenRaft's public roadmap still lists both capabilities as unfinished. Its
current membership implementation evaluates a majority of every member set in a
joint configuration. `raft-rs` is a lower-level consensus core but uses the same
conventional quorum model. Adapting either would change election, commitment,
read-barrier, membership and snapshot safety throughout the core while retaining
an upstream abstraction that does not describe MeshSpan's rules.

The recommended boundary is therefore an owned core informed by:

- Raft's terms, leader discipline, replicated log and understandable state
  transitions;
- Flexible Paxos and FlexiRaft's cross-phase intersection rules;
- ZooKeeper's weighted hierarchical quorum construction;
- OpenRaft's extended membership, durable-store contract, simulation and failure
  history; and
- `raft-rs`'s small deterministic core plus explicit persistence/output loop.

No implementation starts until this contract and its model are reviewed.

## Responsibilities

One consensus group belongs to exactly one metadata partition. It owns:

- durable term and vote state;
- leader election and fencing;
- ordered bounded log replication;
- commit-index calculation under the active quorum plan;
- linearizable read barriers;
- voter, learner and quorum-plan transitions;
- snapshot position, transfer and activation; and
- deterministic events, metrics and fatal-state reporting.

Application code owns command validation, the SQL state machine, operation
idempotency, routing, branch reconciliation and all data placement. A consensus
log entry contains a bounded semantic command or control transition, never file
bytes, shard bytes or an arbitrary SQL statement.

## Quorum-plan model

Every committed configuration carries a versioned immutable `QuorumPlan`:

```text
plan ID and format version
membership epoch
voters and learners
election predicate
commit predicate
read predicate
leader eligibility predicate
compiled minimal quorum sets and proof digest
previous-plan transition evidence, when applicable
```

A predicate is an upward-closed expression over stable voter IDs. The initial
expression language is intentionally small:

```text
voter(node ID)
at_least(k, child predicates)
weighted_at_least(weight, voter weights)
all(child predicates)
```

Nested thresholds express a hierarchy. For example, a plan may require enough
votes inside a building and enough qualifying buildings across a campus. A vote
from one voter is still one durable protocol fact; expression evaluation must
not accidentally count one voter twice where the plan forbids it.

Administrator fault groups may overlap arbitrarily because they also describe
placement risks such as host, room, power circuit and building. A quorum plan is
a compiled projection of that topology, not the raw fault-group graph. The
compiler rejects ambiguous double-counting and any plan that fails the safety
checks below.

## Three quorum families

The protocol distinguishes:

- **Election quorum (`E`)** — may elect one leader for a term.
- **Commit quorum (`W`)** — may durably commit an ordered log position while
  that leader remains valid. `W` is called the consensus-write quorum in APIs to
  distinguish it from an ordinary filesystem write.
- **Read quorum (`R`)** — may confirm the current leader for a linearizable read
  barrier. The leader must also wait until its local state machine has applied
  the returned committed position.

The families may differ. Majority quorums are one valid plan, not a baked-in
algorithm.

For a fixed plan, the compiler MUST prove at least:

```text
for every e1, e2 in E:  e1 intersects e2
for every e in E, w in W: e intersects w
for every r in R, e in E: r intersects e
```

The first rule prevents two same-term leaders. The second preserves committed
history across a later election. The third prevents a stale leader from
completing a linearizable read barrier after another election can complete.

The first release serves linearizable reads only through the current leader and
waits for its applied index. If a later design permits replicas to assemble a
linearizable value directly from read responses, every `R` must additionally
intersect every `W`, and the read algorithm requires a separate proof and model.

The core assumes crash, omission, corruption-detection and partition faults, not
Byzantine voters. Mutual authentication prevents an unauthorised node from being
counted, but a correctly enrolled malicious voter is outside this consensus
model.

## Even-sized voter sets

An even number of voters is useful rather than a permanently awkward setup. A
four-voter flat plan can, for example, use:

```text
E = any 3 of 4
W = any 2 of 4
R = any 2 of 4
```

Every election quorum intersects every commit and read quorum. A stable leader
must durably append locally and participates in the `W` and `R` evidence. It can
therefore commit with one other reachable voter, while electing a replacement
still needs three. In a two-by-two split, the side containing the already valid
leader may continue authoritative metadata work; the other side cannot elect a
competing leader. If that leader is lost, progress pauses until an election
quorum returns.

This is an availability trade, not free redundancy. Receipts report the exact
durability achieved, and a strong data policy may still require more nodes or
zones before acknowledging the associated file version.

One- and two-voter establishment plans use the same algebra and report their
limits honestly. No quorum rule can make a two-node system both elect either
survivor independently and prevent split brain.

## Hierarchical quorums

A hierarchy describes which combinations of topology can make progress. A
three-building example may require a local threshold inside a building and then
a threshold of qualifying buildings. Weighted voters may represent deliberately
different failure or durability properties, but weights are not derived from
CPU speed, free space or current latency.

The automatic planner optimises, in priority order:

1. all safety intersections;
2. survival of the selected machine and shared fault-group scenarios;
3. useful authority during declared building/site partitions;
4. low steady-state commit latency and message count; and
5. balanced voter work.

The normal UI asks about failure survival and places that must remain useful. It
never asks a user to write `E`, `W`, `R`, weights or threshold expressions.
Advanced diagnostics may show the compiled plan and explain which missing voter
or fault group blocks election, commit or a strong read.

## Plan compilation and proof

With at most nine active voters in the initial design, plan compilation is not a
hot-path heuristic. It enumerates voter subsets, evaluates each predicate,
reduces each family to its minimal quorums and proves the required intersections.
It also computes exact minimal cut sets and checks the promised failure
scenarios.

The canonical plan, compiled minimal sets, safety result and proof digest are
stored together. Every voter independently recompiles and verifies them before
accepting the plan. Unknown expression versions or a mismatched digest fail
closed.

Property tests and an independent slow oracle compare the production compiler
against exhaustive truth tables. Formal models cover election, log commitment,
read barriers and reconfiguration; implementation simulation then checks every
message ordering and partition for the bounded model sizes.

## Reconfiguration

Reachability, latency or a failure detector MUST NOT silently change quorum
meaning. A node cannot remove unreachable voters merely to manufacture
authority.

Changing voters or any quorum predicate is an authoritative logged operation:

```text
old plan
  -> add and fully catch up learners
  -> commit joint old+new transition
  -> prove the new plan contains the committed history
  -> commit new plan
  -> retire removed voters
```

During the joint phase, election, commit and read decisions must satisfy the
safe composition of both plans. The transition compiler proves all required
old/new cross-intersections before the first transition record is accepted.
Every protocol message carries the partition ID, plan epoch, term and sender
incarnation; stale epochs and reused identities cannot vote or commit.

A reachable authority may promote a fully caught-up eligible learner and may
transfer leadership before drain or upgrade. Without current authority, nodes
keep serving permitted local filesystem branches and wait; they do not rewrite
the consensus membership around a partition.

## Core shape

The algorithm is a deterministic state machine. It consumes an input and emits
effects; it performs no network, clock, random, SQL or filesystem IO itself:

```text
step(state, input) -> new state, durable writes, outbound messages, timers, events
```

The driver persists required vote/log effects before sending dependent messages
or acknowledging progress. Timers and random election choices are explicit
inputs, allowing virtual time and reproducible simulation. Each peer stream has
bounded independent work so one stalled or hostile peer cannot block the core.

Snapshots contain the applied state-machine image, committed position,
membership epoch, quorum plan and digest. Installation is staged, verified,
atomic and resumable. A snapshot cannot make the receiver forget a newer durable
vote or activate an unproved quorum plan.

## Proof and release gates

The core cannot become an authoritative dependency until it passes:

- executable formal-model invariants for election uniqueness, leader
  completeness, state-machine safety and read-barrier linearizability;
- exhaustive quorum-plan and old/new transition proofs through nine voters;
- deterministic simulations of every partition set for 1–9 voters, including
  repeated heal/repartition and simultaneous elections;
- crash and torn-write injection at every vote, append, truncate, flush, commit,
  apply, snapshot and reconfiguration boundary;
- history checking against a linearizability oracle;
- differential standard-majority traces against at least two established Raft
  implementations where their semantics overlap;
- long-running random schedule, packet loss, duplication, reordering, process
  loss, host loss and disk fault campaigns; and
- real multi-process and multi-machine failover before release.

Any safety counterexample blocks the release. The appliance may fall back to a
previously committed safe plan; it may never weaken the intersection rules to
restore apparent availability.

## References

- [OpenRaft roadmap and feature boundary](https://github.com/databendlabs/openraft)
- [OpenRaft extended membership](https://docs.rs/openraft/latest/openraft/docs/data/extended_membership/index.html)
- [`raft-rs` core boundary](https://github.com/tikv/raft-rs)
- [Flexible Paxos: Quorum Intersection Revisited](https://doi.org/10.4230/LIPIcs.OPODIS.2016.25)
- [FlexiRaft: Flexible Quorums with Raft](https://www.vldb.org/cidrdb/papers/2023/p83-yadav.pdf)
- [ZooKeeper hierarchical quorums](https://zookeeper.apache.org/doc/current/zookeeperHierarchicalQuorums.html)
