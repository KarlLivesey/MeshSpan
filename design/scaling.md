# Scaling and campus availability

Status: draft for review.

MeshSpan scales by adding independent data, gateway, worker and metadata
partitions without making small installations pay for a distributed catalogue on
every operation. One node is the smallest topology of the same model.

## Scaling through federation

One swarm can span many sites, cells and metadata partitions. Federation provides
an additional scale-out boundary when placing all organisational membership and
authority inside one consensus system is no longer desirable. Several autonomous
shop swarms may share with a head-office swarm, or peer swarms may share directly,
without any operation entering a federation-wide Raft group.

Consensus load remains local: an accepting swarm durably records its own work and
cross-swarm branches and receipts propagate asynchronously. The owning swarm of a
shared scope still performs its canonical merge and ACL work. Very large
deployments therefore distribute ownership across volumes or explicit subtree
boundaries rather than sending every namespace through one nominal owner.

Federation is not forced at an arbitrary node count. Operators choose one larger
swarm or several federated swarms according to administrative, failure, latency
and load boundaries. Both use the same filesystem and sharing semantics. See
[`federation.md`](federation.md).

## Availability cells

An availability cell is a locality expected to retain internal connectivity
during a wider outage, such as a building, store or campus zone. A useful cell
has:

- local HTTPS/SMB gateways;
- local storage for the data it promises to serve during isolation;
- a proved local quorum plan for its owned metadata partitions; and
- cached signed identity/configuration and routing revisions.

Cells are not hidden failure domains. Buildings, circuits, rooms, switches,
hosts and devices remain explicit overlapping fault groups used by placement.

## Metadata partition types

```text
Catalogue partition
  mesh membership, partition routing and global policies

Identity/configuration partition
  principals, groups, authentication and mesh-wide desired configuration

Namespace partitions
  volume/subtree namespace, handles, manifests and lifecycle authority
```

Small meshes may co-locate all scopes in one partition and voter set. The IDs and
routing records still exist, so growth is an online ownership movement rather
than a database-format conversion.

The first practical split is one namespace partition per large volume or
availability cell. Subtree partitioning is permitted later behind explicit
mount/ownership boundaries; arbitrary per-file sharding would make rename,
listing and permissions needlessly expensive.

This is a hierarchy of routing and ownership, not nested commit confirmation.
The catalogue tells gateways which independent Raft group owns a scope, but that
group commits its ordinary operations without appending through a parent log.
Automatic volume-level partition creation and measured subtree split/merge are
future optimisations. MeshSpan may eventually recommend and, where policy permits,
perform a subtree split after sustained measured load; it must not create a
consensus group for every ordinary folder by default.

The exact load signals, hysteresis, minimum partition size, split/merge cost model
and automatic-action policy remain open design item O-008. Those details require
measurement and deterministic safety proofs rather than an invented threshold.

## Building disconnection

Suppose a university mesh has one cell per building. When Building A loses the
campus uplink but its internal network remains:

- A's gateways continue serving converged namespace operations where a voter
  majority is reachable and local branch operations wherever valid cached
  authorisation, required base bytes and writable storage remain;
- other buildings continue serving their own and campus-authoritative
  partitions where they retain quorum;
- cached committed identity/configuration may authorise bounded ordinary access
  in A according to policy;
- campus-wide administration, new users, routing changes and cross-cell
  operations may pause;
- other disconnected buildings may advance their own ordinary filesystem
  branches for the same scope but cannot mutate A's control state or converged
  head;
- reconnect triggers log catch-up, branch exchange, deterministic merge,
  routing refresh, inventory reconciliation and repair automatically.

Thus one building outage does not grind the campus to a halt. The isolated
building remains useful for local work, and every durable branch is an honest
acknowledged history until automatic convergence includes it.

## The consistency boundary

Disconnected components cannot both promise that their new value is already the
single globally current value. MeshSpan instead makes the branch contract
explicit: both may durably accept ordinary filesystem work, both state their
local receipt scope, and neither claims global convergence.

On reconnection, causal operations and changes to different objects merge
without user involvement. Incompatible concurrent changes to the same name or
binary content cannot be semantically combined in general, so MeshSpan chooses
one visible result deterministically and preserves every alternative as history
and, where needed, a conflict sibling. The namespace converges automatically;
only the human meaning of a genuine content collision can remain for a user to
inspect. See [`disconnected-writes.md`](disconnected-writes.md).

## Identity during isolation

Cell gateways keep a signed committed identity/configuration snapshot and the
revision required by local namespace partitions. Existing users can authenticate
and exercise already committed rights for a bounded configurable isolation
window. Local filesystem commits record the identity revision used.

Identity administration remains with its owning partition. A remote user disable
cannot reach an isolated cell instantly; policy therefore defines the maximum
staleness allowed for ordinary access and may require live identity authority for
privileged actions. Break-glass and administration do not use stale authority.

## Routing

The catalogue publishes a signed routing epoch mapping scope IDs to partition
IDs, voter identities and handoff state. A gateway routes directly after path
resolution and caches entries by epoch. Stale routes receive an authenticated
`moved` result containing a newer signed route or require catalogue refresh.

Routing never depends on IP as identity. No operation broadcasts to all
partitions. Listings stay within a partition or use explicit bounded fan-out at
declared mount boundaries.

## Online partition movement

```text
planned -> destination learner -> snapshot copied -> caught up
        -> source frozen/fenced -> ownership committed -> destination active
        -> old source retired
```

The catalogue commits one handoff epoch. The source remains sole writer until a
fence position, then stops. The destination proves it has that position before
becoming sole writer. Failure resumes or aborts according to the committed
handoff state; both never accept writes simultaneously.

## Cross-partition operations

Same-partition namespace operations remain one transaction. Cross-partition copy
creates new CoW references/data under a durable operation and publishes the
destination before optionally unlinking the source. Cross-partition rename is
not reported atomic unless a future transaction protocol proves it; initial APIs
return a clear unsupported/unavailable result rather than expose half a rename.

## Growing resilience

- Automatic voter plans normally grow through stable 3, 5, 7 and 9 tiers on
  independent eligible hosts, while first-class even-sized plans use separate
  election, consensus-write and read quorums where the topology and declared
  failure scenarios benefit.
- Gateways can run in every cell against the same APIs and credentials.
- Storage placement distributes stripes across eligible independent domains and
  keeps repair alternatives outside each protected failure union.
- Work queues are partition-local with global summaries, avoiding one scheduler
  bottleneck.
- Adding capacity never silently reduces an existing protection promise.

A large mesh can therefore require a major correlated outage before campus-wide
service is lost, while a failure contained to one cell has contained impact.

## Recovery

As links and nodes return, each partition independently re-establishes leader,
catches up followers, validates its routing epoch and resumes. Storage inventory,
protection and configuration reconciliation follow the authoritative namespace
roots. Repair begins wherever risk exists and cancels redundant work safely when
verified original shards return.
