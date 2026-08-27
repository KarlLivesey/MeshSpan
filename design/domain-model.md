# Domain model

Status: **draft for review**.

## Identity hierarchy

```text
Mesh
├── Host (physical machine)
│   └── Node (one daemon identity)
│       ├── Gateway capability
│       ├── Voter capability
│       └── Storage target (registered folder)
├── Fault groups (overlapping sets of hosts or targets)
├── Availability cells (local service/quorum placement domains)
├── Metadata partitions (single-authority record scopes)
├── Principals (users and groups)
├── Volumes
│   ├── Current immutable namespace commit
│   ├── Snapshot roots
│   └── Namespace objects (stable identities with immutable revisions)
│       └── Immutable file versions
│           └── Stripes
│               └── Shard generations and locations
└── Background work, certificates and audit history
```

A host is not a daemon. Multiple daemon nodes on one host share the host's physical failure groups.
A storage target is not a disk: it is one registered folder with a stable identity and observed
backing-device/filesystem identities.

## Stable identifiers

All externally meaningful entities use application-generated 128-bit identifiers. Database row
numbers and paths are never identities. IDs are validated by domain type and cannot be reused after
retirement.

Every mutable control aggregate has an unsigned revision. Commands that can race supply the
expected revision; mismatches fail rather than merge implicitly. Filesystem CoW operations instead
name causal base commits; concurrent outage branches reconcile through the explicit merge contract.

## State ownership

| State | Authority | Durable location |
| --- | --- | --- |
| Consensus vote, log, quorum plan and snapshot progress | one partition voter locally, replicated by that consensus group | partition voter consensus store |
| Mesh, identity, namespace and catalogues | owning committed metadata partition | voters of that metadata partition |
| Filesystem outage branch commits, receipts and debt | originating node/cell until inclusion | per-partition local branch store and referenced storage targets |
| Component selections, desired configuration and revision history | owning committed metadata partition | voters of that metadata partition |
| Node private identity and decryption keys | owning node only | daemon state directory |
| Storage path, socket binding and provider recovery journal | owning node only | daemon state and registered folder |
| Immutable shard bytes and provider tombstones | owning storage target | registered folder |
| Connection, heartbeat and latency observations | observing process | memory or bounded node-local state |
| Staging bytes | write-owning gateway/storage nodes | node-local staging journal until resolved |

Derived caches are disposable. They never become the only copy of an acknowledged fact.

## Availability cells and metadata partitions

An availability cell is a placement domain intended to keep useful work local
during a wider network outage, for example one university building. It does not
replace fault groups: a building may contain several rooms, circuits and hosts,
and a host may participate in services for several cells.

A metadata partition owns one converged consensus head and its control records. Every
mutable aggregate has one owning partition ID. Small meshes start with one partition;
larger meshes may place volume/subtree partitions with voter majorities inside
their availability cells while a separate catalogue/identity configuration
partition changes less frequently.

A signed routing revision maps scope IDs to partition IDs and voter endpoints.
Gateways cache it and contact an available local partition when possible. If no
majority is reachable, ordinary authorised filesystem mutations may still
publish immutable local branch commits. They do not change partition routing,
identity, permissions or the converged head. A partition move uses a fenced CoW
handoff; two partitions never own the converged head for the same scope.

On reconnection, the owner validates and deterministically merges every eligible
branch. Independent operations commute; incompatible same-object edits preserve
all acknowledged versions under deterministic conflict rules. This gives both
sides useful offline work without inventing two control-plane authorities.

## Replaceable components

A component implementation is code that satisfies one versioned internal
contract. A component instance is authoritative metadata selecting an
implementation plus validated configuration for a scope. A node binding is the
local path, socket, private key or other machine-specific material used to realise
that instance.

```text
contract -> implementation -> configured instance -> node binding/observation
```

These identities are separate. Changing the administration panel does not
change mesh records. Changing an access connector does not change a volume or
filesystem manifest. Changing a storage provider does not change namespace
semantics or make its local locator authoritative.

## Fault model

Fault-group classes describe risks such as machine, backing device, PSU, circuit, rack, room,
network switch or building. Fault groups are instances such as `room/upstairs` or `psu/shared-2`.

A target's effective group set is the union of its direct groups and all groups on its host. Groups
may overlap and need not form a hierarchy.

A protection policy is a set of required scenarios. Each scenario contains simultaneous terms:

```text
Scenario A: any 2 groups of class machine
Scenario B: any 3 groups of class backing-device
Scenario C: any 1 room plus any 1 power-supply
```

A layout satisfies a scenario only if enough distinct shards remain after the union of every
selected failed group's members is removed. It satisfies a policy only if it satisfies every
scenario.

## Namespace and content

A namespace object is a stable folder or file identity. An immutable object
revision contains its metadata plus a file-version or directory-block root. An
immutable namespace commit binds one root object revision and one or more causal
parents. A branch head selects a locally current commit; the volume head selects
the current globally converged commit.

Directory blocks bind canonical names to child object revisions. Updating a path
creates new blocks and object revisions only along that path. Initial MeshSpan
permits one parent per live object identity; the separation leaves a deliberate
future boundary for hard links without implying they already work.

A file version is immutable and contains logical length, content digest and a protected manifest
root. Publishing creates a new object revision and namespace commit. Rename,
tags, owners and permissions similarly create metadata revisions without
rewriting file content.

A user snapshot pins a namespace commit. A metadata backup packages replicated
authority for disaster recovery. A consensus snapshot compacts replicated-log history.
They share immutable techniques but are not interchangeable authorities.

## Authority and receipts

Every mutation has an operation ID stable across retries. A receipt contains the
operation ID, durability/consistency scope and supporting evidence. A converged
receipt also contains its committed consensus position. A wire request ID identifies
only one attempt.

Outcomes are:

- `branch_committed`: filesystem result is durable at its exact local/cell scope;
- `globally_converged`: the owning partition head includes the operation;
- `policy_committed`: every declared strong acknowledgement predicate is met;
- `rejected`: no authoritative mutation occurred;
- `unknown`: the caller must query by operation ID;
- `staged`: private recoverable bytes exist, but no published file is claimed.

There is no generic successful boolean for a mutation.

## Fencing

Node processes, filesystem handles, work claims and certificate orders have monotonically
increasing fencing tokens issued by metadata authority. A later token invalidates every earlier
holder. Local wall clocks never create authority.

## Bounds

Every collection crossing a process boundary is paged or size-bounded. Work items name one bounded
unit. No request may require a scan of all nodes, namespace objects, shards, users or audit events.
