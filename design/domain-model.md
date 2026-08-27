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
├── Principals (users and groups)
├── Volumes
│   └── Namespace objects (folders and files)
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

Every mutable aggregate has an unsigned revision. Commands that can race supply the expected
revision; mismatches fail rather than merge implicitly.

## State ownership

| State | Authority | Durable location |
| --- | --- | --- |
| Consensus vote, log and snapshot progress | one voter locally, replicated by Raft | voter consensus store |
| Mesh, identity, namespace and catalogues | committed metadata state machine | every voter metadata store |
| Node private identity and decryption keys | owning node only | daemon state directory |
| Storage path and provider recovery journal | owning node only | daemon state and registered folder |
| Immutable shard bytes and provider tombstones | owning storage target | registered folder |
| Connection, heartbeat and latency observations | observing process | memory or bounded node-local state |
| Staging bytes | write-owning gateway/storage nodes | node-local staging journal until resolved |

Derived caches are disposable. They never become the only copy of an acknowledged fact.

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

A namespace object is a stable folder or file identity. Directory entries bind a parent and
canonical name to an object. Initial MeshSpan permits one parent per object; the separation leaves a
deliberate future boundary for hard links without implying they already work.

A file version is immutable and contains logical length, content digest and a protected manifest
root. Publishing atomically changes the file object's current version. Rename, tags, owners and
permissions change object metadata without creating a content version.

## Authority and receipts

Every mutation has an operation ID stable across retries. A committed receipt contains the
operation ID and committed Raft position. A wire request ID identifies only one attempt.

Outcomes are:

- `committed`: the typed result is authoritative;
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
