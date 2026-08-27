# Consistency and acknowledgement policies

Status: draft for review.

MeshSpan separates a write being durable somewhere from it being converged and
protected everywhere the policy requires. A scope chooses an acknowledgement
policy; the receipt states exactly which promise was achieved.

“Zone” is the user-facing word for an availability cell such as Home, Office or
Building A. Policies store stable cell IDs; users see their chosen names.

## Two consistency classes

### Eventual convergence

This is the normal availability-first class. A write is acknowledged after its
minimum local durable threshold is met and one immutable branch commit selects
the verified data. Distribution, merge, erasure protection and regional copies
continue asynchronously and automatically.

The default minimum is one durable local target. A policy may strengthen that
local acknowledgement to several distinct nodes or a local failure-domain
proof without turning unrelated remote zones into dependencies.

### Strong publication

A strong operation is acknowledged only after all declared data-placement
conditions have durable verified receipts and the owning metadata partition
atomically commits the manifest and converged namespace head. That final
metadata transition is ACID and linearizable.

The data bytes do not participate in one cross-machine SQL transaction. They are
first installed immutably and flushed on every required target; the ACID
metadata commit then makes exactly that receipt set visible or makes none of it
globally visible. Unpublished bytes remain safe staging/branch data and resolve
idempotently.

Strong publication intentionally waits when one of its declared requirements or
the metadata majority is unavailable. This does not disable normal local work:
the caller may explicitly permit fallback to an eventual branch receipt, or
leave the strong operation pending. An access adapter must not silently choose.

## Policy shape

An acknowledgement policy is inheritable at volume, folder or file scope:

```text
consistency class: eventual | strong

minimum durable targets: integer
minimum distinct nodes: integer
required protection scenario IDs: set
strong-wait deadline and explicit fallback rule

zone requirements:
  zone ID -> required_before_commit | eventual | excluded
  each required zone may have its own minimum targets/nodes/protection
```

Only `required_before_commit` zones hold the strong barrier. An `eventual` zone
receives durable replication debt and catches up automatically; it does not
delay acknowledgement. The advanced, rarely needed `excluded` role makes a zone
ineligible for placement. Thus a file may require Home and Office before commit
while Archive and Lab catch up later.

Counts never manufacture independence. Two targets on one host count as two
targets but one node and one machine fault domain. A receipt satisfies a zone or
failure scenario only after the placement evaluator proves it from the exact
target generations and membership revision.

## User experience

The predicate model is primarily an internal contract. Normal setup presents a
small set of plain-language choices with a topology-aware recommendation:

```text
Keep working during outages (recommended)
  Save locally, then protect and copy everywhere automatically.

Wait for protected storage
  Say saved only after the selected failure promise is met.

Wait for selected places
  Say saved only after the chosen required places confirm.
```

The system derives target counts, node independence and placement evidence. It
shows a one-sentence consequence before applying a policy, for example “writes
will wait if Home or Office is unreachable”. Raw predicates, per-zone overrides
and the rarely needed `excluded` mode live under an Advanced view/API. Users
never select shard locations or erasure geometry.

New meshes default to availability-first eventual convergence. Adding a node or
zone produces a recommendation; it never silently changes the meaning of an
existing acknowledgement policy.

Examples:

```text
Normal documents
  eventual; 1 durable target; all configured zones catch up

Office working set
  eventual; 2 durable targets on 2 nodes within the local zone

Critical records
  strong; Home and Office required; survive any 2 machines in each;
  Archive and Lab eventual

Campus release image
  strong; every zone marked required_before_commit
```

## Outcomes

One operation has separate durable facts:

```text
branch_committed       immutable local/cell branch and bytes are durable
strong_barrier_pending exact missing predicates are recorded
globally_converged     owning partition included the branch in its head
policy_committed       every required acknowledgement predicate was met
```

`policy_committed` is permanent evidence for the acknowledged version and
receipt set. Later hardware loss may make current health degraded but cannot
rewrite the historical promise. Repair restores current compliance.

HTTPS can return a structured receipt. SMB flush success means the configured
policy reached its required acknowledgement point; timeout/failure must not be
reported as success. APIs and the UI expose pending barriers and exact missing
predicates without requiring an administrator to drive normal progress.

## Reads

Ordinary reads use the newest authorised local branch by default. Callers that
need a stable cross-gateway view may request the latest globally converged head
or an exact commit ID. A strong read uses the owning partition's linearizable
read barrier; it cannot be served from an isolated branch as if it were current.

## Cross-partition atomic operations

An explicit all-or-nothing operation spanning metadata partitions uses a strong
distributed transaction independently of the volume's normal eventual write
default. Every participant prepares and fences its affected records before one
coordinator authority commits the global decision. Prepared/in-doubt records do
not return an old value or accept a conflicting mutation after another
participant may expose the commit; they wait or return a typed pending result.
Unrelated records remain available.

An availability-first caller may separately receive a complete
`branch_committed`/`branch_deleted` result at its named local scope. That result
does not pretend the cross-partition transaction is globally committed.

## Required proof

Tests evaluate every threshold against simple topology and failure-domain
oracles. They prove duplicate targets do not fake node/zone independence, only
required zones hold the barrier, no strong acknowledgement precedes its final
receipt or ACID head commit, and crashes at every barrier point recover to
exactly pending or committed.

Partition tests keep eventual writes working on every capable component while a
strong operation remains pending, then reconnect in every delivery order and
prove automatic deterministic convergence and exactly one strong publication.
