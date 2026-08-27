# Regional and local availability

Status: draft for review.

Locality policy answers a different question from erasure protection:

- protection: which failures must not lose the data;
- locality: where must the current data be independently readable;
- convergence: which partition owns the globally converged head and control
  policy while local branches continue during disconnection.

MeshSpan evaluates all three. Satisfying one never implies the others.

## User-facing policy

An administrator or authorised owner can set on a volume, folder or file:

```text
Keep a complete locally readable copy in: Building A

Inside Building A, survive: 1 machine failure

When another required building is offline:
  Keep writing locally, report achieved durability and catch up automatically

Apply to:
  ● This folder and descendants
  ○ This item only
```

The policy may name several cells and can be overridden at a descendant. A file
stores the effective policy revision used for each committed version, so policy
changes cannot silently reinterpret old acknowledgements.

## Complete local copy

`complete_local(cell)` means every byte of the selected committed file version
can be reconstructed using only verified shards on targets inside that cell. It
does not require a byte-for-byte second ordinary filesystem tree.

The planner may use:

- all systematic data slices locally;
- any locally complete `k`-of-`k+m` subset;
- a separate locally protected Reed–Solomon generation; or
- a full immutable replica for shapes where that is more efficient.

The manifest records what exists; clients see one file. Provider folders remain
private chunks.

To report the scope usable during isolation, the cell must also have a reachable
gateway, writable local branch store and sufficient committed
identity/configuration state. Data bytes alone are not service availability.

## Local protection

A complete local copy may itself have a failure promise:

```text
Building A: complete locally, survive any 1 local machine
Building B: complete locally, survive any 2 local machines
```

The placement proof is evaluated within each cell against its host, device and
overlapping custom fault groups. A shard shared between two requirements counts
only where every corresponding proof remains true.

## Availability-first acknowledgement

A locality requirement is desired placement, not by itself a synchronous
dependency. A separate acknowledgement policy may explicitly classify a cell as
`required_before_commit`; only that classification holds a strong barrier. A
writer first tries every reachable desired placement within the normal latency
budget, then an eventual write commits using the best physically achievable
durable scope:

- `node_local`: one node durably holds the branch record and required bytes;
- `cell_replicated`: the local cell has the branch and achieved local
  protection; or
- `globally_converged`: the owning partition has included the branch and all
  current protection/locality requirements are satisfied.

Unavailable eventual cells create explicit debt and a weaker receipt; network
loss alone does not block an eventual write. An explicitly strong write waits
only for cells its acknowledgement policy marks required. During a campus
partition, every cell with cached valid authorisation, required base bytes and
writable storage may advance its own branch. Reconnection automatically merges
those branches and catches every desired cell up from immutable manifests and
shards.

The globally converged head is still owned by one metadata partition. Moving
that ownership uses a fenced metadata-partition handoff; local branches never
grant routing or control-plane authority.

## Effective policy and inheritance

Policy resolution walks the bounded namespace ancestry in the same committed
namespace view as the write. A binding states:

```text
item only
item and descendants
stop inherited locality
```

The effective result is a normalised set of required cells, per-cell local
protection, preferred synchronous placement latency and optional maximum
reported lag. Contradictory inherited requirements fail validation with the
contributing bindings identified.

Owners may strengthen locality within quota/delegation limits. Weakening or
removing an administrator-required cell needs the corresponding administrative
right and an audited policy revision.

## Policy rollout

```text
requested -> validated -> copying -> complete
                              |          |
                              +-> lagging/at_risk
                              +-> impossible
```

Adding a required cell does not falsely relabel existing data complete. The
planner creates bounded replication/recoding work, verifies every manifest and
publishes per-cell status. The stronger desired policy becomes active through an
explicit operation; writes continue at their achieved scope while existing and
new versions remain visibly pending until copied.

Removing a cell drops a placement requirement only after policy commit. Physical
bytes are reclaimed later through reachability and guarded cleanup.

## Flexible cells and regions

Cells are stable IDs with administrator names and membership selectors. A cell
may represent a building, store, region, room or other availability locality.
They may nest for presentation, but placement always evaluates explicit member
targets/hosts plus overlapping fault groups.

Policies and interfaces refer to IDs, not special `building` columns. New
placement implementations can add cost, sovereignty or latency constraints
without changing manifests, namespace APIs or provider contracts.

## Status

Per scope and cell:

- `pending`: policy accepted but no complete verified local set yet;
- `complete`: the named converged or branch version is locally decodable and
  local service prerequisites are satisfied;
- `lagging`: a complete older converged version exists while another branch or
  the converged head has newer work;
- `at_risk`: current version is readable but below its local failure promise;
- `unavailable`: current required version cannot be read locally; or
- `impossible`: current topology/capacity cannot satisfy the configured policy.

Global status reports each cell separately and never collapses lagging into
complete.

## Snapshots

Snapshot creation pins a namespace commit and its effective locality policy by
default. Data referenced only by a retained snapshot stays in each required cell
until that snapshot's separate policy changes or expires. Assigning a cheaper
snapshot policy changes placement requirements, not the immutable snapshot root.

## Required proof

Tests mark nested scopes for one and several cells, write exact versions, sever
all inter-cell links and prove which bytes/versions each cell can read and
write. They exercise all receipt scopes, concurrent branch conflicts, local
failure budgets, policy inheritance/change, snapshot retention, insufficient
capacity and automatic reconciliation/catch-up after long partitions.
