# Disconnected writes and automatic reconciliation

Status: draft for review.

MeshSpan keeps filesystem work available across network and quorum loss. Raft
continues to protect converged partition heads and security-critical control
state, while immutable local branches preserve writes made without that quorum.

## Two-node example

```text
Home node  <--- link down --->  Office node
```

Both nodes may have only one local durable copy. During the outage:

- home users create and edit files against the home branch;
- office users create and edit files against the office branch;
- each successful flush is durable on the node that acknowledged it;
- neither node claims the other has the new bytes or that global protection is
  satisfied;
- reads use the latest version known in that local branch.

When the link returns, the nodes exchange branch heads and missing immutable
objects, validate them, create deterministic merge commits and copy/encode data
until configured locality and protection are restored. No administrator starts
or chooses this process.

If the only node holding a locally acknowledged version is destroyed before it
replicates, that version is physically unrecoverable. MeshSpan exposes this as
`node_local` durability rather than pretending two-node redundancy existed while
the link was down.

## Commit and receipt scopes

```text
node_local
  one node has the durable branch commit and required local bytes

cell_replicated
  a cell-local policy/quorum has the commit and achieved local protection

globally_converged
  the canonical converged head includes the commit; current placement and debt
  remain separately reported
```

The scope is monotonic for one operation: later reconciliation can strengthen
it. `policy_committed` is an additional acknowledgement fact proving that every
blocking predicate was satisfied; it necessarily includes global convergence.
A successful SMB flush cannot carry MeshSpan-specific detail, so the daemon
records the receipt and exposes current durability/protection through the API,
UI, events and file status. It never calls a lost local copy globally protected.
See [`consistency.md`](consistency.md).

## Branch commit

Every offline-capable mutation creates:

```text
branch commit ID
mesh, metadata-partition and branch/cell IDs
one or more causal parent commit IDs
operation ID and request digest
actor/session and committed identity revision
namespace intent and affected stable object IDs
new immutable object/directory/file/manifest roots
local durability receipts
logical instant for display plus causal clock
signature/authenticated origin
```

One node serializes its own branch. A cell with a local consensus group may
replicate and order a shared cell branch. Neither requires the wider campus
partition leader to accept ordinary filesystem content.

## What can be written offline

Allowed branch operations include file/folder create, content write, truncate,
copy, rename, move within locally available scope, delete, ordinary attributes
and tags that do not grant authority.

Identity, group, role, ownership, permission, voter, secret, component-code and
global policy changes remain authority-gated. A future design may delegate a
strict subset explicitly, but loss of connectivity never turns cached admin
rights into an unrestricted mergeable mutation.

A random write to an existing file needs the base ranges it preserves. If those
bytes are not local, MeshSpan cannot invent them. New independent files still
work; scopes intended for full offline editing should require a complete local
copy.

## Automatic reconciliation

On reconnection:

1. Peers authenticate and compare converged and branch-head summaries.
2. They fetch missing commit headers, validate the causal graph, operation IDs,
   identity revision/delegation and bounds, then fetch required immutable blocks.
3. Already included operations deduplicate by operation ID/request digest.
4. Causally ordered commits replay in that order.
5. Independent operations on distinct objects/names commute.
6. Concurrent incompatible intents use the deterministic conflict rules below.
7. The owning converged partition commits one merge node with all included heads
   as parents and advances its canonical root.
8. Every branch observes inclusion, then locality/protection debt is scheduled
   and repaired automatically.

Interrupted reconciliation resumes from immutable IDs. Repeating it produces
the same graph/root and cannot duplicate a user operation.

### Executable planning contract

Reconciliation is split into a pure planner and a receipt-backed applier. The
planner receives one complete bounded causal closure containing the current
converged head and every eligible branch head. It:

1. rejects duplicate commit identities, missing parents, cycles, mixed volumes
   or root objects, excessive parents/frontiers/commits and conflicting reuse of
   an operation ID;
2. computes the ancestry already included by the converged head;
3. removes exact operation replays already present in that ancestry;
4. topologically orders remaining commits, selecting among causally ready
   commits by `(operation ID, commit ID)` only; and
5. removes ancestor heads from the merge frontier, sorts the surviving parents
   by commit ID and digests the complete plan under a versioned domain.

The batch bound is a paging boundary, not a mesh-size ceiling. A peer must fetch
the next causal page before planning if the closure does not fit. The applier
may use only the planner's exact digest and ordered commits. It validates and
imports immutable records before one authoritative transaction creates the
multi-parent merge commit, advances the converged head and records inclusion.
The source branch remains durable until that receipt is observed. Lost replies
therefore repeat the same plan instead of inventing a second merge.

Each ordinary branch commit stores its canonical replay intent atomically with
the commit: typed mutation, validated display/canonical path, stable leaf object,
new and causal-prior revisions, name generation and selected immutable file
version where applicable. Nested intents also bind each source ancestor's stable
directory identity and exact prior/resulting revision. If a directory is moved
to a recovered conflict path, later descendant intents follow that identity
mapping rather than the losing display path. Reconciliation applies these
bounded affected paths; it never discovers user operations by scanning or
heuristically diffing an entire namespace tree.

## Deterministic conflict rules

No generic system can meaningfully combine two concurrent arbitrary binary edits
to the same bytes. MeshSpan converges the namespace automatically while
preserving all acknowledged content:

| Concurrent intents | Automatic result |
| --- | --- |
| Changes to distinct objects/names | Apply both |
| Identical operation/request digest | Deduplicate |
| Create same canonical name | Deterministic winner keeps name; other gets deterministic conflict sibling |
| Modify same file from common base | Deterministic winner is current; every other version remains in history and gets conflict sibling when needed for ordinary access |
| Delete versus modify | Original name follows deterministic delete/modify rule; modified bytes are preserved as recovered conflict item |
| Rename versus rename | Deterministic destination wins; alternative intent is retained in history and represented as conflict sibling without creating an unsafe hard link |
| Rename versus create at destination | Apply winner by canonical operation order; preserve other object under conflict sibling |
| Directory delete versus descendant change | Preserve changed descendants in a deterministic recovered directory |
| Tag/ordinary attribute changes | Merge disjoint keys; deterministic value plus history for same-key collision |

Canonical ordering uses causal ancestry first and a stable operation-ID tie-break,
never wall-clock arrival order. Conflict names include a stable short origin/commit
identity and are canonicalised like ordinary names. Re-running on every node
produces identical output.

The affected user may later rename, compare or delete alternatives. That is a
content decision, not an administrative repair requirement; the mesh is already
converged and continues operating.

## Handles and locks

Locks and share modes coordinate reachable gateways. A partition can prevent
conflicts only within its connected authority. Disconnected branches may both
hold apparently valid local handles, so reconnect treats incompatible writes as
concurrent versions rather than allowing stale fencing to overwrite one.

An old handle can append to its own branch but cannot replace the canonical
converged head directly. Publication/reconciliation validates its base and causal
parents.

## Protection and locality debt

Local commit planning uses the best currently writable targets and records the
exact achieved layout. It does not block solely because remote protection cannot
be met. Missing desired placements create durable debt linked to the version and
policy revision.

As soon as peers return, critical single-copy versions replicate first, followed
by local protection, required regional copies, balance and optional recoding.
Debt is idempotent and survives restart/churn.

## Snapshots

A local branch may create branch-local snapshots of its durable namespace head.
After merge, their roots remain valid because commits and content are immutable.
The owning partition imports the snapshot record or records an exact rejection
if the actor lacked delegated snapshot authority; rejecting the name never
deletes acknowledged file versions.

Globally scheduled retention policy is applied after reconciliation. Snapshot
roots protecting local-only content are not reclaimed while their validity is
unresolved.

## Delete/edit reconciliation

Causal order decides non-concurrent cases. A deletion after the latest version
remains deleted; an explicit recreation after observing deletion is a new
object. For a genuinely concurrent race:

- content write/truncate or rename survives in the visible merged namespace;
- tag, timestamp, permission or ownership metadata alone does not resurrect the
  deleted object; and
- every acknowledged alternative remains immutable version history.

MeshSpan does not initially interpret or merge file formats. It chooses one
visible version deterministically and exposes alternatives through version
history, with `restore` and `restore as copy`. A future format-specific merger
may create a new version from immutable inputs but cannot overwrite them.

An atomic bulk-delete branch commit hides the complete batch together. If any
member has a concurrent surviving edit during global reconciliation, the global
all-or-nothing transaction resolves the complete batch rather than deleting only
uncontested members.

## Bounds and exhaustion

Offline work is bounded by actual local durable capacity, authorised quota and
resource reserve. Branch logs, conflict counts and reconciliation batches are
paged and compactable only after converged inclusion is proven.

When capacity is nearly exhausted, MeshSpan prioritises compact metadata and new
user content over remote replicas/rebalance, reports the concrete limit and
rejects only when it cannot durably store the requested bytes. Network loss by
itself is never that reason.

## Required proof

Deterministic tests generate two or more branches from every namespace state,
apply all pairs and randomized sequences of intents in every delivery order, and
assert the same merged root, preserved acknowledged versions and idempotent
repair debt.

Real tests run home/office nodes, sever the link for an hour, perform real HTTPS
and SMB writes on both sides, power-cycle each side, reconnect and verify exact
bytes, deterministic conflicts, automatic convergence and restored protection
without an administrator action.
