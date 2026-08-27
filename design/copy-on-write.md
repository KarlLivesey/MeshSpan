# Copy-on-write and snapshots

Status: draft for review.

MeshSpan is semantically copy-on-write: published user-visible and durable
configuration state is immutable and replaced by atomic root changes. This does
not mean every health counter or SQL page is physically append-only.

## Immutable roots

```text
Volume head
  -> namespace commit
       -> root object revision
            -> immutable directory blocks
                 -> child object revisions
                      -> file version
                           -> manifest blocks
                                -> stripe generation
                                     -> immutable shards
```

Separate immutable roots cover component configuration generations,
certificate/secret generations and metadata backups.

Every immutable record has a stable ID, format version and digest. A parent
references exact child identities/digests. Publishing verifies the new reachable
graph, commits its records and advances one authoritative head in the same
metadata transaction.

## Namespace commits

A namespace commit contains:

```text
commit ID
volume ID
one or more causal parent commit IDs
branch ID and originating availability cell
root object revision ID
author and operation ID
converged log position when included, plus causal ordering metadata
root digest
```

An ordinary mutation has one parent. Automatic reconciliation creates a merge
commit with every included branch head as a parent. A local branch commit is a
durable published fact at its declared receipt scope, but only the owning
partition's majority may include it in and advance the converged volume head.
Canonical merge ordering uses causal ancestry and stable operation IDs, never
wall-clock arrival order. See [`disconnected-writes.md`](disconnected-writes.md).

## Path copying

Changing `/a/b/file` creates a new file/object revision and new immutable
directory blocks along `b`, `a` and the root. Unchanged sibling blocks and file
content are referenced by both old and new roots.

Large directories use bounded persistent blocks rather than copying an entire
entry list. The exact tree structure is an implementation decision hidden behind
the namespace repository contract. Canonical ordering and digest test vectors
make the logical result independent of database engine.

## What a snapshot captures

A volume snapshot pins one committed namespace commit. It therefore captures:

- names, hierarchy and object metadata;
- file versions and manifest roots;
- owners, tags and object/folder grants represented by those object revisions;
- extended attributes and named streams;
- the exact logical point in time.

It does not capture live sessions, leases, locks, presence, health observations,
work claims, throttling buckets or node-local state.

Snapshot visibility is governed by current explicit access to the snapshot plus
current active principal/authentication state. Captured historical grants may
further restrict traversal within the snapshot but cannot reactivate a disabled
principal or bypass the absence of a current snapshot-level grant.

## Snapshot lifecycle

```text
creating -> active -> expiring -> removed
              |
              +-> restore_requested -> restored_as_new_head
```

Creation validates the chosen current/explicit namespace or local branch commit
and adds one root reference in the corresponding durable branch. No file bytes
are copied. A branch-local snapshot is imported or explicitly rejected during
reconciliation without deleting the file versions it protects.

Manual and scheduled policies may retain by count, age and protected labels.
Expiry/removal only drops the snapshot root after open snapshot handles and legal
retention permit it. Reclamation is a later reachability decision using the
guarded cleanup lifecycle.

## Restore

Restore never rewinds consensus or overwrites the current head in place. It creates a
new namespace commit whose content root derives from the snapshot, records the
pre-restore current head as its parent/audit context, and atomically makes the
new commit current. The snapshot and intervening commits remain immutable until
their own retention expires.

Whole-volume restore is required initially. File/folder restore is a copy from a
snapshot root into a new current namespace commit and may share unchanged
content.

## Copy-on-write configuration

Changing a component creates a new immutable configuration revision. The
component instance advances its desired revision only after validation. Nodes
report which revision is active. Rollback creates another revision selecting or
copying a prior compatible configuration; it does not erase rollout history.

Certificate, credential and secret rotations similarly create new generations
and retire old generations after acknowledgements and retention rules.

## Mutable coordination state

Leases, handle liveness, presence, observations, attempt buckets, queue claims,
progress and accounting counters are mutable transactional coordination. Making
them copy-on-write would create unbounded history without improving user data
safety. They remain fenced, revisioned and auditable where relevant, but user
snapshots neither capture nor restore them.

## Reachability and reclamation

Reclamation starts from every retained root:

- current volume heads;
- active snapshots;
- open/pinned file versions;
- in-progress committed lifecycle references;
- retained backup/repair roots where applicable.

The reachability result is tied to a catalogue revision. Cleanup intents and
removal permits are issued only if that exact result is still current. A stale
collector can waste scanning work but cannot delete newly reachable data.

Reference counts may accelerate discovery but are not sole deletion authority;
periodic graph reconciliation must detect count drift before physical cleanup.

## Scaling and recovery

Snapshot creation is constant metadata work. Mutation cost grows with changed
path/tree blocks, not total volume bytes. Reads traverse bounded immutable
blocks that can be safely cached by revision/digest across gateways.

After outage, returning voters catch up the converged head, local branches
exchange immutable commits and returning targets reconcile shard identities.
Because published records are immutable, deterministic merge creates new roots
without modifying either input branch in place. Missing reachable shards enter
repair automatically as soon as eligible authority/capacity is available.
