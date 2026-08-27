# Authoritative operation flows

Status: draft for review.

Each flow names its authority, durable commitment and failure result. Interfaces
may present fewer steps, but they must not replace these operations with a
different path.

## 1. Create a mesh

**Actor:** local operator on the first node.

**Authority:** an atomic local bootstrap transaction that creates the first
single-voter configuration.

1. The daemon validates that its state directory is private, writable and not
   already bound to another mesh.
2. It generates a node identity key and mesh root material locally.
3. The operator supplies the initial mesh name and administrator credentials.
4. One bootstrap operation creates the mesh, host, node, voter membership,
   administrator user, initial owner/admin grants and audit event.
5. The node installs its certificate, commits the bootstrap snapshot and only
   then starts public services.

The receipt identifies the mesh, node and committed position. A crash resumes or
rolls back bootstrap; it never exposes a half-created mesh or default password.

## 2. Issue and consume a join grant

**Actor:** an authenticated administrator, then an unenrolled daemon.

**Authority:** metadata voter majority.

1. The administrator creates a grant with expiry, allowed roles, use count and
   optional host/fault-group constraints.
2. Only the one-time plaintext grant is returned; metadata stores its digest.
3. The joining daemon generates its private identity key locally and submits the
   grant, public key, requested host identity and supported features over HTTPS.
4. The leader atomically consumes one use, creates the node in `admitted` state
   and issues a mesh-bound certificate for that public key.
5. The daemon verifies the mesh identity, persists its certificate chain and
   bootstrap peers, then connects over Quinn/mTLS.
6. A committed activation command records its incarnation, capabilities and
   validated endpoints. Only then may it serve or store authoritative data.

UI, API and `--join-code` startup invoke this same flow. A lost enrolment reply is
resolved by its operation ID and public-key fingerprint; the grant is not
consumed twice.

## 3. Register storage folders

**Actor:** local daemon with an administrator-authorised registration request.

**Authority:** local path validation followed by committed metadata activation.

For each repeated `--storage-path` or UI-selected folder:

1. Resolve and canonicalise the existing folder without following an unsafe
   replacement or formatting anything.
2. Inspect writability, capacity, filesystem and backing-device evidence.
3. Reject the daemon state directory, overlapping registered roots, unsupported
   semantics, provider files from another target or unverifiable ownership.
4. Create a random target identity and target-local marker atomically.
5. Commit the public target identity, node/host association and known fault-group
   memberships.
6. Reconcile an empty or existing private shard inventory before placement is
   enabled.

Each path is an independent target. Different sizes are normal. A registration
failure does not invalidate other paths in the same invocation.

## 4. Define fault groups and protection

**Actor:** administrator.

**Authority:** metadata majority and deterministic placement evaluator.

1. Create named fault-group classes and instances such as building, room,
   circuit, PSU or switch.
2. Add hosts or storage targets to any number of groups.
3. Define required simultaneous-failure scenarios, for example any two machine
   groups and any three backing-device groups.
4. The evaluator tests current eligible target sets against every scenario and
   reports feasible, temporarily under-protected or impossible with reasons.
5. Volume creation commits the user promise and allowed layout set only after
   validation. The system chooses concrete coding layouts per stripe.

Changing topology never rewrites the promise. It may mark existing data at risk
and create repair/rebalance work.

## 5. Create identities and access rules

**Actor:** administrator, delegated manager or object owner as authorised.

**Authority:** metadata majority.

1. Create users and groups as principals.
2. Add a user to many groups or a user/group to a containing group. The command
   rejects cycles and updates the transitive closure atomically.
3. Add one or more owner principals to an object. An owner may be a user or
   group; transitive members receive effective ownership.
4. Add permission grants with scope, rights, inheritance and optional active
   time window.
5. Attach descriptive tags to objects or principals independently of access.
6. Enrol one or more authentication methods for each user under current
   assurance policy.

Every mutation changes the relevant authorisation revision, invalidates stale
capabilities/sessions where required and appends a redacted audit event. The last
active owner cannot be removed without a replacement in the same transaction.

## 6. Authenticate to HTTPS

**Authority:** committed identity, authentication policy and session state.

1. The gateway accepts a bounded login attempt and records mesh-wide throttle
   state without revealing whether the user exists.
2. It verifies the selected factor through its typed credential handler.
3. If policy requires another factor or recent step-up, it creates a short-lived
   pending ceremony rather than a full session.
4. Once policy is satisfied, it commits a session digest, factors, service scope,
   issue/expiry times and current identity revision.
5. The browser receives the opaque cookie plus CSRF protection; raw credential
   material is discarded.

Any gateway can validate the same committed session. Revocation and relevant
identity changes take effect across gateways.

## 7. Authenticate to SMB

**Authority:** the same user and permission records as HTTPS.

1. A strongly authenticated HTTPS/admin session creates or rotates a
   separately revocable SMB-scoped credential.
2. An SMB gateway performs protocol authentication against the typed verifier
   and current user/method state.
3. It establishes a bounded SMB session tied to user and identity revisions.
4. Tree connect resolves an export and requires traversal/access rights; every
   file operation subsequently asks the common filesystem service for its exact
   right.

SMB credentials cannot access administration. Multiple gateways may authenticate
the same user and expose the same namespace concurrently.

## 8. Open, write, flush and close a file

**Actor:** an HTTPS or SMB adapter acting for a session.

**Authority:** common filesystem service backed by metadata majority.

1. `Open` resolves the canonical path, evaluates access, create disposition,
   share modes and delete state, and returns a fenced handle.
2. Random writes update gateway-local staged content associated with a durable
   write transaction; they do not mutate a published version.
3. `Flush` chunks/encodes content, places shards, collects durability receipts
   and atomically publishes one immutable version as defined in
   [`data-lifecycle.md`](data-lifecycle.md).
4. `Close` flushes if required, releases locks and resolves delete-on-close.

The adapter maps `committed`, `rejected`, `in_progress` and indeterminate
transport outcomes to protocol-correct responses. It never reports a lost reply
as a successful save. A subsequent connection to any gateway reads the committed
version.

## 9. Read a file

1. The adapter opens or validates a fenced handle and current read permission.
2. The filesystem service obtains the immutable current version and manifest.
3. It fetches verified shards concurrently and reconstructs the requested range.
4. It returns only verified bytes and records any missing/corrupt observations
   for repair.

Losing a source node during the read is transparent when enough valid shards
remain; otherwise the caller receives an explicit availability error.

## 10. Rename, move and delete

- Rename/move atomically changes the directory entry after canonical-name,
  cycle, lock and permission checks. Object ID, owners and tags remain stable.
- User deletion removes/tombstones the namespace link according to open-handle
  semantics.
- Snapshot/reference retention may keep the object version reachable.
- Physical shard cleanup occurs later through exact cleanup intents and removal
  permits. A user delete request never contains storage locations.

## 11. Lost response and retry

1. The caller submits a stable operation ID and request digest.
2. If the connection is lost, the local result is `unknown`.
3. The caller asks `OperationStatus(operation_id)` from current authority.
4. `committed` returns the original typed result; `rejected`/`aborted` returns the
   durable terminal reason; `in_progress` is polled with bounded backoff.
5. If no operation exists, the same ID and identical request may be retried.

The same operation ID with a different digest is always rejected.

## 12. Majority loss and recovery

- Any connected component with a voter majority elects at most one leader and
  may continue authoritative mutations.
- Every component without a majority refuses mutations. It may serve only reads
  whose stated consistency and available verified data permit it; it never
  reports a local uncommitted edit as saved.
- If a five-way partition leaves no majority, all components stop authoritative
  writes. This is required to avoid conflicting histories.
- When connectivity returns, Raft selects the committed majority history. Stale
  log tails are discarded, followers catch up or install a verified snapshot,
  then shard inventories are reconciled and repaired.

There is no conflict picker because ordinary partitioned components never create
multiple committed histories. Deliberate disconnected multi-writer operation is
a separate deferred design.

## 13. Voter replacement

1. Current authority marks a voter unavailable based on failure policy.
2. It selects an eligible, caught-up node that has durable state storage and
   validated identity.
3. Raft joint consensus adds the replacement voter.
4. After it catches up and the new configuration commits, joint consensus
   removes the failed voter if requested.

No minority component can promote itself. Stable recommended voter counts are
odd; transitions remain safe while moving through joint configurations.

## 14. Repair and return

1. Loss, scrub or read verification creates a deduplicated repair finding.
2. A fenced worker reconstructs and durably places replacements.
3. A catalogue compare-and-swap publishes them, then old shards become eligible
   for guarded cleanup.
4. Returning nodes announce a new incarnation and inventory their old shards.
5. Verified still-current shards are reused; stale shards are quarantined or
   cleaned through authority.

Repeated unplug/replug cycles are expected operation, not an exceptional manual
recovery workflow.

## 15. Certificate issue and renewal

1. An administrator commits ACME account and HTTP-01 or DNS-01 settings.
2. One elected worker obtains a fenced certificate-order claim.
3. It fulfils the selected challenge. Replacement workers may resume only after
   the prior fence expires or is superseded.
4. It commits the public certificate plus a separately encrypted private-key
   envelope for every authorised gateway node.
5. Each node fetches only its envelope, decrypts locally, atomically installs the
   bundle and acknowledges the public fingerprint.
6. Gateways switch generations without dropping established service; retirement
   waits for required installation acknowledgements or explicit policy.

One certificate order serves all relevant gateways, avoiding one public CA
request per node behind the same address.

## 16. Backup and restore

1. Authority creates a state-machine snapshot at an exact committed position.
2. It packages the manifest, schema version and required encrypted secret
   material and verifies the digest.
3. Restore occurs with public services closed.
4. The daemon validates mesh identity, snapshot/log position, schema, membership
   and decryptability before installing atomically.
5. Nodes rejoin with their own identities and reconcile target inventories.

Copying an arbitrary live database file is not this flow.
