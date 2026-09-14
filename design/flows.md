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
2. It generates a node identity key and one high-entropy single-use claim bundle,
   prints it only on an interactive local CLI and atomically writes it to a
   configured protected automation file when requested.
3. The operator enters that bundle on the setup page or submits it through an
   authenticated existing-swarm add-node flow. The setup surface never reveals
   the bundle.
4. For a new mesh, the operator supplies the mesh name and enrols a passkey or
   login-capable API key.
5. One bootstrap operation creates the mesh, host, node, voter membership,
   administrator user, initial owner/admin grants and audit event.
6. The node invalidates the claim bundle, removes its output file where possible,
   installs its certificate, commits the bootstrap snapshot and only
   then starts public services.

The receipt identifies the mesh, node and committed position. A crash resumes or
rolls back bootstrap; it never exposes a half-created mesh or default credential.

## 2. Issue and consume a join grant

**Actor:** an authenticated administrator, then an unenrolled daemon.

**Authority:** the catalogue/identity partition's valid leader and consensus-write quorum.

1. The administrator creates a grant with expiry, allowed roles, use count and
   optional host/fault-group constraints.
2. Only the one-time plaintext grant is returned; metadata stores its digest.
3. The joining daemon generates its private identity key locally and submits the
   grant, public key, requested host identity and supported features over HTTPS.
4. The leader atomically consumes one use, creates the node in `admitted` state
   and issues a mesh-bound certificate for that public key.
5. The daemon verifies the mesh identity, persists its certificate chain and
   bootstrap peers, then connects over Quinn/mTLS. Each bootstrap peer carries
   its current committed incarnation as a positive decimal string alongside its
   node identity, endpoint and certificate. A fresh joiner must not assume that
   an existing peer is still at its first incarnation.
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

**Authority:** the owning configuration/namespace partition and deterministic
placement evaluator.

1. Create named shared-failure groups such as physical hypervisor, building,
   room, circuit, PSU or switch.
2. Add machines to any number of overlapping groups. Backing-device identity
   remains a separate built-in failure dimension.
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

**Authority:** the owning identity or namespace partition.

1. Create users and groups as principals.
2. Add a user to many groups or a user/group to a containing group. The command
   rejects cycles and updates the transitive closure atomically.
3. Add one or more owner principals to an object. An owner may be a user or
   group; transitive members receive effective ownership.
4. Add permission grants with scope, rights, inheritance, optional active time
   window and optional activation policy. A group may also require activation.
5. Attach descriptive tags to objects or principals independently of access.
6. Enrol one or more authentication methods for each user under current
   assurance policy.

Every mutation changes the relevant authorisation revision, invalidates stale
capabilities/sessions where required and appends a redacted audit event. The last
active owner cannot be removed without a replacement in the same transaction.

When access requires activation, the user supplies a bounded reason and desired
duration. Authority verifies current structural membership or grant assignment,
its absolute schedule, the policy maximum and any recent step-up requirement,
then commits a mesh-wide activation and audit event. It contributes rights only
until the earliest source, policy, session or activation expiry. Revocation is
immediate at the authoritative revision and invalidates derived capabilities.

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

1. A user creates or rotates an API key whose ordinary scopes permit SMB login.
2. An SMB gateway performs protocol authentication against that method's digest
   and current user/method state.
3. It establishes a bounded SMB session tied to user and identity revisions.
4. Tree connect resolves an export and requires traversal/access rights; every
   file operation subsequently asks the common filesystem service for its exact
   right.

The same key cannot administer unless its explicit scopes also permit that
operation. Multiple gateways may authenticate the same user and expose the same
namespace concurrently.

## 8. Open, write, flush and close a file

**Actor:** an HTTPS or SMB adapter acting for a session.

**Authority:** common filesystem service using the owning namespace partition
when reachable and a constrained local CoW branch during isolation.

1. `Open` resolves the canonical path, evaluates access, create disposition,
   share modes and delete state, and returns a fenced handle.
2. Random writes update gateway-local staged content associated with a durable
   write transaction; they do not mutate a published version.
3. `Flush` resolves the inherited acknowledgement policy, chunks/encodes
   content, places shards, collects durability receipts and atomically publishes
   one immutable version to the local branch. A strong policy then waits only
   for its required zones/protection predicates and the converged ACID head
   commit, as defined in [`consistency.md`](consistency.md) and
   [`data-lifecycle.md`](data-lifecycle.md).
4. `Close` flushes if required, releases locks and resolves delete-on-close.

The adapter maps `branch_committed`, `policy_committed`, `rejected`,
`in_progress` and indeterminate transport outcomes to protocol-correct
responses. It never reports a lost reply or unmet strong barrier as a successful
save. A gateway reads its newest authorised local branch; after reconciliation,
every caught-up gateway reads the same converged version.

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
3. The caller asks `OperationStatus(operation_id)` locally and, when reachable,
   from current authority.
4. `branch_committed`, `globally_converged` or `policy_committed` returns the
   original typed receipt at that stage; `rejected`/`aborted` returns the durable
   terminal reason; `in_progress` is polled with bounded backoff.
5. If no operation exists, the same ID and identical request may be retried.

The same operation ID with a different digest is always rejected.

## 12. Authority loss and recovery

- For each metadata partition, a connected component may elect a leader only if
  it satisfies the committed election predicate. An already valid leader may
  advance the converged head and security-critical control state only while its
  component satisfies the committed consensus-write predicate.
- A component without either form of authority may durably commit authorised
  ordinary filesystem operations to its local CoW branch when it has the
  required base bytes and writable storage. Its response states `node_local` or
  `cell_replicated`; it never claims global convergence or absent protection.
- If a multi-way split leaves no component with a valid leader plus commit
  quorum and no component able to elect one, no component advances the converged
  head or control metadata, but every physically capable component may continue
  its own filesystem branch. Unrelated partitions continue independently.
- When connectivity returns, consensus restores one converged owner, branch
  summaries and immutable objects are exchanged, and deterministic merge commits
  include every valid operation. Repair then restores protection and locality
  debt.

No administrator picks an internal history. True concurrent content collisions
become deterministic conflict siblings while every acknowledged version remains
available. The exact rules are in
[`disconnected-writes.md`](disconnected-writes.md).

## 13. Voter replacement

1. Current authority marks a voter unavailable based on failure policy.
2. It selects an eligible, caught-up node that has durable state storage and
   validated identity.
3. The current plan adds the replacement as a learner and proves full catch-up.
4. A proved joint old/new quorum-plan transition adds the replacement voter and,
   when requested, retires the failed voter.

No unauthorised component can promote itself. Automatic plans normally prefer
odd voter counts, but even counts are first-class when their proved quorum
families improve the declared topology.

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
   Before contacting the CA it commits the generated leaf key as an encrypted
   order-bound secret. After every accepted remote step it commits a bounded,
   validated order checkpoint under the same live fence. A replacement worker
   decrypts that same key, re-fences the checkpoint and resumes the existing
   order; an unfinished challenge is re-published under the replacement fence.
3. It fulfils the selected challenge. A manual DNS-01 publisher creates a
   durable task with the exact record and deadline; authoritative-DNS probing
   resumes the order without relying on an administrator button. Replacement
   workers may resume only after the prior fence expires or is superseded.
4. It commits the public certificate plus a separately encrypted private-key
   envelope for every authorised gateway node.
5. Each node fetches only its envelope, decrypts locally, atomically installs the
   bundle and acknowledges the public fingerprint.
6. Gateways switch generations without dropping established service; retirement
   waits for required installation acknowledgements or explicit policy.

One certificate order serves all relevant gateways, avoiding one public CA
request per node behind the same address.

An external automated CA instead calls the scoped certificate-publisher API with
an idempotent operation ID, certificate chain and matching private key. MeshSpan
validates names, chain, lifetime and key, creates the same encrypted generation,
probes gateway installation and activates it make-before-break. There is no
manual certificate-upload path and the private key is neither returned nor
logged.

## 16. Backup and restore

1. Authority creates a state-machine snapshot at an exact committed position.
2. It packages the manifest, schema version and required encrypted secret
   material and verifies the digest.
3. It places several generations through configured backup destinations, which
   may be registered targets, another swarm or another provider, and records
   exact receipts plus declared failure overlap.
4. Restore occurs with public services closed.
5. The daemon validates mesh identity, snapshot/log position, schema, membership
   and decryptability before installing atomically.
6. Nodes rejoin with their own identities and reconcile target inventories.

Copying an arbitrary live database file is not this flow.

The restore-readiness API's `gateway_key` scope verifies only backups encrypted
for the checking gateway's wrapping key. A backup captured before that gateway
joined can still be exported, but its local restore check returns an explicit
missing-recipient conflict. Check it on a gateway included in the capture or use
the offline recovery bundle; enrolment does not rewrite historical backups.

### Offline backup verification

The headless executable can check an exported backup with every mesh node stopped:

```sh
meshspan-daemon verify-backup backup.msb sha256:EXPECTED_DIGEST recovery.bundle recovery.code new-verification-work
```

Keep `EXPECTED_DIGEST` from the `MeshSpan-Backup-Digest` header of the original
authenticated HTTPS export, separately from the backup. The command also accepts
the 64 lowercase hexadecimal digits without `sha256:`. Calculating a new digest
from an untrusted replacement is not independent verification of the saved copy.

Use the recovery bundle downloaded at setup and its separately saved code file.
Both the existing `meshspan-recovery-file-v1.` text download and the binary bundle
are accepted. The code file must be owner-only; the secret code is never a command
argument. The last argument must name an absent directory, not a live daemon state
directory. Relative paths are supported.

Verification checks the complete encrypted container, authenticates/decrypts its
chunks, restores SQLite in an isolated private workspace and checks integrity,
the captured schema, mesh/partition identity, membership and exact log position/revision.
Only the new private copy advances through the supported migration chain; the
original backup is never changed. A missing/changed migration or failed post-migration
integrity check refuses restoration. Source and restored schema versions are
reported separately; this does not promise that every pre-1.0 version is supported.
The stored recovery recipient, root certificate and bundle identity must match
the supplied offline authority. Every retained encrypted secret generation,
including historical generations, must have an envelope for that recovery key
and pass authenticated decryption. Plaintext secrets are zeroised immediately
after checking. No network listener starts and no live database is installed or
modified. Successful output is one JSON report, with string-form log positions,
revision, original `schema_version`, `restored_schema_version` and
`retained_secret_generations_verified`; failure returns a non-zero
exit without a success report.

The workspace temporarily contains decrypted metadata and needs space for two
plaintext database copies. Normal success and failure remove that temporary
state. Cleanup failure is reported as failure, not success; abrupt power loss
can leave sensitive temporary files in the requested directory. Unlinking them
is not a claim of secure erasure. Use an encrypted filesystem where required.

This verifies that exact exported **metadata** generation with the offline key.
It does not prove that it is the latest generation, check file shards, establish
that all referenced data-encryption keys are present or fence/admit a replacement cluster. The live disaster
recovery and service-admission workflow remains separate Stage 10 work.

### Offline recovery preparation

The operator can prepare a replacement set with the mesh stopped:

```sh
meshspan-daemon prepare-recovery backup.msb sha256:EXPECTED_DIGEST recovery.bundle recovery.code selection.json recovery-work
```

Use the independently saved HTTPS export digest, setup recovery bundle and
owner-only code file, as for `verify-backup`. `selection.json` must also be an
owner-only regular file. It describes public replacement identities, not private
keys or live authority. Its Rust-authored boundary rejects unknown/duplicate
fields, null where omission selects a default, coercion and excessive input.
The backup, bundle, code and selection must all be outside `recovery-work`:
resolved paths are checked before workspace ownership or cleanup. A supplied
input never becomes disposable merely because it has a recognised temporary name.

Selection fields:

- `recovery_id`: a fresh canonical versioned UUID for this recovery operation.
- `storage`: the bounded source selection described under
  [offline file-content verification](#offline-file-content-verification): a
  `maximum_copied_bytes` budget and `targets` with exact identities, generations
  and existing folder paths. Preparation derives the inventory digest itself;
  the old caller-supplied `target_inventory_sha256` input is rejected.
- `nodes`: 1–1,024 initial replacements. Each supplies `node_id`, `host_id`,
  `host_name`, `node_name`, string-form positive `incarnation`, `roles` containing
  `storage`, `gateway` and/or `metadata`, the canonical hexadecimal
  `identity_public_key` (P-256) and `wrapping_public_key` (X25519), and its
  `private_endpoint`. Private keys remain on their nodes. Existing nodes require
  a newer incarnation; duplicate identities, endpoints or ambiguous names fail.
- `quorum`: omitted or `{"kind":"automatic"}` for a flat majority of the selected
  metadata-eligible nodes. Advanced clients can provide
  `{"kind":"compiled","specification":"HEX"}` with canonical `ActiveQuorumPlan`
  bytes. The command independently re-proves the predicates and requires the exact
  successor membership epoch; this does not introduce a second consensus engine.

The command verifies and restores the exact source and both filesystem journals,
checks the saved recovery identity, validates selected target markers against
that authenticated metadata, and retains private encrypted pack copies. Every
file selected by the backup's retained roots must reconstruct and pass complete
plaintext length/digest verification before replacement keys or signatures are
created. The command then derives the canonical inventory commitment,
plans fresh operational keys and rewraps retained generations through
an encrypted, bounded-record spool. It signs the exact replacement plan, restores
a separate isolated preparation, stages/seals its keys, fences copied transient
credentials and exports one `<node-id>.bundle` per selected node. Output includes
`root.der`, `prepared.sqlite3`, per-node encrypted bundles, `inventory/` and `prepared.json`.
The final report is stored durably before it is printed. It explicitly reports
`service_started: false`, `admission_ready: false` and
`target_inventory_verified: true`, with the derived `target_inventory_sha256`.
This is proof of the retained copies and selected files, not restored protection,
readiness of replacement nodes or authority to start their services.

Rerun the same command and selection to continue after interruption. A private
workspace binds the saved backup digest, recovery bundle and normalised selection;
a lock permits only one preparation process at a time. A changed request is
rejected before reusing work. Whitespace and object-key order do not change the
normalised selection, but array order remains part of the requested intent.

Unpublished work lives in a private `build` subdirectory. It can be discarded and
rebuilt because no node bundles are exported from it. A complete, credential-fenced
SQLite snapshot is synchronised and atomically linked as `prepared.sqlite3`
before exports start. Once published, its exact keys, certificates, fence time
and collected receipts survive retries. Every retry verifies the signed source
and selection; missing exports are regenerated deterministically and existing
exports must match exactly. Existing damaged state is rejected, not overwritten.
Retained pack copies live outside disposable build work. Published-preparation
retries recalculate their byte commitment and compare it to the root-signed plan;
missing or changed copies cannot silently acquire a new commitment. Original
source media are not required for those retries. An interrupted, unpublished
build still needs its selected sources to complete discovery and verification.
The stored `prepared.json` report is verified or created before printing success.
The encrypted planning spool is disposable build material, not a second journal
that the operator must maintain.

Normal completion removes only recognised disposable build files. Abrupt loss
may leave them for the next invocation; unknown files and unsafe directories
are preserved and reported, never recursively deleted. Several temporary metadata
copies may coexist while building the atomic snapshot. Use an encrypted host
filesystem where metadata confidentiality at rest is required. This operation
does not register/repair sources, fence unreachable old members or start recovered services.
Workspaces produced before this restartable layout are not automatically adopted;
use a new recovery-work directory for those pre-alpha preparations.

### Filesystem-history staging

Automatic backup preparation now captures the control snapshot together with the
namespace and content-layout journals in one encrypted archive. The same export,
provider copies and independent digest cover all three members. Capture checks
the filesystem-history closure against a separate read copy of the exact control
snapshot; missing required roots, manifests, layouts or retained key generations
prevent publication. A never-used filesystem can contribute an empty journal pair
only when that closure check succeeds. No source journal is created implicitly.

The isolated preparation can stage history directly from that backup:

```sh
meshspan-daemon stage-recovery-history recovery-work/prepared.sqlite3 recovery.bundle recovery.code backup.msb new-history-work
```

The saved root-signed preparation supplies the required backup digest; the command
never trusts a digest calculated from an arbitrary replacement file. All three
members must authenticate before the copied control member is removed and the
filesystem copies are opened. A surviving filesystem directory is also accepted
instead of the archive: both existing journals are snapshotted read-only into the
new private directory. Only copies are migrated and checked.
The snapshots are not a cross-database transaction: completeness is checked
against the exact preparation's retained namespace roots. Bounded history pages
must resolve those roots and their manifests; referenced layouts must match and
their content-key envelopes must decrypt using the corresponding retained volume
key generation. Missing or damaged history, layout or keys fails the operation.

Success publishes `history.json` and reports checked root/manifest-reference
counts. These are reference counts, not distinct-file counts. It explicitly reports
`history_source: authenticated_backup` or `surviving_journals`, and
`shards_verified: false`, `admission_ready: false` and `service_started: false`.
It has not read, reconstructed or proved physical file bytes. Additional donor
branches do not acquire serving authority by being present in the copy.

The destination must be new; an existing directory is never overwritten. Failed
attempts can leave private partial copies but no success report. A new directory
is required to retry this staging step. The original donor journals are unchanged.

### Offline file-content verification

The headless verifier reconstructs the files selected by the authenticated backup,
using surviving encrypted packs without opening their original target journals:

```sh
meshspan-daemon verify-recovery-content recovery-work/prepared.sqlite3 recovery.bundle recovery.code backup.msb storage-selection.json new-content-work
```

The prepared database supplies the root-signed source identity and backup digest.
The verifier independently decrypts the archive again, checks its exact metadata
position and integrity, and obtains target fingerprints, retained roots and secret
generations from that verified source—not mutable preparation rows or source-folder
claims. The archive must contain both filesystem journals. This command does not
accept arbitrary surviving journals in place of the archive.

`storage-selection.json` is an owner-only regular file, bounded to 2 MiB, containing:

```json
{
  "maximum_copied_bytes": "10737418240",
  "targets": [
    {
      "target_id": "11111111-1111-8111-8111-111111111111",
      "generation": "1",
      "storage_path": "/surviving/storage-folder"
    }
  ]
}
```

Use the actual target identity and generation from the selected backup. Positive
integers are canonical decimal strings; null, numeric coercion, duplicate or
unknown fields, repeated target generations and repeated paths are rejected.
There are 1–1,024 selected targets. Marker fingerprints are never accepted from
this file: they come from the authenticated metadata. Retired targets may supply
salvage bytes without being reactivated.

The new work directory must be outside every selected source folder. Each target
is held exclusively while its packs and crash journals are copied. The cumulative
copy limit counts source bytes; SQLite working files and the inventory index need
additional space. Originals are not repaired or modified. The private inventory
indexes exact encrypted identities and tries surviving duplicates after corruption
or missing copies. Incomplete copies cannot satisfy reads.

The filesystem verifies enough slices to reconstruct each encrypted chunk,
authenticates/decrypts it and checks the complete file length and digest. Plaintext
is streamed into a verification sink, not exported as ordinary files. A failed
reference, key or required byte prevents `content.json` and any success report.
Successful output records checked root/manifest-reference, logical-byte and chunk
counts. Repeated references are counted repeatedly, not reported as distinct files.

`content_verified: true` proves only this isolated verification. The command also
recalculates the inventory commitment and requires it to match the root-signed
preparation exactly; it reports `target_inventory_verified: true` and the matching
`target_inventory_sha256`. Different copies cannot replace the selected inventory
merely because they could reconstruct the same files. Restored protection,
all-node readiness and service admission remain separate work, so `admission_ready`
and `service_started` stay false. It is not an admission receipt. The work directory retains
private metadata and encrypted pack copies; use an encrypted host filesystem for
metadata confidentiality. An existing command destination is never overwritten;
retry with a new destination. Low-level inventory capture is restartable, but this
whole-command retry does not yet resume a previous verification.

The version-one commitment is SHA-256 over, in order:

1. ASCII `MeshSpan recovery inventory v1` followed by a zero byte and the
   independently selected 32-byte encrypted-backup digest.
2. A big-endian unsigned 64-bit selected-target count, followed by targets sorted
   by target identity and generation. Each has 16 identity bytes, an unsigned
   64-bit big-endian generation and the 32-byte authenticated marker fingerprint.
   Selected empty targets are included. Local paths and capacity budgets are not.
3. ASCII `MSRECOVERYPACKS`, byte `0x01`, and an unsigned 64-bit big-endian pack count.
   Packs sort by mesh identity, target identity, generation and sequence, not
   discovery order or scratch-directory allocation. Each has its exact 116-byte
   target marker and unsigned 64-bit big-endian sequence.
4. Within each pack, three ordered member records: main database (role 1), WAL
   (role 2), rollback journal (role 3). Each starts with its one-byte role and
   one-byte presence flag. Present members additionally have an unsigned 64-bit
   big-endian byte length and a 32-byte BLAKE3 digest of exactly those bytes.
   The main database must exist. Missing optional members are distinct from
   present empty members. Total member bytes must equal copy accounting.

Shared-memory files and the derived lookup index are excluded: neither is a
source of authoritative bytes. Lookups remain suspect and each reconstructed file
is checked independently. A partial manifest, incomplete copy or failed hash/read
must never be signed or reported as verified.

The archive container is now format **2**. It has fixed member roles rather than
archive-supplied paths, authenticated per-member lengths/digests and one increasing
chunk nonce sequence across all members. Metadata-only extraction still authenticates
discarded history bytes. Format-1 pre-alpha containers are rejected; recreate them
from their source state with the current build. The low-level metadata-only capture
API is not a complete filesystem backup and cannot satisfy a request to extract
history. Full recovery still requires physical shard availability, retention of
backup-referenced content and explicit recovered-service admission.

### Replacement-node recovery key installation

The node-side key/certificate installation step is headless and does not need the offline
recovery bundle or its private root:

```sh
meshspan-daemon install-recovery-keys keys.bundle root.der NODE_UUID node-identity.pk8 node-wrapping-key.x25519 new-installed.bundle
```

Use a separately trusted root certificate and the node's existing private identity
and wrapping-key files. Inputs must be owner-only regular files. The node UUID
must be in the signed replacement plan and both local public keys must match it.
`prepare-recovery` exports the bundles using the same typed
`export_recovery_key_bundle` repository API, which requires the verified, sealed,
root-authorised and credential-fenced isolated recovery copy. Final service
admission remains unfinished.

Installation verifies bounded frames, the root signature, exact replacement and
key-inventory commitments, and assigned encrypted generations while copying to
a private temporary file. Gateways open all assigned keys; storage-only nodes
open only the fresh storage-permit key, never gateway or historical generations.
Metadata-only nodes receive neither kind of key. Fresh CA/permit material is checked separately
from historical encrypted generations. Missing, reordered, corrupted or extra
material is rejected without publishing a success destination. Transfer format 3
also includes a replacement leaf signed by the prepared successor online CA for
the node's existing public identity and canonical private-transport DNS name.
Its generation succeeds every retained source certificate for that node, and its
30-day window starts at the recorded fence time rounded down to whole seconds.
Issuance is deterministic across retries. The recipient checks the exact key,
issuer, name, usages, generation serial and interval before installing the bundle.

Only after file and directory synchronisation does the node sign an installation
transcript binding its identity/incarnation, recovery/partition/mesh, exact plan,
bundle digest and verified generation count. Identical retries reverify and sync
the existing installation; changed or unsafe destinations are never overwritten.
The JSON report contains public digests, certificate generation/expiry and the
signature, not decrypted keys. The format-3 acknowledgement binds the certificate
and role-specific opened-generation count through the exact bundle digest.
Pre-alpha format-1 and format-2 transfers are rejected;
start a fresh recovery preparation if old receipts already exist.

Save the installer's successful JSON output in an owner-only file (for example,
set `umask 077` before redirecting stdout). Transfer that public signed report
back to the offline coordinator and run:

```sh
meshspan-daemon collect-recovery-installation recovery-work/prepared.sqlite3 recovery.bundle recovery.code NODE_UUID installation.json
```

The command consumes one bounded report (at most 16 KiB), rejects unknown or
duplicate fields, and records one selected node's verified signature. The output
contains the independently reconstructed bundle digest and the first durable
receipt time. It always reports `service_started: false` and
`admission_ready: false`. A lost response can be retried with the same report;
the first successful receipt is retained. A failed signature does not insert a
receipt. No private node key or decrypted secret is needed by collection.

The coordinator's typed `record_recovery_key_installation` API accepts the
selected node ID and decoded `installation_signature`. It independently derives
the expected transcript from its own signed preparation and exact deterministic
export, rather than trusting the report's hash, count or message. It retains the
verified signature in the isolated recovery database. Reopening and exact retry
revalidate the evidence and preserve the first receipt time. The corresponding
`recovery_key_installation` read returns no receipt for a selected node that has
not acknowledged; it never counts a missing receipt as installed. Report hash,
count, certificate fields, message and scope text are untrusted display claims:
collection neither echoes nor uses them as authority. The selected node signature
must verify the coordinator's reconstructed transcript. The all-node readiness
and admission workflow is still unfinished.

This installs **encrypted recovery keys and the replacement node certificate**
inside one durable bundle. It does not select live transport credentials, restore
metadata into service, prove target availability or activate consensus. Admission
must check current certificate validity; a deterministic historical verification
is not proof that an expired certificate can serve traffic. A signature
attests the node's installation claim; it is not proof of physical disk health.
The command explicitly reports `service_started: false`.

### Replacement-node prepared state transfer

After preparation, export the selected node's metadata/history and key package:

```sh
meshspan-daemon export-recovery-state recovery-work/prepared.sqlite3 recovery.bundle recovery.code backup.msb NODE_UUID new-state-package
meshspan-daemon install-recovery-state new-state-package root.der NODE_UUID node-identity.pk8 node-wrapping-key.x25519 new-installed-state
```

The exporter takes a consistent isolated snapshot of the preparation, checks its
root-authorised source and replacement plan, restores the authenticated backup's
filesystem journals and verifies their retained-root/layout closure. It encrypts
all three SQLite files to the selected node's public wrapping key using the
existing bounded encrypted-backup format. The package contains only `state.msb`,
`keys.bundle` and `state.auth`; successful export removes its private plaintext
staging copies. Neither private node keys nor the offline private root travel in
the package.

After restoration receipts have been collected, the same export command also
prepares their replacement read routes. It revalidates each node's complete stored
stream in one metadata read view, resolves each original receipt in the authenticated
archive and compares its exact replacement operation, target, generation and bytes.
The original archive catalogue stays separate from the output catalogue: repeated
retained references cannot mistake an already projected route for the original.
Conflicting or corrupt mappings fail export before a signed package is produced.
`restored_route_references` counts checked receipt references, not unique shards or
a complete/healthy recovery. A new package is needed after later receipts arrive.

Route projection preserves manifests, coding and content keys. It uses the normal
replay-safe route representation inside this isolated candidate, reserving
`source_revision + 1` for recovery activation. That reservation is **not** a
consensus commit or a metadata-head advance. Future admission must validate and
adopt the matching recovery revision, install current provider/permit authority,
verify required shard availability and fence old nodes before serving this state.
The encrypted archive digest in the root-signed transfer binds the projected routes;
no additional route file or private wire format is introduced.

The separate root-signed `MSRSTATE` version-one record binds the original signed
recovery authorisation, recipient UUID/incarnation and exact lengths and SHA-256
digests of both encrypted files. Framing is closed and at most 512 bytes: nine-byte
magic/version, big-endian two-byte original-authorisation length and its encoded
bytes, 16-byte node UUID, eight-byte incarnation, 32-byte state digest, eight-byte
state length, 32-byte key-bundle digest, eight-byte key-bundle length, one-byte DER
signature length and that signature (at most 72 bytes). Both signatures require
an independently selected trusted root. This is delivery authority, **not**
permission to serve files or participate in consensus.

Installation needs only that public root and the node's existing protected
identity/wrapping keys. It verifies the exact file streams and assigned key
envelopes before decrypting into a new owner-only directory. It checks SQLite
integrity, the persisted recovery identity/source position and retained history
closure, then synchronises files/directories before issuing a node-signed
`installed.json`. The attestation signs the distinct
`MeshSpan recovery state installation v1` domain, a zero byte, and the complete
signed transfer record. It cannot substitute for a key-only installation report.

The external installer uses the normal daemon layout: `root-authority.sqlite3`,
the two filesystem journals under `filesystem/`, identity-bound `local.sqlite3`,
and the node's existing identity/wrapping keys under `secrets/`. It generates fresh node-local
TOTP/passkey ceremony keys and saves the independently supplied public root as
`recovery-root.der`. These private keys are copied only within the same node;
they are never included in exported packages. No first-boot claim, consumed-claim
history or configured setup receipt is fabricated. Internal disposable recovery
workspaces retain their preparation layout and do not duplicate private keys.

Initial admission verifies those same runtime journal paths. For a replacement
gateway it then initialises only missing node-local branch heads from the verified
recovered converged heads before metadata activation. This is an idempotent local
projection, not a new namespace commit or permission grant; existing local heads
are preserved and storage-only nodes do not gain gateway branches.

`state.auth` is published before any database or key installation. Normal daemon
startup treats its presence as a pending-recovery fence, including after an
interruption, and returns `RecoveryAdmissionRequired` before generating a new
identity/claim or opening services. This is not a completed recovery lifecycle:
the root-authorised identity/setup and membership admission transition must still
be implemented and verified. Removing the marker is not a supported admission
procedure and does not remove the metadata consensus fence.

For a common state-set package containing projected replacement providers, the
installer also accepts repeated `--storage-target TARGET_STATE_DIRECTORY STORAGE_FOLDER`
options (at most 1,024). Each directory must be the original node-local directory
used to prepare and restore that target. The installer verifies its node-signed
target report against the selected transfer, the projected provider/marker and
the actual exclusively reopened folder and existing journal. It then records the
folder and journal locations in the installed node's `local.sqlite3`, without
inventing a user registration command or changing replicated metadata.

The original target-state directory is **permanent node state, not disposable
export staging**. Its journal is reused in place, including committed WAL state;
it is not cloned into a second independent write history. Retain both that
directory and the storage folder. Normal startup discovers these bindings and
rechecks current provider authority and the required applied revision before
opening them with current permit keys. A missing journal fails closed rather
than creating an empty replacement. Folder listings include recovered targets,
but only an actually opened provider is shown as active. This local attachment
is not fresh all-node readiness or recovered service admission.

These commands refuse existing output directories: no running state is replaced.
A failed/interrupted run may leave private partial work, including plaintext;
that work has no successful installation receipt and must not be used as an
admitted node. Retry into a fresh directory. Storage copying, protection proof,
all-node readiness and recovered-service activation remain separate
steps. The persisted recovery admission fence stays in place and both reports
state `service_started: false` and `admission_ready: false`.

The physical restoration executor can reconstruct an archived stripe from verified
salvage slices and write its selected replacements through normal storage-provider
reservations. It verifies the complete request set before IO and all selected
regenerated slices before any write. One reconstruction supplies the whole bounded
batch; no content decryption key is needed. A partial failure can leave a durable
prefix, whose exact receipts are recovered by replaying the same operation IDs.
The caller must retain returned receipts and separately authorise route changes;
neither this executor nor the state installer asserts a committed metadata revision
or restored fault-domain protection. The restoration, collection and route-export
steps below now compose these mechanisms; live recovery admission remains outstanding.

### Exact state-package installation collection

For a multi-node recovery, export every selected node from one frozen view:

```sh
meshspan-daemon export-recovery-state-set recovery-work/prepared.sqlite3 recovery.bundle recovery.code backup.msb new-state-set
```

The exporter snapshots the coordinator once, derives routes and all recipient key
bundles from that snapshot, then atomically projects canonical replacement node,
host, role, wrapping-key, certificate and secret-recipient records into the copy.
Retained ciphertext does not change; old node wrapping authority is retired and
the prepared successor CA/permit generations become the candidate heads.
Storage-only nodes receive exactly the fresh permit-key envelope needed by their
provider, not any volume, authentication, public-TLS, CA or historical key envelope.
Both the signed role selection and actual recipient set are checked; metadata-only
nodes receive no secret envelopes. This key distribution does not add consensus
membership or gateway roles. The original
coordinator remains unchanged. Schema 114 seals the projection after the atomic
transaction; it cannot be partially committed or reopened to alter recipients.

Collected replacement folders are also projected into normal storage-target,
generation, provider-component and configuration records in that transaction.
Each stored report is revalidated against the selected node, incarnation and
recovery signature before use. Original targets are retired in the candidate;
their immutable generation/marker history remains available for archive checks.
Paths remain node-local. No backing-device or filesystem identity is invented
from a folder report.

Schema 115 records the provider's creator as the saved offline recovery authority,
not an administrator or fabricated service account. Ordinary component creation
still requires its real user/service principal; the two origins are mutually
exclusive and immutable. Recovered creation is allowed only during the matching
open projection. Normal target validation, including draining-scope rejection,
is retained. These are candidate records: node-local runtime installation,
membership, fresh readiness and final service admission still must complete.

A fresh snapshot captures those exact bytes, and the exporter encrypts the
metadata/history archive once for the selected wrapping keys.
Each `new-state-set/NODE_UUID` is an ordinary three-file
package usable by `install-recovery-state`. The encrypted `state.msb` bytes are
identical across packages; the key bundle and root-signed transfer remain bound
to the exact node/incarnation. Same-filesystem hard links avoid storing N copies
of the archive in the export directory. They are only a space optimisation: each
recipient verifies the signed hash while copying its package into private state.
Package bytes must not be edited in place. Copying a package to another machine
does not require preserving hard links.

The command removes its fixed plaintext staging files and any SQLite sidecars
created while verifying those copies, after connections close, before publishing transfer
authorisations. An interrupted export may leave partial private work; it is not a
completed set. Retry into a fresh directory. A node may install a complete
individual package, but cannot bypass the all-node check or its admission fence.
Subsequent coordinator changes do not alter an exported set; a newly selected
candidate needs a fresh export and its own installation acknowledgements.

The coordinator can retain a node's acknowledgement of the exact package it
intends to use, separately from key-only or shard-copy reports:

```sh
meshspan-daemon collect-recovery-state recovery-work/prepared.sqlite3 recovery.bundle recovery.code new-state-package/state.auth new-installed-state/installed.json
```

The expected `state.auth` is independently selected by the coordinator. The node's
report cannot choose it. Closed JSON validation checks the displayed node, digest
and signing message against that expected transfer; the selected node's signature
must then verify the reconstructed message. The transfer's root authorisation,
original recovery, exact node/incarnation and credential fence are checked again.
Schema 113 retains immutable `(node, encrypted-state digest)` receipts with their
complete transfer and signature. Exact retry preserves the first collection time;
a failed insert leaves no partial receipt. Older packages remain separate history.

The typed installation-set check requires one expected package for every selected
replacement node, the same encrypted-state digest and length across that set,
and verifies every corresponding stored receipt in one read view. Independently
valid acknowledgements from different exports cannot be combined into one set.
Empty, incomplete, duplicate or unselected sets fail. It validates the complete
sealed preparation once per check, not once per node. An old package's acknowledgement
cannot satisfy an explicitly newer package, even when the original backup and key
bundle are the same. Key-only acknowledgement is insufficient.

This is **not** an admission operation or an implicit selection of the latest state.
The set exporter supplies one frozen candidate with canonical node/key/provider records,
but its reported `reserved_revision` is not yet applied. The final activation
workflow must select the intended set, account for subsequent preparation changes, check
current certificates and required storage availability, and atomically activate
the prepared runtime, including node-local provider state and replacement membership.
Those integration steps remain open.
Collection leaves the metadata head and consensus recovery fence unchanged and
reports `service_started: false` and `admission_ready: false`.

### Replacement consensus permission

After collecting every selected node's installation receipt, the offline
coordinator can authorise the exact common state set:

```sh
meshspan-daemon authorize-recovery-consensus recovery-work/prepared.sqlite3 recovery.bundle recovery.code new-state-set consensus.permission
```

The selected replacement manifest determines the package directories; an arbitrary
directory listing does not select membership. Every expected transfer and stored
node signature is verified in the same transaction as the decision. Missing,
duplicate, foreign or mixed-state installations cannot produce permission.
Partition schema 116 retains one immutable signed decision per preparation.
Retries return the original bytes, including after output-file publication fails;
a competing state set cannot replace that decision. Existing output files are
accepted only when private and byte-identical, never overwritten.

`RecoveryConsensusAdmission` uses the distinct version-one `MSRCNSNS` framing:
root-signed recovery authorisation, common encrypted-state SHA-256 and exact
length, followed by the offline root signature. Integers are big-endian; the
complete record is bounded to 512 bytes. The embedded authorisation binds the
swarm, partition, source log/revision, recovery epoch, replacement manifest and
content inventory. Receivers require an independently selected root. A state
transfer, installation signature or other signed message is not this permission.

This permission is for forming replacement consensus, **not** proof of current
storage protection or file-service readiness. Issuance neither edits installed
nodes nor advances metadata, clears either startup fence or starts a service.
The node-side application is described below. Fresh live readiness remains a
separate, unfinished gate. Do not delete `state.auth` to bypass recovery checks.

### Replacement consensus activation

On each installed replacement, the offline permission can now be consumed with:

```sh
meshspan-daemon admit-recovery-state installed-node-state consensus.permission
```

This command verifies the independently supplied root, exact transferred state,
selected identity and node-owned keys, retained filesystem history and sealed
replacement projection. It durably stores the signed permission before applying
one metadata transaction. Normal startup resumes that exact intent if interruption
occurs between those steps; it never creates a first-boot claim or fabricates a
local create/join transaction. Verification runs on an owned blocking worker
during normal daemon startup.

Partition schema 117 distinguishes a root-authorised recovery origin from a
normal Raft membership transition. Activation installs the selected membership
and successor epoch, clears the old vote at a higher term, applies the reserved
metadata revision and retains an immutable receipt with the previous plan. The
backed-up applied log is retained; only its unapplied tail is removed. Retired
source nodes no longer appear in the current membership projection. Exact retry
returns the original activation revision without resetting later votes or log
entries. Neither the preparation record nor `state.auth` is deleted.

The command starts no service and reports `admission_ready: false`. Real-process
coverage currently reaches configured HTTPS startup on a recovered gateway, but
the two-node acceptance still fails on the storage-only replacement: the current
daemon composition assumes a local consensus member and gateway services.
Storage-only composition, fresh all-node readiness, returning-node fencing and
recovered HTTPS/SMB file access remain open. Do not interpret local activation
or the configured setup response as proof of those outcomes.

### Replacement storage preparation and collection

A selected storage-role node can prepare an existing folder using its recovery
package, independently trusted public root and local private keys:

```sh
meshspan-daemon prepare-recovery-target new-state-package root.der node-identity.pk8 node-wrapping-key.x25519 storage-request.json target-work
meshspan-daemon collect-recovery-target recovery-work/prepared.sqlite3 recovery.bundle recovery.code target-work/target.report
```

The protected request uses the existing storage-folder request contract:
`operation_id`, `path` and `usage_limit` (percentage or decimal byte ceiling).
Use a separate operation/work directory for each folder. Paths stay node-local;
the portable report contains no path. These are headless recovery building
blocks, not an instruction for ordinary users to manage internal shard placement.

Preparation verifies the package's selected node/incarnation and storage role,
persists its exact intent before touching the folder, then uses the normal
exclusive ownership, capability probes and durable marker installation. Only
the private `.meshspan` directory is used; sibling files remain untouched.
An exact retry reopens that target and reproduces its signed report. Changed
intent, another target or a live owner is rejected. Preparation does not install
metadata, store shards, observe available capacity or enable serving.

The closed binary `target.report` is at most 512 bytes. Its signed message is
ten-byte `MSRTARGET`/version-one magic, big-endian two-byte original-authorisation
length and encoded authorisation, node UUID (16 bytes), incarnation (8), operation
UUID (16), fresh target UUID (16), generation (8, initially one), marker fingerprint
(32), usage kind (one byte: 1 percentage, 2 fixed-byte ceiling) and usage value (8). All integers
are unsigned big-endian. The message is followed by a one-byte DER node-signature
length and that signature (8–72 bytes). Unknown kinds, trailing bytes and invalid
bounds are rejected. The original authorisation must verify against the public
root; the report signature must verify against the exact selected node identity.

The coordinator records immutable, target-ID-pageable reports in isolated
preparation metadata (schema 111). It checks the current recovery fence, selected
storage node/incarnation, signature and fresh target identity. Exact replay keeps
the first record; conflicting operation/target identities never replace it.
No row becomes an active target or provider. Both commands report
`service_started: false` and `admission_ready: false`. Physical restoration,
authoritative route installation and recovered-service admission remain separate.

### Physical restoration into a prepared target

The selected node can restore retained slices from one original target into its
prepared destination without receiving the offline private root:

```sh
meshspan-daemon restore-recovery-target new-state-package root.der node-identity.pk8 node-wrapping-key.x25519 target-work restore-request.json
```

The protected request contains destination `path`, `inventory_directory`, original
`source_target_id` and decimal `source_generation`. Paths are local bindings, not
identity. The command verifies the selected node and its target attestation, then
restores fresh metadata/history from the authenticated encrypted package on every
attempt. It never treats previously staged mutable SQLite files as source authority.
The original target must exist in the authenticated source metadata. Source and
destination locations must not overlap.

The retained-tree walker selects referenced manifests, including snapshots, and
restores the selected source target's recorded slices. Each stripe is reconstructed
and hash-verified against the archive before normal provider reservation/write
operations. Work is bounded by one stripe, receipts stream to disk, capacity limits
still apply, and the destination is held exclusively. No volume decryption key,
running donor or original target journal is needed. Old target IDs are not adopted.
This is physical copying; fault-domain placement and live routes are not inferred
from a one-original-target-to-one-destination copy.

Stable operation IDs bind the recovery, destination and exact original receipt.
Partial failures leave durable provider progress, not a completed restoration
claim. Retry rebuilds its temporary authenticated state and resolves those same
operations. Each source target has its own locked work directory beneath
`target-work`; normal provider journals persist separately across retries.
Shared retained references may repeat receipts, but never duplicate their physical
shards. These counts describe receipt references, not distinct logical files.

On success, `receipts.bin` starts with eight-byte `MSRRCPT`/version-one magic,
followed by two-byte big-endian length-prefixed version-one data-plane shard
receipts (126 bytes each). A node-signed `restored.json` binds the target's complete
attestation message, original target/generation, SHA-256 of that entire stream,
receipt count and encrypted-byte count. Its signature domain is
`MeshSpan recovery target restoration v1` followed by a zero byte; UUIDs are
16 bytes, generation/counts are unsigned eight-byte big-endian integers and the
digest is 32 bytes. Existing published output must match exactly. Temporary
plaintext is removed before successful stdout is returned. Failed private work
may remain and is checked/cleaned on retry.

The coordinator independently verifies these receipts and their completeness
through the collection step below before they can be used in later route/admission
work. The node command explicitly reports no service start, admission readiness or
restored fault-domain protection.

### Collecting restored-shard evidence

The coordinator compares a node's complete output with the independently selected
encrypted archive, then retains its verified receipt stream:

```sh
meshspan-daemon collect-recovery-restoration recovery-work/prepared.sqlite3 recovery.bundle recovery.code backup.msb node-restoration-output collection-work
```

It validates the closed `restored.json`, original root authorisation, selected
node signature, previously collected target identity and exact original target
generation. Displayed counts/digest must equal the signed message. It restores
fresh source metadata/history from the authenticated archive and walks retained
manifests independently of the node's report. Every expected operation, shard,
length, digest and destination must match in order; missing or extra records,
noncanonical framing and a mismatched whole-stream digest are rejected. A valid
node signature alone cannot make a different archive receipt acceptable.

The comparison writes a private validated stream copy. Only afterwards does one
local SQLite transaction retain the complete signed claim and its ordered receipts
in schema 112. Memory is bounded by a receipt, not the full stream. Failed input,
incomplete streams and failed inserts roll back the entire collected result; exact
retry preserves its first receipt time. Reopening revalidates stored signatures,
identity, contiguous ordinals, counts and the complete stream hash. This is a
node-attested durable-copy claim matched to the archive, not a fresh physical
availability probe. The work directory must be separate from all input locations;
owned temporary plaintext is cleaned before successful stdout.

Collected rows are not live target/provider or shard-route rows. A subsequent
state export can prepare their routes in its isolated catalogue as described above.
Provider registration, restored protection assessment, replacement membership and
live service admission remain outstanding. No collector result clears the recovery
fence or publishes a cluster revision.

## 17. Replace or reconfigure a component

1. An administrator or authorised automation submits the implementation ID,
   contract/schema versions and canonical desired configuration through the
   public API.
2. Authority validates syntax, permissions, compatibility, secrets and required
   node support, then commits a new desired revision and audit event.
3. Assigned nodes prepare the instance using their local binding, activate that
   exact revision idempotently and publish observed state.
4. The UI/API reports desired and observed revisions separately until the
   rollout reaches its declared availability condition.
5. For a replacement, old and new compatible instances coexist while exports,
   targets or work are moved through their ordinary drain/activation flows.
6. Retirement occurs only after authoritative references are gone and safety is
   proved. Rollback commits a new revision selecting the prior compatible value.

Executable code is deployed and verified separately; metadata never executes a
payload supplied as configuration. A replacement administration panel simply
uses the same public API and needs no server-side migration.

## 18. Continuous physical churn

1. A link, node or target disappears during arbitrary foreground/background
   work. The affected operation becomes typed failure, retryable or unknown; no
   disconnect itself is success.
2. Authority and storage availability are recomputed from reachable verified
   facts. Operations that remain safe continue through other gateways/targets.
3. Repair is queued according to actual protection risk and grace policy while
   repeated presence events are coalesced.
4. The resource returns with stable identity and a new process incarnation where
   applicable. Stale streams, leases, work claims and configuration observations
   remain fenced.
5. Consensus catches up, provider journals resolve, inventories reconcile and
   current shards/configuration are verified.
6. Eligible services resume and redundant repair work is cancelled or completed
   safely without administrator choices.

Below the decode threshold, MeshSpan cannot read the affected existing bytes or
perform a random modification that requires them. Without any writable durable
medium it cannot acknowledge new bytes. Loss of quorum alone pauses converged
head, strong-publication and control operations but does not pause eligible
eventual branch work. Every limitation is reported exactly and clears
automatically when resources return.

## 19. Require a complete local copy

1. An authorised principal attaches a locality policy to a volume, folder or
   file, choosing inheritance, required cells, per-cell protection and commit
   mode.
2. The owning metadata partition resolves the effective policy against a fixed
   namespace/policy revision and commits it as desired state.
3. The placement planner proves current feasibility and creates bounded copy or
   recoding work for every existing retained file version in scope.
4. Workers create verified CoW placements in each cell. Per-version/cell status
   advances independently from `pending` to `complete` or an exact degraded
   state.
5. New writes use the best currently reachable placement and return the exact
   `node_local`, `cell_replicated` or `globally_converged` receipt scope. Missing
   required cells become explicit locality/protection debt, not a network wait.
6. During disconnection, gateways report their exact latest local branch and
   its achieved protection. Reconnection transfers immutable versions,
   reconciles branches and restores desired locality automatically.

Policy removal drops the requirement only after an authorised commit. Existing
bytes remain until the guarded reachability/cleanup lifecycle proves them
unneeded by protection, another locality rule or a snapshot.

## 20. Create, expire and restore a snapshot

1. A manual request or committed schedule selects one exact current namespace
   commit in the volume's owning partition.
2. Authority creates a named snapshot root referencing that commit, captured
   policy revision and requested retention/locality policy. No file bytes are
   copied.
3. The snapshot is immediately listable/read-only. Any additional locality work
   has its own status and does not mutate the root.
4. Expiry/removal drops the snapshot reference only after policy and open-handle
   checks. Reachability and guarded cleanup run later.
5. Whole-volume restore creates and validates a new namespace commit derived
   from the snapshot, then atomically advances the current volume head.
6. File/folder restore path-copies selected historical objects into a new current
   namespace commit while reusing immutable content.

Restore never rewinds consensus or erases the snapshot/intervening commit
history.
