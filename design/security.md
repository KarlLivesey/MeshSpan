# Security and trust model

Status: draft for review. MeshSpan assumes faults and hostile input everywhere,
but does not claim Byzantine consensus against a malicious voter majority.

## Assets

MeshSpan protects:

- committed user content and its existence, names and metadata;
- mesh, node, user and group identities;
- namespace, permissions, ownership and audit history;
- consensus history and durability receipts;
- node, mesh CA, ACME, HTTPS, SMB, recovery and future data-encryption secrets;
- availability within declared resource and failure limits.

## Trust boundaries

| Boundary | Assumption |
| --- | --- |
| Browser/SMB client to gateway | Untrusted network and input; authenticated user may be malicious |
| Node to node | Network is hostile; enrolled peer identity is authenticated but its input remains untrusted |
| Daemon to provider folder | Filesystem may fail, corrupt, reorder, fill or return stale bytes |
| Gateway to metadata authority | Gateway may be stale; every mutation and capability is fenced |
| Storage worker to catalogue | Worker observations are evidence, not authority |
| Administrator | May configure infrastructure; does not silently own user content |
| Voters | Crash/partition faults tolerated; malicious majority is out of scope |
| Build/update source | Untrusted until signature, provenance and gates verify it |

## Identity and key hierarchy

- A new node generates its identity private key locally.
- An administrator-issued join grant binds enrolment to one mesh, lifetime, use
  count and allowed capabilities.
- The mesh CA signs node identities. Private node keys never enter replicated
  metadata.
- Cluster secrets use generation-numbered envelope encryption. Each authorised
  node receives ciphertext for its current public wrapping key only.
- CA and recovery design must avoid one plaintext key copied to every node.
- Public-service certificate keys may be shared only through per-node encrypted
  envelopes and only with eligible gateway nodes.
- Rotation is make-before-break, fenced, acknowledged and auditable.
- Loss of required wrapping/recovery keys fails closed with exact guidance; the
  software does not manufacture a replacement mesh identity.

The precise root/wrapping/recovery key ceremony remains decision O-005 and must
be accepted before secret-store implementation.

## Authentication threats

Controls include:

- memory-hard password verification with upgradeable parameters;
- constant-shape failure responses and mesh-wide throttling;
- secure, HTTP-only, same-site cookies plus CSRF protection;
- origin checks for state-changing browser requests;
- WebAuthn challenge binding and replay prevention;
- TOTP replay window tracking;
- hashed, scoped, expiring API tokens and recovery codes;
- revocable SMB-only credentials created after strong web/admin authentication;
- session fixation prevention, rotation after step-up and mesh-wide revocation.

Authentication material is parsed by its method-specific handler; generic
credential blobs are not accepted.

## Authorisation threats

- Stable IDs, not usernames or paths, are authority subjects.
- Nested group closure is committed atomically and checked for cycles.
- Owners are an explicit many-to-many user/group relation.
- Time grants use authority-provided instants; gateway wall clocks do not extend
  access.
- Capabilities bind principal/session, operation, object/version/range, identity
  and ACL revisions, gateway/node fence and expiry.
- A capability for read cannot write; a shard ID cannot grant read; a storage
  location cannot grant delete.
- Permission changes and principal disablement increment epochs/revisions used
  to invalidate capabilities and sessions.
- Administration and content access are separate; break-glass access is explicit,
  time-bounded, strongly authenticated and audited.

## Network and protocol threats

- Quinn connections require mTLS after enrolment and exact certificate-to-hello
  identity agreement.
- Every message family has size/count/depth limits before allocation.
- Mutations carry operation IDs, request digests, deadlines and fencing data.
- Replays are idempotent only for identical requests; conflicting reuse fails.
- Unknown versions and command variants fail closed.
- Consensus/control queues remain isolated from bulk streams.
- Peer endpoints are never trusted as identity, and redirects are accepted only
  from an authenticated mesh peer.
- Diagnostics and protocol errors contain correlation IDs but no credentials,
  plaintext capabilities, paths unnecessary to the recipient or secret payloads.

## Storage and data threats

- Provider paths are daemon-private and never mirror user paths.
- Target markers bind mesh, target ID and generation; path reuse or replaced
  media cannot inherit authority accidentally.
- Writes use temporary identities, exact length/digest checks, persistence
  barriers and atomic installation before receipt.
- Reads verify shard and logical-content integrity before returning bytes.
- Corrupt or unexpected records are quarantined where feasible.
- Cleanup requires a committed unreachable decision and current exact removal
  permit; local inventory never authorises deletion.
- Scrub, compaction and recovery revalidate bytes instead of trusting the local
  index.
- Symlink traversal, mount substitution, path overlap and unsafe permissions are
  rejected at folder registration/open.

## Public-service threats

HTTPS must apply request/body/header/time bounds, safe content disposition,
upload quotas, CSRF defence and strict output encoding. Static assets use a
restrictive content security policy. File previews, if later enabled, are
treated as hostile active content and isolated.

The SMB adapter validates every length, offset, state transition and negotiated
feature before translating it. It applies resource-aware budgets but does not
claim to be a network DDoS appliance. SMB names, identities and status codes are
converted at the adapter boundary; they do not weaken canonical permissions.

## Availability and resource exhaustion

- Connection, stream, buffer, handle, upload, lock and work counts use explicit
  resource budgets rather than one arbitrary global ceiling.
- Work is cancellable, deadline-bound and scheduled by priority.
- Per-peer failures cannot create unbounded retry loops, log volume or durable
  work duplication.
- Repair reserve protects the ability to restore existing promises.
- A majority partition preserves one authoritative history; components without
  authority cannot spend capacity on acknowledged writes.

## Secrets, logs and diagnostics

Secrets are never logged. Sensitive values use redacting wrapper types so normal
debug formatting cannot expose them. Diagnostic bundles use an allow-list of
fields, not a deny-list applied to arbitrary configuration. Audit records are
hash-linked in order, bounded by retention policy and replicated with the
operation they describe where correctness requires it.

## Software supply chain

- Dependencies are minimal, pinned through lockfiles and reviewed for
  maintenance, security and legal compatibility.
- Automated updates run format, lint, build, unit, compatibility and affected
  integration gates before merge.
- Release commits/tags are signed and artefacts publish checksums and provenance.
- Runtime updates do not execute arbitrary hooks from mesh metadata.

## Recovery and break-glass

The recovery bundle contains enough encrypted authority to validate a committed
snapshot and reconstruct the mesh control plane, but no user passwords or
plaintext file data. Recovery runs with public services closed and produces an
audited new authority epoch. Old nodes and capabilities are fenced until they
are deliberately re-admitted.

Emergency content access, unsafe protection override and destructive recovery
are separate explicit actions. Each states the consequence, requires recent
strong authentication and leaves a durable audit record. The ordinary appliance
flow never uses them automatically.

## Required adversarial proof

Before MUP, tests cover malformed and oversized messages, replay, credential
enumeration, stale sessions/capabilities/fences, cross-mesh identity, path and
symlink attacks, target substitution, forged receipts/removal permits, corrupt
shards/manifests/snapshots, hostile archive names, CSRF and concurrent permission
changes. A security review must trace each public and private operation to its
authentication, authorisation, bounds, audit and failure behaviour.
