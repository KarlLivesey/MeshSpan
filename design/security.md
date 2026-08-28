# Security and trust model

Status: draft for review. MeshSpan assumes faults and hostile input everywhere,
but does not claim Byzantine consensus against a malicious authorised quorum.

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

Trust is operation-scoped and non-transitive. Authentication, TLS, a successful
system call, a database constraint, a catalogue row, a checksum, a durability
receipt or an earlier scrub can contribute evidence; none converts its subject
into permanently trusted data. Each boundary validates the exact properties its
operation relies on.

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

The accepted root/wrapping/recovery ceremony is decision D-056 and is detailed
in `stage-0-review.md`. Secret-store implementation must preserve that boundary.

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
- Storage read and removal permits use canonical domain-separated keyed BLAKE3
  MACs. The provider verifies the MAC and every bound identity, revision, epoch,
  incarnation and expiry; a plain digest supplied by a caller is never authority.
- Permission changes and principal disablement increment epochs/revisions used
  to invalidate capabilities and sessions.
- Administration and content access are separate; break-glass access is explicit,
  time-bounded, strongly authenticated and audited.

## Network and protocol threats

- Every public or private message is parsed as hostile, even when sent by an
  authenticated administrator, enrolled node, current voter or another local
  component in the same process.
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

- All stored bytes and metadata are suspect on every read. Consumers verify
  bound identity, length, digest, generation/revision and semantic constraints
  before the bytes can affect visible content, authority, placement, repair,
  deletion, snapshots, backup or recovery.
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

Every HTTPS route is default-deny without explicit access metadata. Cheap
framing, route, method and media-type checks occur before authentication;
authentication, coarse authorisation and admission occur before expensive body
acceptance or work where the protocol permits. Anonymous schema, health, login,
enrolment and ACME routes are explicit, bounded and independently abuse-limited.

Rust validates every public request and outgoing response. Generated Zod
validation is web-client defence in depth and is never assumed for CLI,
third-party or hostile callers. Pagination re-applies current permissions;
authenticated conditional validators incorporate the caller-visible
authorisation projection.

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
- A majority partition preserves one converged control history. An isolated node
  may spend its authorised quota and local capacity on ordinary filesystem
  branch commits, but cannot claim remote durability or mutate identity,
  permissions, voters, secrets, executable selection or global policy.
- Offline authorisation uses a signed committed identity/configuration revision,
  a bounded isolation policy and the actor/session recorded in every branch
  commit. Reconciliation rejects unauthorised control effects without deleting
  acknowledged file content.
- Authority may pre-allocate an isolation delegation to a node/cell. It binds
  namespace scopes, permitted ordinary operations, identity/ACL revision,
  target/cell set, per-node byte budget, validity interval and delegation epoch.
  Each node receives a disjoint budget and records consumption durably, avoiding
  an offline global counter that could be overspent independently.
- A storage target accepts an isolated peer write only with an exact
  operation/shard/target capability derived from such a delegation. The target
  verifies the signed delegation, mTLS identity, local durable remaining budget,
  expiry and target generation before writing. Local same-daemon writes still
  pass the identical branch-policy and quota checks.
- Revocation cannot cross a severed link instantly. Policy therefore bounds the
  maximum isolation interval and privileged operations always require live
  authority. Reconnection applies current access rules to visibility while
  preserving content that was validly acknowledged under its recorded
  delegation.

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

## Component configuration

- Replicated metadata may select installed implementation IDs and carry bounded,
  schema-versioned configuration; it never carries executable code or loader
  paths.
- Component configuration is hostile input even when submitted by an
  administrator. Deterministic validation occurs before commit and node-local
  validation occurs before activation.
- Secret fields are references or encrypted generations, not plaintext embedded
  in generic configuration.
- Local bindings cannot override mesh-level authority and cannot make a component
  active under a different desired revision.
- A replacement administration panel has exactly the public API rights of its
  authenticated principal and no implicit trust from being served by the daemon.
- Component support/health reports are observations and cannot self-authorise
  installation, assignment or configuration changes.

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
