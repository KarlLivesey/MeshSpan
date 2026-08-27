# MeshSpan requirements

Status: **draft for review**.

## Product contract

- **SYS-001** MeshSpan MUST combine registered storage folders across one or more nodes into one
  shared filesystem namespace.
- **SYS-002** The same implementation and record model MUST operate from one node to many nodes.
- **SYS-003** MeshSpan MUST automate ordinary placement, reconstruction, healing, rebalancing,
  certificate handling and membership work.
- **SYS-004** MeshSpan MUST refuse an operation it cannot perform safely and MUST NOT fabricate
  durability, authority or success.
- **SYS-005** Routine use MUST NOT require administrators to select erasure geometry, shard
  locations, metadata leaders or conflicting internal versions.
- **SYS-006** All externally supplied data MUST be treated as hostile and validated before use.
- **SYS-007** The normal deployment MUST be one self-contained daemon plus its compiled web assets;
  it MUST NOT require Kubernetes, an external database, proxy, message queue, Samba or FUSE.
- **SYS-008** The daemon, including storage, HTTPS and SMB gateway capabilities, MUST run natively on
  supported Linux and macOS hosts and in the supported container image; nodes in one mesh MAY mix
  supported operating systems and architectures.

## Hosts, nodes and membership

- **CLU-001** A host MUST represent a physical machine failure domain independently of daemon
  process identity.
- **CLU-002** A node MUST represent one enrolled daemon identity and MAY share a host with other
  nodes without manufacturing an additional host failure domain.
- **CLU-003** A one-node mesh MUST be useful and MUST report that it lacks node redundancy.
- **CLU-004** A running mesh MUST support online enrolment and growth without conversion from a
  standalone format.
- **CLU-005** A joining node MUST generate its private identity keys locally; private identity keys
  MUST NOT leave that node.
- **CLU-006** Join grants MUST be administrator-issued, expiring, use-limited and bound to one mesh.
- **CLU-007** UI, API and headless enrolment MUST execute the same authoritative transaction.
- **CLU-008** A node MUST support headless startup with a daemon state directory, storage paths and
  join material.
- **CLU-009** Metadata voter membership MUST remain independent of unbounded storage membership.
- **CLU-010** A side holding voter majority MAY continue authoritative mutations during a partition;
  a side without authority MUST NOT acknowledge authoritative mutations.
- **CLU-011** A stale node or process incarnation MUST be fenced from publishing state after
  replacement.
- **CLU-012** Eligible storage nodes SHOULD be promotable to replace unavailable voters through a
  surviving majority.
- **CLU-013** Discovery MAY advertise non-sensitive enrolment endpoints over local IPv4 and IPv6,
  but manual endpoint entry MUST remain available and identity MUST NOT depend on an IP address.
- **CLU-014** Possession of a valid administrator-issued join grant MUST be sufficient to perform
  its bounded pre-authorised enrolment without a second interactive approval step.
- **CLU-015** Node availability profiles and role restrictions MUST prevent unsuitable intermittent
  nodes from being selected as voters while allowing deliberately registered storage to leave and
  return safely.

## Storage targets and fault groups

- **TOP-001** One daemon MUST accept multiple registered storage-folder paths.
- **TOP-002** Registration MUST use existing folders without formatting, partitioning or mounting
  devices.
- **TOP-003** Folder size and filesystem type MUST NOT be assumed uniform.
- **TOP-004** A storage target MUST have a stable identity independent of its path spelling.
- **TOP-005** Machine, daemon, target, backing device and filesystem identities MUST remain distinct.
- **TOP-006** Hosts and storage targets MAY belong to multiple overlapping fault groups.
- **TOP-007** Fault-group classes and instances MUST be administrator-definable; machine and backing
  device groups MUST be created automatically where they can be proved.
- **TOP-008** Placement MUST evaluate the union of resources affected by simultaneous group failures.
- **TOP-009** Uncertain or contradictory failure-domain identity MUST reduce placement eligibility;
  it MUST NOT manufacture independence.
- **TOP-010** A topology change MUST expose any resulting loss of protection and queue safe movement
  when capacity permits.
- **TOP-011** Provider folders MUST contain only private provider records and shards; they MUST NOT
  mirror the user-visible namespace or become an alternate access path.
- **TOP-012** Folder-provider storage layout, indexing, packing and compaction MUST remain behind a
  provider interface and MUST avoid requiring one operating-system file per small shard.

## Protection and data lifecycle

- **DAT-001** Users MUST express required failures to survive; ordinary users MUST NOT select Reed–
  Solomon geometry.
- **DAT-002** A volume MAY contain immutable data encoded with different layouts while retaining one
  user-visible protection promise.
- **DAT-003** One-node data MUST use an explicitly unprotected layout rather than fake redundancy.
- **DAT-004** A write MUST NOT become visible until every shard required by its chosen layout is
  durable and verified and its metadata version is committed.
- **DAT-005** Stored shard identities and contents MUST be immutable after publication.
- **DAT-006** Logical content and stored shards MUST carry cryptographic integrity digests.
- **DAT-007** Reads MUST verify content and SHOULD reconstruct from surviving shards without waiting
  for background repair.
- **DAT-008** Periodic scrub MUST detect missing and corrupt shards independently of client reads.
- **DAT-009** Reduced protection MUST create durable, bounded repair work and SHOULD heal without
  administrator intervention when eligible capacity exists.
- **DAT-010** A shard MUST NOT be deleted using location as authority.
- **DAT-011** Deletion MUST require an exact irreversible cleanup decision, current validation and a
  durable local tombstone before bytes become unreachable.
- **DAT-012** Interrupted, replayed, partial, out-of-space and indeterminate writes MUST recover
  without exposing partial files or leaking unbounded storage.
- **DAT-013** Storage and repair reservations MUST prevent concurrent work from double-spending
  capacity and MUST preserve configured repair reserve.
- **DAT-014** Folder and host drain MUST move authoritative data and prove safety before reporting
  that removal is safe.
- **DAT-015** The placement engine MUST support heterogeneous capacity and performance weights while
  treating failure independence as a hard constraint rather than a weight.
- **DAT-016** Logical chunks, shards, manifests, snapshots and provider records MUST use a reviewed
  cryptographic integrity algorithm with deterministic cross-implementation test vectors.
- **DAT-017** Capacity admission MUST preserve configurable repair and temporary-work reserve; it
  MUST block unsafe new writes before consuming space needed to honour existing promises.
- **DAT-018** Volumes MUST be thin-provisioned with an optional logical quota and MUST report both
  logical and actual protected physical consumption.

## Filesystem namespace

- **FS-001** Files and folders MUST have stable identities that survive rename and move.
- **FS-002** Directory names MUST be unique under their parent after canonicalisation.
- **FS-003** Published file versions MUST be immutable; a file object MUST identify its current
  published version atomically.
- **FS-004** The filesystem service MUST support atomic open semantics including desired access,
  sharing access and create disposition.
- **FS-005** It MUST support bounded random reads and writes, length changes, flush, close, rename,
  deletion, enumeration and metadata operations.
- **FS-006** Cross-gateway share modes, byte-range locks and delete-on-close state MUST be governed by
  authoritative metadata.
- **FS-007** A dirty flush MUST publish exactly one committed file version or report an unknown
  outcome resolvable by operation ID.
- **FS-008** Access adapters MUST use the filesystem service and MUST NOT read provider folders or
  database records directly.
- **FS-009** Extended attributes and named streams MUST have bounded protocol-neutral representations.
- **FS-010** Each volume MUST have an explicit, immutable-at-creation name policy; the ordinary
  default SHOULD be case-preserving, case-insensitive and portable across supported access clients.
- **FS-011** Large manifests MUST be divided into immutable, bounded and independently verified
  blocks rather than embedded as unbounded consensus commands.
- **FS-012** Copy MUST have defined same-volume semantics and MUST preserve permissions, ownership,
  tags and content identity according to an explicit policy.

## Principals, groups, ownership and tags

- **IAM-001** Users and groups MUST share one principal identity namespace.
- **IAM-002** A user MAY belong directly to multiple groups.
- **IAM-003** A group MAY contain users and other groups.
- **IAM-004** Group membership MUST NOT contain direct or transitive cycles.
- **IAM-005** Nested-group membership MUST be evaluated consistently across all gateways.
- **IAM-006** A file or folder MUST have one or more owner principals.
- **IAM-007** An owner principal MAY be a user or group, and one object MAY have multiple owners.
- **IAM-008** Direct and transitive members of an owning group MUST receive effective ownership.
- **IAM-009** Ownership MUST survive content updates, rename and move.
- **IAM-010** Removing or disabling the last active owner MUST require an atomic ownership transfer.
- **IAM-011** Ownership and permission changes MUST be audited.
- **IAM-012** Files, folders, users and groups MAY carry multiple tags.
- **IAM-013** Tagging MUST NOT implicitly grant authority or file access.
- **IAM-014** Tags MUST attach to logical objects rather than immutable content versions.

## Permissions

- **ACL-001** A permission grant MUST target a user or group principal.
- **ACL-002** Grants MUST support volume, file and folder scope with explicit inheritance behaviour.
- **ACL-003** Grants MUST support optional activation and expiry instants.
- **ACL-004** A cached decision MUST NOT outlive its session, source grants, identity revision,
  gateway fence or authority validity.
- **ACL-005** Permission evaluation MUST include direct membership, transitive group membership,
  object ownership and inherited folder grants.
- **ACL-006** The internal rights model MUST distinguish traversal, listing, data read/write,
  creation, rename, deletion, attributes, permissions and ownership changes.
- **ACL-007** The ordinary UI SHOULD present understandable permission presets while advanced
  interfaces MAY expose individual rights.
- **ACL-008** Permission evaluation MUST be deterministic and independent of the serving gateway.

## Authentication and sessions

- **AUTH-001** A user MUST be able to enrol multiple independently revocable authentication methods.
- **AUTH-002** The model MUST support password, WebAuthn/passkey, TOTP, recovery-code, API-token,
  client-certificate and SMB-scoped credential records without combining their secret formats.
- **AUTH-003** Raw passwords, session tokens, API tokens and recovery codes MUST NOT be persisted.
- **AUTH-004** Authentication policies MUST support factor count, factor class, service scope,
  session lifetime and recent step-up requirements.
- **AUTH-005** Administrative operations SHOULD require recent strong authentication.
- **AUTH-006** Sessions MUST be usable consistently across authorised gateways and revocable across
  the mesh.
- **AUTH-007** Authentication throttling and security events MUST be mesh-wide so changing gateways
  cannot bypass them.
- **AUTH-008** Credential and secret material at rest MUST be hashed or encrypted according to its
  verification needs.
- **AUTH-009** Authentication failure MUST NOT reveal whether a user or individual factor exists.

## Access services

- **ACC-001** MeshSpan MUST provide built-in HTTPS and standards-compliant SMB services.
- **ACC-002** The SMB service MUST be implemented inside the Rust daemon without Samba or FUSE.
- **ACC-003** Multiple gateways MAY expose the same authoritative namespace concurrently.
- **ACC-004** The same user identity and permissions MUST apply through HTTPS and SMB.
- **ACC-005** HTTPS MUST provide authenticated administration, file browsing, upload and download.
- **ACC-006** SMB MUST support the filesystem operations and acknowledgement semantics required by
  the selected SMB compatibility profile.
- **ACC-007** Public services MUST remain usable on supported Linux and macOS hosts and in the
  supported container environment.
- **ACC-008** HTTPS uploads MUST be resumable, bounded and recoverable after client disconnect;
  downloads MUST stream, support ranges and stable version-derived validators without whole-file
  gateway staging.
- **ACC-009** Each eligible gateway MAY expose HTTPS and SMB concurrently; gateway selection MUST
  NOT create a single active namespace or credential owner.

## Certificates and secrets

- **PKI-001** Every enrolled node MUST have a mesh-bound identity certificate.
- **PKI-002** Node and user-facing certificate private keys MUST be protected at rest and in transit.
- **PKI-003** ACME MUST support HTTP-01 and DNS-01 challenges.
- **PKI-004** Only one fenced worker MAY act on a certificate order at a time.
- **PKI-005** An issued certificate and private key MUST be delivered as node-specific encrypted
  envelopes to authorised gateways.
- **PKI-006** Renewal, failed-order retry and worker replacement SHOULD be automatic.
- **PKI-007** Secret rotation MUST identify generation, recipients and installation acknowledgements.
- **PKI-008** Local installations MUST support a clearly identified mesh-local certificate, and
  administrators MAY install their own certificate without weakening private node identity.

## Administration and status

- **OPS-001** MeshSpan MUST provide user and administrator interfaces plus equivalent headless APIs.
- **OPS-002** Normal setup MUST not require editing generated protocol, consensus or certificate
  configuration files.
- **OPS-003** Status MUST report metadata authority, read availability, write availability,
  reachability and protection separately.
- **OPS-004** Slow placement, repair, scrub, drain and reconciliation work MUST be asynchronous,
  bounded and resumable.
- **OPS-005** Routine failure and return within policy SHOULD recover without administrator action.
- **OPS-006** Security- and durability-relevant administrative activity MUST be audit logged without
  secrets or file content.
- **OPS-007** The default dashboard MUST answer protection, availability, capacity, failures,
  background work and required action in plain language without consensus or erasure-code jargon.
- **OPS-008** The user interface MUST be keyboard accessible, screen-reader understandable,
  responsive on a phone, colour-independent and respectful of reduced-motion preferences.
- **OPS-009** User and administrator views MUST receive bounded incremental operation/event updates
  without requiring full-page reloads.
- **OPS-010** Optional email and generic-webhook notifications MUST be derived from durable,
  deduplicated events and MUST NOT contain secrets or file content.
- **OPS-011** A diagnostic bundle MUST contain versions, redacted configuration, recent bounded
  logs/events, topology, target health, quorum state and work status while excluding credentials,
  private keys, join secrets, tokens and user content.
- **OPS-012** Advanced metrics SHOULD be available in a documented scrapeable format without being
  required for ordinary administration.
- **OPS-013** Capacity and protection changes MUST show an honest feasibility, capacity and work
  estimate before commit, including uncertainty where prediction is weak.

## Persistence, upgrade and recovery

- **PER-001** Authoritative metadata MUST use transactional SQLite-compatible relational schemas.
- **PER-002** Database schema, protocol and persisted record versions MUST be explicit.
- **PER-003** Migrations MUST be transactional, restartable or fail closed before service admission.
- **PER-004** Backup and restore MUST bind an exact committed metadata position and mesh identity.
- **PER-005** Restore MUST validate integrity, membership and secret availability before admission.
- **PER-006** Upgrade and supported rollback paths MUST be tested against real published artefacts.
- **PER-007** A voter database MUST remain local to that voter and MUST NOT be shared over a network
  filesystem.
- **PER-008** Protocol, command, schema, manifest, provider, capability and export formats MUST be
  independently versioned and reject unknown incompatible versions clearly.
- **PER-009** Rolling upgrade planning MUST preserve voter majority and working gateways, negotiate
  mixed-version features explicitly and block operations unsupported by any required participant.
- **PER-010** Recoverable metadata snapshots SHOULD be copied to protected storage targets without
  allowing those copies to participate in consensus.
- **PER-011** Catastrophic metadata recovery MUST use an administrator-held recovery bundle plus a
  verified committed snapshot and target inventories; it MUST never infer a new namespace solely
  from untrusted filenames or locations.

## Scale, performance and resource safety

- **SCL-001** Protocol identifiers, paging and membership records MUST NOT impose a small fixed
  storage-node limit.
- **SCL-002** Request-path work MUST NOT scan all nodes, files, shards or users.
- **SCL-003** Enumeration, inventory and work queues MUST be revision-bound and cursor-paged.
- **SCL-004** Connection, stream, memory, file-descriptor and background-work limits MUST be
  resource-aware and configurable rather than arbitrary product ceilings.
- **SCL-005** Bulk data traffic MUST NOT starve consensus, authentication or control traffic.
- **SCL-006** Unreachable peers MUST be handled concurrently with bounded timeouts, cancellation and
  backoff.
- **SCL-007** Local development tests MUST remain partitioned and fast enough to run before push;
  CI MUST confirm rather than discover ordinary failures.
- **SCL-008** Runtime scheduling MUST use explicit priority classes so metadata, health and
  interactive IO are not starved by repair, rebalance, recoding, scrub or compaction.
- **SCL-009** Ordinary connection capacity MUST derive from available workers, memory, descriptors
  and configured budgets rather than a small hard-coded product ceiling.

## Verification and release

- **TST-001** Semantic state transitions MUST have deterministic normal, replay, conflict and hostile
  input vectors independent of database and transport implementations.
- **TST-002** Storage tests MUST inject process death, power-loss semantics, partial writes,
  corruption, read-only state and out-of-space failures.
- **TST-003** Multi-node tests MUST exercise leader loss, majority/minority and multi-way partitions,
  return, catch-up and stale-process fencing.
- **TST-004** Real HTTPS and SMB clients MUST perform create, write, flush, read, rename and delete
  cycles against the same files and users.
- **TST-005** Protection tests MUST remove every configured combination of machine, device and custom
  fault groups and verify exact reconstructed bytes.
- **TST-006** Repair, scrub and drains MUST be tested while client activity continues.
- **TST-007** Backup, restore, migration, upgrade and rollback MUST have end-to-end acceptance tests.
- **TST-008** Long-duration churn, certificate renewal and heterogeneous-capacity tests MUST precede
  a stable release claim.
- **TST-009** Native Linux and macOS daemon/gateway acceptance plus the supported container path MUST
  exercise mixed-host meshes; SMB client interoperability MAY use any standards-compliant clients
  and MUST NOT turn a client product into a service requirement.
- **REL-001** Commits and tags MUST be signed, and releases MUST publish checksums and provenance.
- **REL-002** Development branches MUST be short-lived, merged promptly and deleted after merge.
- **REL-003** The project MUST publish a container image and the accepted native platform artefacts.

## Development system

- **DEV-001** Rust builds MUST track the latest stable toolchain that passes the complete required
  suite; toolchain updates MUST be tested before merge.
- **DEV-002** The web workspace MUST target Node.js 26 and TypeScript 7.0.
- **DEV-003** Web date/time domain logic MUST use Temporal rather than introducing new JavaScript
  `Date` arithmetic.
- **DEV-004** Every Rust workspace crate and web package MUST participate in language-standard
  format, lint, type/build and test gates with warnings treated as failures.
- **DEV-005** Dependency and toolchain update pull requests MAY merge automatically only after all
  required gates pass and the update policy has not classified the change for manual review.
- **DEV-006** Fast checks MUST be runnable locally in independently parallelisable lanes; ordinary
  feature work MUST NOT depend on a completed `main` workflow before its own relevant tests run.
- **DEV-007** The web application MUST use Solid 2.0, remain a compiled static client served by the
  Rust daemon and introduce no production Node.js server.
- **DEV-008** Rust public API schemas SHOULD generate TypeScript representations so the web client
  does not manually duplicate protocol-facing types.

## Public API

- **API-001** The HTTPS API MUST have an explicit major version and typed resources for setup,
  authentication, mesh, nodes, targets, fault groups, volumes, exports, principals, groups,
  permissions, files, uploads, work, repair, certificates, events and diagnostics.
- **API-002** Long-running operations MUST return an operation ID and expose durable state, bounded
  progress, cancellation support where safe and the terminal committed outcome.
- **API-003** Errors MUST contain a stable code, plain message, request ID, retry classification and
  bounded field/remediation details while excluding sensitive data.
- **API-004** List APIs MUST use stable revision-bound cursors with explicit ordering and page
  limits.
- **API-005** API authentication and authorisation MUST use the same principals, sessions, roles,
  grants and audit rules as the user and administrator interfaces.

## Deferred capabilities

- **DEF-001** NFS, WebDAV, SFTP, S3 and other access adapters are deferred but MUST use the same
  filesystem service when implemented.
- **DEF-002** Native direct-shard clients and peer-assisted verified caches are deferred; caches MUST
  never count toward durability.
- **DEF-003** Disconnected multi-writer sites require an explicit branch-and-reconciliation model and
  MUST NOT activate implicitly when metadata authority is lost.
- **DEF-004** Whole-device management and native Windows hosting are not part of the initial MUP.
