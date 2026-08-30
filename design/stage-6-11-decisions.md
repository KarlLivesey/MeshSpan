# Stage 6–11 design decisions

Status: **accepted in discussion on 2026-08-30**.

This document records the accepted product decisions for the HTTPS appliance,
embedded SMB service, protection, healing, operations and `0.1.0` proof. It is a
contract, not an implementation claim. Existing code and evidence remain subject
to the retrofit notes in the roadmap and this document.

The current generated public-API scaffold still contains password login models.
Those models are implementation debt and must be removed with their generated
types/tests before Stage 6 can pass; their presence is not an accepted exception.

## 1. Claim and authentication

- An unclaimed daemon creates one high-entropy, single-use claim bundle. The
  unauthenticated setup page and API never reveal it.
- An interactive first boot prints the bundle once. The daemon may also write it
  atomically to a configured automation file protected as `0600` or by the
  equivalent platform ACL. A daemonised process logs only the file location.
- The bundle survives restart until it is used or rotated. Successful claim
  atomically invalidates it and removes the output file where possible.
- The bundle contains enough bound node identity evidence to be entered on the
  node's setup page or submitted by an authenticated administrator to an
  existing swarm's add-node flow. Re-enabling claim after success requires local
  machine control or recovery authority.
- MeshSpan has no password authentication. Passkeys and login-capable API keys
  are primary methods; TOTP is an additional factor and recovery codes are
  single-use recovery or step-up factors.
- API keys use the same typed method and scope model for browser-session exchange,
  headless API access and SMB login. MeshSpan never creates a duplicate
  service-specific credential database or credential kind.
- A protocol may be unable to perform a particular method, for example SMB cannot
  conduct a passkey ceremony. That incompatibility does not invalidate the
  method or create a second identity.
- User client-certificate authentication is not part of the initial product.
  Node mTLS and public HTTPS certificates remain separate machine/service
  identities, not user login methods.
- The initial product has no external identity provider. The authentication
  boundary reserves a later complete OIDC/OAuth provider, including providers
  such as Google. LDAP or Active Directory must not be partially emulated.

## 2. HTTPS appliance and sharing experience

- User and administration panels are one static Solid application over the
  public API. Administration is a distinct permission-gated area; unauthorised
  clients neither receive nor see its controls.
- Clear operations, accessibility and sensible API/resource routes take priority
  over visual polish. The current stable Chromium, Firefox and Safari engines
  are supported through Chromium/Firefox/WebKit journeys. Core flows meet WCAG
  2.2 AA, keyboard, screen-reader, reduced-motion and phone-layout requirements.
- Federated content is an ordinary file, folder or volume in the namespace. It
  receives no default federation badge or special file type. Origin, receipt and
  convergence evidence is available in details/status and appears prominently
  only when it changes a result or requires action.
- Public discovery and access are independent. A share may be public/listed,
  public/unlisted or restricted. Unlisted means absent from enumeration; knowing
  the URL is sufficient and no second access secret is implied. A share may
  follow the live object or pin one immutable version.
- Audit history is append-only and hash-linked, uses configurable non-zero
  retention, indexed filters and opaque cursors, and supports bounded signed JSON
  Lines export with schema metadata. Protected recovery evidence is never
  silently discarded under pressure.

## 3. Federated delegation and repair

- Each swarm is the intrinsic root principal for every resource it owns. It may
  grant rights directly to local users/groups and separately delegate rights to
  another swarm. Ownership needs no synthetic self-federation record.
- Swarm A grants a shared resource to Swarm B, not to users or groups that A
  imports from B. A does not enumerate or administer B's principals.
- B decides which of its local users and groups receive equal or narrower rights.
  B may also re-export the accessible data through B to Swarm C with equal or
  narrower rights. C does not thereby become authorised to connect directly to A.
- Every delegation hop is attributable, preserves the owning swarm and can only
  narrow the effective rights, bounds and validity it received. Revocation and
  expiry propagate through the chain with the already accepted disconnected-work
  quarantine rules.
- A remains authority for its content, ACL and canonical protection promise. B
  may keep additional caches or copies but cannot redefine A's promise. A may
  adopt signed B placement receipts as evidence for A's policy.
- The swarm whose local protection state is being repaired coordinates that
  repair. Mutual or external swarms merely honour bounded capabilities and return
  receipts; they never control another swarm's repair plan.
- Another swarm is not inherently an independent failure location. Physical
  independence is an explicitly accepted, signed administrator assertion about
  shared-failure groups; MeshSpan labels it declared rather than cryptographically
  proven. Unaccepted or incomplete evidence may store data but does not satisfy
  the affected survival promise.
- A strong policy may explicitly require a remote swarm/location. Eventual remote
  placement never blocks ordinary writes.
- Cross-swarm deduplication is limited to content already explicitly shared under
  compatible ownership, encryption and protection contracts. MeshSpan never
  probes unrelated peer content or creates a content-existence oracle.

## 4. Embedded SMB profile

- The first service implements SMB 3.1.1 only. It rejects SMB1, SMB 2.0.2, SMB
  2.1 and SMB 3.0.2. SMB over QUIC, multichannel, RDMA, compression, clustering
  and POSIX extensions are deferred.
- Every session is signed. Encryption is required by default; an authorised user
  may explicitly relax it for an export under a trusted-network policy. Unsigned
  access is never permitted.
- SMB authenticates the ordinary MeshSpan principal using an API key whose
  normal scopes permit SMB login. It has no SMB-only credential record.
- An authorised owner, user or administrator decides whether a volume or folder
  becomes an SMB export, its share name and eligible gateways. Publication is
  replicated desired configuration; nothing implicitly exposes the whole swarm.
  SMB tree roots remain directory-like as required by the protocol.
- Durable stages, operation identities and handles permit safe reconnect through
  another gateway. Completely invisible clustered failover is not promised in
  `0.1.0`; acknowledged bytes are never lost or replayed ambiguously.
- SMB reports effective MeshSpan rights. Authoritative user, group, owner and
  grant editing remains in the common API/panel rather than pretending Windows
  ACLs represent activation and time-bounded MeshSpan authority.
- Explicit DNS/IP access always works. mDNS/DNS-SD advertisement is available
  where supported; NetBIOS discovery and legacy browsing are absent.
- A user accesses federated files through their local swarm's ordinary SMB
  export and local identity. Credentials never cross a federation hop.
- The first common-filesystem profile includes portable timestamps, basic/DOS
  attributes and bounded alternate data streams. Symbolic links, hard links,
  arbitrary extended attributes, device files and platform-specific metadata
  extensions remain deferred.

## 5. Protection, HA and physical representation

- Node count is topology, not protection. One machine with independent backing
  devices may satisfy device-loss protection while providing no machine, power
  or location survival.
- A user-defined shared-failure group names machines with one common failure
  point, for example a physical hypervisor, power source, switch, rack, room or
  building. Machines may belong to several overlapping groups. Built-in machine,
  daemon and backing-device identities remain distinct.
- The ordinary protection UI asks how many machine failures and backing-device
  failures to survive. Advanced scenarios combine those dimensions or name
  overlapping shared-failure groups. Users never select coding geometry or shard
  locations.
- Data reconstructability, read availability, write acceptance and converged
  protection are reported separately. Several drives in one machine can protect
  bytes from device loss without making reads available after machine loss.
- Ordinary authorised writes never wait merely for readable base data, voters,
  remote locations or full protection. A writable gateway may commit a durable
  CoW branch or immutable overlay referencing an unavailable base and reports
  its exact scope and debt. Physics, authority, keys, capacity or an explicitly
  strong barrier may still prevent a truthful success.
- If desired protection is currently impossible, MeshSpan uses the strongest
  valid layout, reports exact debt and upgrades automatically when resources
  arrive. Strong operations wait or fail by their deadline.
- Chunk profiles are automatic, power-of-two and benchmark-selected, aiming for
  roughly 1,024 logical chunks without a hard chunk-count ceiling. Exact coding
  geometry is automatic and recorded per stripe.
- Small final extents and shards use their actual logical length; they do not
  reserve a full profile-sized allocation.
- Providers may append small independently encrypted and authenticated immutable
  shard records to bounded packs. Exact indexed range reads avoid whole-pack read
  amplification. Updating content appends new records; it never rewrites a pack.
  Copy-on-write compaction occurs only after dead-space pressure, and pack size,
  record count and corruption blast radius remain bounded and benchmarked.

## 6. Scrub, repair and rebalance

- An integrity or partial-write violation immediately stops destructive work on
  a target. Transient IO failures feed a decaying error score; quarantine occurs
  at its threshold.
- Scrub uses time since the last successful exact verification rather than
  calendar fenceposts. A configurable maximum age supplies the fixed cadence;
  risk can bring work forward. Manual and scheduled work update the same record.
- Repair is ordered by urgency and may use as much resource as swarm
  administrators allow. Defaults are adaptive; explicit resource budgets are
  authoritative.
- A returning target advertises journal-known immutable shards immediately and
  resumes new immutable writes after marker, generation and capability probes.
  Reads still verify exact bytes because immutability does not prevent bit rot.
- A returning consensus member is a learner and cannot become a voter until it
  is caught up to the required committed revision and a new quorum plan proves
  its safe admission.
- Repeated flapping uses risk-based hysteresis. No remaining recovery margin
  triggers immediate repair; safe excess redundancy permits delay. Repeated
  flaps increase instability so necessary repair cannot be deferred forever.
- Rebalance orders protection, required local availability, repair reserve,
  capacity headroom and measured performance. It includes movement cost and
  hysteresis and does not move safe data for negligible score improvement.

## 7. Certificates, backup, updates and operations

- ACME supports HTTP-01 and DNS-01. Initial DNS publishers are RFC 2136,
  Cloudflare and a generic external command/webhook contract.
- Manual DNS-01 is a durable `awaiting_dns_record` task showing the exact record
  and deadline. MeshSpan probes authoritative DNS and continues automatically;
  renewal creates and notifies the task well before expiry.
- One fenced worker owns an ACME order. Every eligible gateway receives only the
  bounded HTTP-01 challenge material; the resulting certificate/key generation
  is distributed through per-node encrypted envelopes.
- Local-only deployments receive a mesh-local CA and trust bundle. The product
  strongly recommends obtaining an inexpensive domain for publicly trusted,
  unattended HTTPS without making the local-CA route defective or insecure.
- There is no manual certificate-upload UI. External automated CA systems use a
  narrowly scoped certificate-publisher API. It validates names, chain, matching
  key, lifetime and generation, stages node-encrypted envelopes, probes gateway
  installation and activates make-before-break without returning or logging the
  key.
- Internal node/federation certificates may rotate frequently. Public ACME
  renewal respects CA schedules, rate limits and retry guidance. Adding a gateway
  does not create a new order; stable names and DNS wildcards avoid topology-driven
  reissuance.
- Metadata backups are automatic, encrypted, integrity-verified and bound to an
  exact committed position. Destinations may be registered storage, another
  swarm or a replaceable backup provider. Several generations are retained and
  destination failure overlap is reported honestly. Explicit encrypted offline
  export and non-destructive restore-readiness checks are supported.
- An administrator chooses a signed release once. MeshSpan performs the
  compatibility-checked rolling update across nodes, preserves voter/gateway
  availability, stops on failed probes and reports progress. Per-node manual
  replacement is not the normal update path.
- Pre-`1.0` releases promise no downgrade or rollback compatibility. Migrations
  may be one-way and release notes say so plainly; verified backups remain a
  safety measure rather than a rollback guarantee.
- GitHub Actions remain absent until a later explicit decision. Complete local
  update, validation, packaging and release scripts must already exist so future
  automation only orchestrates proven commands.
- Dependency/toolchain changes run the entire applicable automated suite plus
  compatibility, advisory and licence gates before acceptance.
- No operational telemetry leaves the appliance by default. Exporters, email and
  webhooks are explicit, authenticated, allow-listed and redacted.

## 8. Metrics

- Plain-language appliance status is derived from authoritative state and
  separately reports read availability, write acceptance, protection, capacity
  and action required. Metrics never authorise work or prove durability.
- Engineering metrics cover protection/locality debt; capacity and reservations;
  repair/scrub/drain/rebalance/reconciliation; target errors and latency;
  HTTPS/SMB operations; consensus/quorum/catch-up; coding and degraded reads;
  pack amplification/compaction; deduplication savings; federation backlog;
  authentication rejection; certificate state; backup readiness; update state;
  runtime resources; and clock uncertainty.
- Metric names, units and bucket schemas are versioned. Cardinality is bounded.
  Usernames, paths, object/shard/operation IDs, secrets and client IPs never
  become labels.
- The panel uses bounded downsampled local history rather than a distributed
  time-series database. Prometheus/OpenMetrics is the first optional
  authenticated exporter behind a replaceable interface; alerts derive from
  durable deduplicated events rather than transient samples.

## 9. Release proof and pre-`1.0` scale work

- Release proof covers real 1, 2, 3 and 6 machine topologies and 20 real nodes
  when available; at least 100 daemon processes/emulated nodes; and deterministic
  1,000 and 10,000-node loads across single and federated swarms.
- Federation proof includes editable peers, hierarchical governance, opaque
  backup storage, multi-partner placement, restart/disconnected edits, automatic
  convergence, revocation quarantine, identity rotation, downstream narrowing
  and relationship removal.
- Raspberry Pi-class and server-class benchmarks lock separate throughput,
  latency, repair, recovery, reconciliation, memory and concurrency floors.
- A seven-day release-candidate soak is required but does not run in ordinary CI.
  Accelerated deterministic time tests, automated real-process soak and a
  controlled/semi-automated hardware laboratory provide complementary evidence.
  A restart-safe controller records seed, schedule and out-of-band expected
  hashes/receipts and emits a signed result manifest. A 30-day observation soak
  is non-blocking.
- Lost acknowledged versions, corrupt bytes returned as valid, unauthorised
  access/deletion, dual authoritative writers, false success, manual ordinary
  conflict selection or failed documented metadata recovery are release blockers.
- At least five network components split several ways in release tests. Control
  work remains authority-gated; authorised ordinary writes continue on durable
  local branches and every admissible acknowledgement converges automatically.
- `0.1.0` proves permanent root authority, delegated operation/key-range routing
  and manual delegated groups without dual writers. Automatic measured
  Raft-group creation, split, merge and rebalance is not a `0.1.0` blocker but is
  a required post-`0.1.0`, pre-`1.0` feature—not an indefinite future idea.
- `0.1.0` requires an independent threat/operation-boundary review, retained
  fuzz corpora, advisory/licence gates and closure of critical/high findings. A
  paid penetration test is preferred but not an absolute blocker until available;
  MeshSpan never claims an audit that did not occur.
