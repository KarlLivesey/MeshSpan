# Product roadmap

Status: active implementation plan. Stage status is claimed only where the linked
executable evidence passes.

## Delivery rules

- Build vertical, executable slices after the design lock.
- Use one short-lived branch at a time: branch from `main`, test locally, sign
  commits, push, review, merge and delete before dependent work begins.
- Run fast local suites concurrently in independent lanes. Hardware, soak and
  release tests run separately and never become the ordinary edit/test loop.
- A stage is complete only when its observable behaviour and exit evidence pass.
  A type, table, handler or mock by itself does not complete a stage.
- One-node code paths must remain the smallest instance of the same multi-node
  model.

## Stage 0 — lock the contracts

**Status:** complete. The accepted federation records, messages, authority boundaries and staged
retrofit gates are locked without weakening the original contracts. See
[`federation.md`](federation.md).

**Purpose:** agree what will be built before implementation starts.

Deliverables:

- accepted requirement set and terminology;
- accepted logical records and transaction boundaries;
- versioned private-message catalogue;
- accepted IAM, ownership and authentication rules;
- explicit write/read/delete/repair/failure flows;
- decisions for the first SMB profile, consensus implementation, protection
  policy UI, eventual/strong acknowledgement presets, performance gates and
  release platforms.
- autonomous-swarm federation contracts covering horizontal sharing, acyclic
  governance, downstream delegation, bilateral restrictions, multi-writer branches,
  remote capacity, revocation/quarantine and ownership recovery.

Exit evidence:

- every open decision needed by Stage 1–3 is accepted or deliberately deferred;
- all normative requirements map to a roadmap gate;
- contradictory, duplicate and platform-as-protocol requirements are removed.
- federation logical records, canonical encodings, trust transitions and private
  message flows are complete enough that Stages 1–5 need no authority guesses.

No production implementation is claimed in this stage.

## Stage 1 — fast foundation and executable domain

**Depends on:** Stage 0.

**Status:** complete. The federation domain, canonical wire contracts, hostile vectors and
root/delegated routing contracts pass with the original foundation evidence.

Build:

- Rust workspace tracking the latest tested stable toolchain, plus a Node.js 26
  and TypeScript 6.0.3 web workspace using Temporal for date/time domain logic;
- one root task runner for format, lint, unit, conformance and integration lanes;
- domain crates for typed IDs, revisions, outcomes, principals, topology,
  protection scenarios and lifecycle transitions;
- versioned contracts and conformance harnesses for replaceable storage,
  connectors, administration clients, persistence, consensus, coding, placement,
  authentication, certificate and observability implementations;
- a composed deterministic consensus-library boundary whose MeshSpan persistence,
  transport, command and daemon integrations remain outer adapters;
- deterministic clock/random/IO interfaces for tests;
- Protobuf schema generation and compatibility fixture harness;
- Rust-authored OpenAPI generation, server request/response validation and the
  deterministic committed TypeScript/Fetch/Zod generation harness;
- one local scheduler that runs independent Rust, web, schema/protocol and
  integration lanes concurrently with resource-aware worker limits;
- globally qualified swarm/principal identities, relationship and governance
  graph types, bilateral policy intersections, federation rights, offline grants,
  recovery transitions, quarantine outcomes and federated durability states;
- versioned contracts and canonical fixtures for swarm authentication, remote
  branch paging, remote storage capabilities and signed receipts;
- typed root/delegated partition identities, operation-family and key-range
  scopes, routing epochs and safe split/merge/handoff transition contracts which
  do not assume one swarm always has one log.

Exit evidence:

- format, warning-denied Rust lint, web format/type/lint and unit tests pass
  locally;
- transition tables prove normal, replay, conflict and hostile-input cases;
- public API fixtures prove Rust, OpenAPI and generated Zod accept/reject parity;
- clean checkout can run the fast suite with one documented command;
- suite duration is measured and budgeted before more tests accumulate;
- transition and hostile-input vectors prove governance-cycle rejection,
  restriction intersection, bounded delegation, revocation/quarantine and exact
  federation outcome semantics.

Requirements: SYS-002, SYS-004, SYS-006, SYS-009, PER-002, SCL-007, TST-001, REL-001,
REL-002, DEV-001–006, EXT-001–005, EXT-008, FED-001–005, FED-007–009, FED-013–015,
FED-022, FED-025, CLU-035, CLU-036, SCL-013, SCL-014.

## Stage 2 — authoritative metadata kernel

**Depends on:** Stage 1.

**Status:** complete. The original metadata kernel and federation retrofit pass their migration,
integrity, transaction-boundary, restart, backup/restore and bounded-query evidence. See
[`stage-2-evidence.md`](stage-2-evidence.md).

Build:

- SQLite-compatible migrations for the state-machine and node-local records;
- typed command/query repository boundaries;
- atomic operation deduplication and committed-result receipts;
- topology, IAM, namespace and lifecycle record invariants;
- authoritative component instances, configuration revision history,
  assignments and desired-versus-observed rollout state;
- backup/snapshot representation at an exact state revision;
- engine conformance harness, initially against SQLite and optionally Turso as a
  non-production compatibility lane;
- authoritative federation relationships, rotating trust identities, governance
  edges, resource grants, delegated ceilings, bilateral quotas, offline validity,
  recipient-local grant assignments, actor lifecycle attestations, downstream delegation chains, successor
  designations and quarantine records;
- typed idempotent commands and receipts for connect/approve, renew, restrict,
  revoke, recover, transfer ownership and retire a relationship;
- a root-owned partition/delegation directory with immutable epochs, scoped
  snapshot/catch-up positions and old/frozen/new ownership states that cannot
  admit two authoritative groups for one record.

First vertical proof:

- create a one-node mesh;
- create users and nested groups;
- create a volume/folder/file record with multiple user/group owners;
- grant a time-bounded permission;
- restart and retrieve the exact committed result by operation ID.

Exit evidence:

- crash at every transaction boundary yields either the old or new valid state;
- migration, integrity, backup/restore and constraint vectors pass;
- no request-path query is unbounded or lacks its intended index;
- migration, crash and backup/restore proofs cover every federation transition;
  no transaction spans a remote call or treats another swarm's database as local
  atomic state.

Requirements: IAM-001–014, ACL-001–008, PER-001–005, SCL-002, SCL-003,
CFG-001–008, EXT-002–004, EXT-007, FED-003–015, FED-021–025, CLU-035, CLU-036,
SCL-013, SCL-014.

## Stage 3 — one-to-many cluster kernel

**Depends on:** Stage 2.

**Status:** complete after the 2026-08-30 federation audit. Within-swarm consensus and autonomous-
swarm identity, authority synchronisation and restart-resumable history exchange pass together.

Build:

- Quinn/mTLS node identity negotiation;
- MeshSpan's owned leader-based consensus core behind the consensus boundary;
- consensus, typed metadata command/query/status and snapshot streams;
- one-node bootstrap, administrator join grants and headless enrolment;
- one-, two- and three-voter operation using the same state model;
- presence, incarnation fencing and safe membership transitions;
- real partition IDs, signed routing epochs and an initial single-partition
  deployment that can create and hand off a second namespace partition;
- bounded branch-head comparison and immutable commit/object transfer messages,
  before filesystem merge behaviour is added in Stage 5;
- mutually approved swarm connection over Quinn/mTLS, federation identity
  rotation/recovery, signed delegation and restriction propagation, bounded
  cursor-based remote branch/object transfer and remote-storage routing;
- strict separation between federation sessions and within-swarm membership,
  routing, voters and consensus authority;
- one permanent root control group which initially owns every authoritative
  scope, plus a typed epoch-fenced delegation boundary through which operation
  families and key ranges can later move to directly routed Raft groups.

First vertical proof:

- start three local daemon processes;
- enrol nodes using a join grant;
- commit metadata through any node via leader routing;
- kill the leader, elect another, resolve a lost reply by operation ID and catch
  the old leader up after return;
- move one test scope to a second metadata partition with no dual-writer window.

Exit evidence:

- deterministic multi-way partition tests prove only a valid elected authority
  retaining its compiled consensus-write quorum advances the converged/control
  head;
- stale processes, replayed messages and corrupt snapshots fail closed;
- control traffic remains responsive during a saturated synthetic data stream;
- real autonomous processes connect, rotate identity, disconnect, renew/revoke,
  reject replay/stale epochs, resume bounded pages and never admit a peer as a
  voter or local principal merely because it is federated;
- the root safely delegates one test scope to a proved child group, rejects the
  split without enough eligible members, admits no dual writer and leaves
  delegated operations independent of the root log.

Requirements: CLU-001–027, OPS-003, TST-003, SCL-005, SCL-006, SCL-010,
CLU-035, CLU-036, FED-001–007, FED-011–015, FED-020, FED-022, FED-025, FED-026,
SCL-011–014.

## Stage 4 — folder storage and safe shard lifecycle

**Depends on:** Stage 3.

**Status:** complete, including capability-scoped federated partner capacity. See
[`stage-4-evidence.md`](stage-4-evidence.md).

Build:

- repeatable `--storage-path` plus `--daemon-state-dir` configuration;
- folder-provider interface and initial filesystem-folder implementation;
- target identity, local journal, inventory and incarnation handling;
- private shard put/get streams with bounded capabilities and durable receipts;
- guarded cleanup intents, removal permits and provider tombstones;
- scrub observations, staging recovery, reservations and full/partial/corrupt IO
  injection.
- capability-scoped partner-swarm capacity with bilateral quotas and separate
  protection-contribution and ordinary-read classifications;
- encrypted cross-swarm put/get/scrub/repair/retire flows whose signed receipts
  never expose volume keys or namespace/user metadata to storage-only partners.

First vertical proof:

- register multiple differently sized folders on each of three processes;
- put and retrieve immutable verified chunks remotely;
- crash at every write/delete transition and recover to the exact expected
  inventory without location-authorised deletion.

Exit evidence:

- real folder IO tests cover restart, `ENOSPC`, short write, lost fsync result,
  corruption, path replacement and stale target incarnation;
- provider contract tests can be reused by a future storage backend.
- real partner-provider tests prove quota intersection, protection-only placement,
  optional serving reads, reconnect, revocation, lost response and receipt-backed
  cleanup without location authority.

Requirements: TOP-001–005, DAT-005, DAT-006, DAT-010–013, TST-002,
FED-005, FED-016–021, FED-024, FED-025.

## Stage 5 — filesystem and access-control service

**Depends on:** Stages 2–4.

**Status:** complete after the 2026-08-30 local-convergence and autonomous-swarm federation audit.
All reopened gaps have executable closure evidence.
See [`stage-5-evidence.md`](stage-5-evidence.md) and [`federation.md`](federation.md).

Build:

- protocol-neutral path resolution and canonical naming;
- directories, files, immutable versions and staged random writes;
- persistent CoW directory blocks, namespace commits and atomic volume heads;
- durable per-partition local branch stores, causal multi-parent commits and
  deterministic automatic reconciliation;
- read-only snapshots, schedules/retention and restore-as-new-head;
- authoritative opens, share modes, locks, rename, delete-on-close and flush;
- complete permission evaluation over nested groups, multiple owners,
  inheritance and time windows;
- sessions, capabilities, audit events and adapter-facing filesystem API;
- lazily materialised existing-file state on a forked writable branch so offline
  branches can edit existing content, not only create new names;
- referenced-record-only, cursor-paged history exchange with concrete signed
  Protobuf/Quinn codecs and handlers rather than one opaque in-memory bundle;
- receiving-swarm local-principal authorisation inside an upstream swarm grant,
  signed downstream/offline delegation, deterministic cross-swarm multi-writer
  reconciliation and revocation quarantine;
- fail-closed cross-record import validation binding commits, identities,
  delegations, versions, manifests and content evidence;
- filesystem routing by stable scope/partition epoch, including stale-route retry
  and explicit subtree ownership boundaries without exposing partitions to users.

First vertical proof:

- two in-process adapters acting as different gateways execute conflicting and
  non-conflicting opens against the same files and users;
- committed flush survives gateway loss and is visible through the other
  adapter; uncommitted staged content is never visible;
- two isolated nodes both write through the filesystem service, restart, heal
  and automatically converge with every acknowledged version preserved;
- two autonomous swarms accept non-empty edits from home-authenticated users while
  disconnected, restart, exchange paged signed history over real Quinn, reconcile
  into the owner and read every admissible version's exact bytes;
- a retroactively inadmissible disconnected edit remains invisible but enters
  bounded audited quarantine, and exact retry/restart cannot publish or lose it.

Exit evidence:

- protocol-neutral filesystem vector suite covers every operation, disposition,
  right, inheritance shape, group graph and lost-response state;
- no adapter requires SQL or provider-path knowledge.
- large-volume paging does not scan/export every immutable volume record and
  resumes after loss without a mesh-size ceiling;
- existing-file fork edits, non-empty content healing, delegation expiry,
  revocation, bilateral restriction and hostile imported-record vectors pass.

Requirements: FS-001–013, COW-001–009, CON-001–015, IAM-005–011, ACL-003–008,
AUTH-006, SIM-008, SIM-009, FED-005, FED-007–015, FED-022–025.

## Pre-Stage 6 — accepted-decision retrofit

**Depends on:** Stages 1–5. **Required before Stage 6 starts.**

**Status:** complete. See
[`pre-stage-6-retrofit-evidence.md`](pre-stage-6-retrofit-evidence.md).

The executed Stage 1–5 evidence predates D-074–D-077. It remains valid for the
underlying consensus, persistence, transport, storage and filesystem behaviour,
but the superseded authentication/federation policy is not grandfathered.

Build and re-prove:

- remove password-login generated API models, fixtures and handlers;
- replace password/client-certificate/SMB-specific method shapes with passkey,
  TOTP, recovery-code and scoped API-key records;
- replace `manage_sharing` and owner-imported remote-principal authority with
  swarm-targeted grants plus monotonic downstream delegation;
- update schema, canonical messages, migrations, signatures, receipts and
  hostile/restart fixtures for the new delegation chain;
- add the persistent single-use claim-bundle record and local protected output
  contract; and
- report one-machine backing-device protection independently from machine HA.

Exit evidence:

- repository search and generated-contract drift prove no password,
  client-certificate or SMB-only user credential surface remains;
- A-to-B-to-C tests prove C cannot address A directly, each hop only narrows and
  expiry/revocation quarantine propagates after restart/disconnection;
- current Stage 1–5 suites pass without weakening their existing evidence; and
- the implementation/status audit identifies no accepted Stage 6 prerequisite
  as already complete merely because a superseded scaffold existed.

## Stage 6 — usable HTTPS appliance slice

**Depends on:** the accepted-decision retrofit.

Build:

- first-start claim-bundle create/join experience and headless equivalents;
- HTTPS authentication, session, CSRF and step-up flows;
- MeshSpan's native specialised HTTPS file/data API for generated clients, CLIs,
  automation, bespoke applications and the shipped file browser, with
  upload/download/create/rename/delete;
- administrator panels for users, groups, owners, grants, nodes, targets, fault
  groups, volumes and operation status;
- the same native HTTPS contract exposes public administration operations
  sufficient for the shipped panel, CLI and a replacement panel without
  private daemon access; it is not an S3, WebDAV, NFS or other compatibility
  surface;
- asynchronous progress and safe retry for long operations.

First vertical proof:

- a real HTTPS client creates an administrator, enrols three nodes, registers
  storage folders, adds users/groups/permissions, uploads a file through one
  gateway and downloads exact bytes through another after leader loss.

Exit evidence:

- browser and API tests cover the complete flow, malicious inputs, inaccessible
  controls, session revocation and unknown operation outcomes;
- ordinary healthy operation requires no manual shard or leader choices;
- a clean-machine usability test completes create/join, folder registration,
  user/share creation and an HTTPS file round trip without exposing process
  roles, consensus, shards or placement internals.

Requirements: SIM-001–010, ACC-003–005, AUTH-001–011, OPS-001–020,
API-001–005, EXT-006.

## Stage 7 — embedded SMB appliance slice

**Depends on:** Stage 5. May proceed alongside Stage 6 only on a separate
independent contributor branch; it merges before dependent storage work.

**Status:** complete. The embedded SMB 3.1.1 implementation and its real-client,
three-gateway failure proof pass locally. See
[`stage-7-evidence.md`](stage-7-evidence.md).

Build:

- SMB 3.1.1-only profile inside the Rust daemon;
- negotiation, authentication, tree connect, durable session/handle semantics
  required by that profile;
- mapping from SMB operations and status codes to the common filesystem service;
- ordinary MeshSpan API-key authentication with an SMB-login scope and no
  service-specific credential record;
- resource-aware connections, streams, buffers and worker scheduling.

First vertical proof:

- a real SMB client connects to each of three gateways with one MeshSpan user,
  creates, writes, flushes, closes, reads, renames and deletes the same files;
- the test kills the active metadata leader and one storage process during IO,
  then verifies exact acknowledged bytes and expected protocol errors.

Exit evidence:

- SMB conformance vectors and real-client end-to-end cycles pass locally on the
  supported host/container environments;
- no Samba, FUSE, external service, raw provider-folder access or SMB-specific
  permission database is present.

Requirements: ACC-001–004, ACC-006, ACC-007, ACC-010, ACC-011, TST-004.

## Stage 8 — protection policies and erasure coding

**Depends on:** Stages 4–7.

**Status:** complete. Fault-aware placement, streaming erasure coding, degraded
reads and the real six-daemon HTTPS/SMB protection proof pass locally. See
[`stage-8-evidence.md`](stage-8-evidence.md).

Build:

- administrator-defined overlapping fault groups and scenario evaluator;
- automatic layout selection from user failure promises and eligible capacity;
- separate data-survival and service-availability evaluation over overlapping
  machine shared-failure groups;
- streaming erasure encode/decode behind a coding interface;
- immutable stripe manifests and mixed layouts within a volume;
- degraded verified reads;
- inherited per-scope locality policies, complete local decodable placements and
  availability-first catch-up;
- inheritable eventual/strong acknowledgement policies with simple presets and
  per-zone `required_before_commit`, `eventual` and advanced `excluded` roles.

First vertical proof:

- create a volume promising survival of any two machine failures and any three
  backing-device failures;
- require a complete locally protected copy of a folder in two availability
  cells, with both required before one strong publication and a third cell set
  to eventual;
- upload through HTTPS and SMB, remove every modelled failure combination and
  sever the cell link, then retrieve the exact permitted versions through both
  adapters.

Exit evidence:

- exhaustive small-topology property tests agree with a simple placement oracle;
- heterogeneous target sizes do not weaken fault independence;
- one-machine layouts report proved backing-device protection separately from
  absent machine/power/location survival and upgrade online as resources arrive.

Requirements: TOP-006–010, DAT-001–008, DAT-019, EC-001–008, LOC-001–011,
ACK-001–010, TST-005.

## Stage 9 — autonomous healing, rebalance and drain

**Depends on:** Stage 8.

Build:

- durable repair/scrub/drain queues with leases and fencing;
- read repair and periodic bit-rot scrub;
- automatic repair priority and safe bandwidth/resource control;
- rebalancing after growth or topology change;
- target, node and fault-group drain with authoritative safe-to-detach proof;
- fast returning-target service after focused probes plus background inventory
  reconciliation; returning voters remain learners until caught up.

First vertical proof:

- repeatedly stop, start, isolate and return nodes while clients continue IO;
- corrupt and remove shards, fill a target and drain another;
- verify automatic convergence to the promised protection without manual shard
  selection or conflicting-version choices.

Exit evidence:

- deterministic simulations explore long churn sequences with reproducible
  seeds;
- process tests prove repair, scrub and drains alongside real HTTPS/SMB traffic;
- every background operation is resumable and bounded.

Requirements: DAT-007–014, OPS-004, OPS-005, TST-006.

## Stage 10 — certificates, packaging and operations

**Depends on:** Stages 6–9.

Build:

- ACME HTTP-01 and DNS-01 with fenced single-worker orders;
- per-node encrypted certificate/private-key distribution and rotation;
- operational health, protection, capacity, security and audit panels;
- native artefacts for accepted platforms and a minimal container image;
- complete local signed release/update scripts, checksums, provenance and
  dependency update policy without GitHub Actions;
- mesh-wide rolling update, migration, automatic metadata backup/restore and
  explicitly unsupported pre-`1.0` downgrade handling;
- automated external-certificate publication plus bounded local metrics and
  optional authenticated exporters.

Exit evidence:

- real ACME staging tests cover both challenges, failover and renewal;
- every gateway installs the same generation without broadcasting plaintext key
  material;
- published artefacts execute the complete HTTPS and SMB acceptance cycle;
- dependency/toolchain update candidates run the complete applicable automated
  suite before acceptance.

Requirements: PKI-001–007, PER-003–007, REL-001, REL-003, TST-007.

## Stage 11 — minimal useful product proof

**Depends on:** every prior stage.

This gate is the first `0.1.0` candidate, not a stable API promise.

Required evidence:

- one-node, two-node growth-state and supported redundant topologies;
- real six-machine survival of two simultaneous machine failures;
- real corruption, full-disk, partial-write, abrupt power-loss and network
  partition injection;
- repeated cable, device and node churn plus multi-way partition/rejoin with
  deterministic automatic branch convergence and no lost acknowledgement;
- a two-node Home/Office mesh loses its link for one hour, accepts real HTTPS
  and SMB eventual writes on both sides through restarts, then reconnects and
  converges without an administrator or lost version;
- a multi-cell campus scenario where one building loses its uplink, keeps its
  owned scopes serving locally and catches remote replicas up automatically;
- strong writes requiring two selected zones wait for exactly those zones while
  other eventual zones do not hold acknowledgement;
- real HTTPS and SMB full cycles for users, groups, permissions, volumes, files,
  failures, repair and deletion;
- backup/restore plus upgrade and every explicitly supported recovery path from
  published artefacts;
- ACME challenge, renewal and gateway-key-distribution cycles;
- long-duration repair/certificate/churn soak;
- heterogeneous-drive and foreground/degraded/repair performance results against
  the accepted targets;
- container and accepted native artefacts with signed tag, checksums and
  provenance.
- a seven-day release-candidate soak with reproducible out-of-band evidence and
  an independent security review closing every critical/high finding.

Requirements: all non-deferred requirement IDs.

## Stage 12 — automatic metadata-group scaling

**Depends on:** Stage 11 measurement evidence. **Required before `1.0`.**

This is deliberately not a `0.1.0` blocker, but it is near-term pre-`1.0` work,
not an indefinite optimisation.

Build:

- capacity-normalised load/headroom measurements per authoritative group;
- automatic group creation and directly routed operation/key-range delegation;
- online split, merge and rebalance with epoch-fenced single-writer handoff;
- automatic eligible voter placement against shared-failure groups; and
- stable hysteresis using measured migration cost, locality and resource class.

Exit evidence:

- deterministic and process tests interrupt every prepare, copy, fence,
  activation and retirement boundary without dual writers or unroutable scopes;
- split/merge decisions improve a measured bottleneck and reverse safely when
  load changes;
- Raspberry Pi-class and server-class groups use measured capacity rather than
  node count or one hardware-independent operations threshold; and
- ordinary filesystem/API semantics and root-owned swarm identity/enrolment/
  federation authority remain unchanged.

Requirements: SCL-010, SCL-013, SCL-014, DEF-005.

## Other post-MUP boundaries

After the first useful product is proven, separately designed extensions may
include additional access adapters, direct-shard clients, disconnected
application-specific semantic merge handlers, more storage-provider
implementations and native Windows hosting. None may bypass the filesystem,
authority, lifecycle or access-control contracts established above.
