# Product roadmap

Status: draft for review. This is an implementation dependency order, not a
claim that documentation is product progress.

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

Exit evidence:

- every open decision needed by Stage 1–3 is accepted or deliberately deferred;
- all normative requirements map to a roadmap gate;
- contradictory, duplicate and platform-as-protocol requirements are removed.

No production implementation is claimed in this stage.

## Stage 1 — fast foundation and executable domain

**Depends on:** Stage 0.

**Status:** complete. See [`stage-1-evidence.md`](stage-1-evidence.md).

Build:

- Rust workspace tracking the latest tested stable toolchain, plus a Node.js 26
  and TypeScript 6.0.3 web workspace using Temporal for date/time domain logic;
- one root task runner for format, lint, unit, conformance and integration lanes;
- domain crates for typed IDs, revisions, outcomes, principals, topology,
  protection scenarios and lifecycle transitions;
- versioned contracts and conformance harnesses for replaceable storage,
  connectors, administration clients, persistence, consensus, coding, placement,
  authentication, certificate and observability implementations;
- deterministic clock/random/IO interfaces for tests;
- Protobuf schema generation and compatibility fixture harness;
- Rust-authored OpenAPI generation, server request/response validation and the
  deterministic committed TypeScript/Fetch/Zod generation harness;
- one local scheduler that runs independent Rust, web, schema/protocol and
  integration lanes concurrently with resource-aware worker limits.

Exit evidence:

- format, warning-denied Rust lint, web format/type/lint and unit tests pass
  locally;
- transition tables prove normal, replay, conflict and hostile-input cases;
- public API fixtures prove Rust, OpenAPI and generated Zod accept/reject parity;
- clean checkout can run the fast suite with one documented command;
- suite duration is measured and budgeted before more tests accumulate.

Requirements: SYS-002, SYS-004, SYS-006, SYS-009, PER-002, SCL-007, TST-001, REL-001,
REL-002, DEV-001–006, EXT-001–005.

## Stage 2 — authoritative metadata kernel

**Depends on:** Stage 1.

**Status:** complete after executable re-audit. See
[`stage-1-3-audit.md`](stage-1-3-audit.md).

Build:

- SQLite-compatible migrations for the state-machine and node-local records;
- typed command/query repository boundaries;
- atomic operation deduplication and committed-result receipts;
- topology, IAM, namespace and lifecycle record invariants;
- authoritative component instances, configuration revision history,
  assignments and desired-versus-observed rollout state;
- backup/snapshot representation at an exact state revision;
- engine conformance harness, initially against SQLite and optionally Turso as a
  non-production compatibility lane.

First vertical proof:

- create a one-node mesh;
- create users and nested groups;
- create a volume/folder/file record with multiple user/group owners;
- grant a time-bounded permission;
- restart and retrieve the exact committed result by operation ID.

Exit evidence:

- crash at every transaction boundary yields either the old or new valid state;
- migration, integrity, backup/restore and constraint vectors pass;
- no request-path query is unbounded or lacks its intended index.

Requirements: IAM-001–014, ACL-001–008, PER-001–005, SCL-002, SCL-003,
CFG-001–008, EXT-002–004, EXT-007.

## Stage 3 — one-to-many cluster kernel

**Depends on:** Stage 2.

**Status:** complete after executable re-audit. See
[`stage-1-3-audit.md`](stage-1-3-audit.md).

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
  before filesystem merge behaviour is added in Stage 5.

First vertical proof:

- start three local daemon processes;
- enrol nodes using a join grant;
- commit metadata through any node via leader routing;
- kill the leader, elect another, resolve a lost reply by operation ID and catch
  the old leader up after return.
- move one test scope to a second metadata partition with no dual-writer window.

Exit evidence:

- deterministic multi-way partition tests prove only a valid elected authority
  retaining its compiled consensus-write quorum advances the converged/control
  head;
- stale processes, replayed messages and corrupt snapshots fail closed;
- control traffic remains responsive during a saturated synthetic data stream.

Requirements: CLU-001–027, OPS-003, TST-003, SCL-005, SCL-006, SCL-010.

## Stage 4 — folder storage and safe shard lifecycle

**Depends on:** Stage 3.

Build:

- repeatable `--storage-path` plus `--daemon-state-dir` configuration;
- folder-provider interface and initial filesystem-folder implementation;
- target identity, local journal, inventory and incarnation handling;
- private shard put/get streams with bounded capabilities and durable receipts;
- guarded cleanup intents, removal permits and provider tombstones;
- scrub observations, staging recovery, reservations and full/partial/corrupt IO
  injection.

First vertical proof:

- register multiple differently sized folders on each of three processes;
- put and retrieve immutable verified chunks remotely;
- crash at every write/delete transition and recover to the exact expected
  inventory without location-authorised deletion.

Exit evidence:

- real folder IO tests cover restart, `ENOSPC`, short write, lost fsync result,
  corruption, path replacement and stale target incarnation;
- provider contract tests can be reused by a future storage backend.

Requirements: TOP-001–005, DAT-005, DAT-006, DAT-010–013, TST-002.

## Stage 5 — filesystem and access-control service

**Depends on:** Stages 2–4.

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
- sessions, capabilities, audit events and adapter-facing filesystem API.

First vertical proof:

- two in-process adapters acting as different gateways execute conflicting and
  non-conflicting opens against the same files and users;
- committed flush survives gateway loss and is visible through the other
  adapter; uncommitted staged content is never visible;
- two isolated nodes both write through the filesystem service, restart, heal
  and automatically converge with every acknowledged version preserved.

Exit evidence:

- protocol-neutral filesystem vector suite covers every operation, disposition,
  right, inheritance shape, group graph and lost-response state;
- no adapter requires SQL or provider-path knowledge.

Requirements: FS-001–013, COW-001–009, CON-001–015, IAM-005–011, ACL-003–008,
AUTH-006.

## Stage 6 — usable HTTPS appliance slice

**Depends on:** Stage 5.

Build:

- first-start create/join experience and headless equivalents;
- HTTPS authentication, session, CSRF and step-up flows;
- user file browser with upload/download/create/rename/delete;
- administrator panels for users, groups, owners, grants, nodes, targets, fault
  groups, volumes and operation status;
- a public administration API sufficient for the shipped panel, CLI and a
  replacement panel without private daemon access;
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

Requirements: SIM-001–007, ACC-003–005, AUTH-001–009, OPS-001–016,
API-001–005, EXT-006.

## Stage 7 — embedded SMB appliance slice

**Depends on:** Stage 5. May proceed alongside Stage 6 only on a separate
independent contributor branch; it merges before dependent storage work.

Build:

- chosen initial SMB dialect/profile inside the Rust daemon;
- negotiation, authentication, tree connect, durable session/handle semantics
  required by that profile;
- mapping from SMB operations and status codes to the common filesystem service;
- separately revocable SMB-scoped credentials;
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

Requirements: ACC-001–004, ACC-006, ACC-007, TST-004.

## Stage 8 — protection policies and erasure coding

**Depends on:** Stages 4–7.

Build:

- administrator-defined overlapping fault groups and scenario evaluator;
- automatic layout selection from user failure promises and eligible capacity;
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
- one-node layout is explicitly unprotected and upgrades data online as nodes
  and fault groups become available.

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
- returning-node inventory reconciliation.

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
- signed release automation, checksums, provenance and dependency update policy;
- upgrade, migration, rollback and metadata backup/restore flows.

Exit evidence:

- real ACME staging tests cover both challenges, failover and renewal;
- every gateway installs the same generation without broadcasting plaintext key
  material;
- published artefacts execute the complete HTTPS and SMB acceptance cycle;
- automated dependency/toolchain updates merge only after required local-equivalent
  gates pass.

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
- backup/restore plus supported upgrade/rollback from published artefacts;
- ACME challenge, renewal and gateway-key-distribution cycles;
- long-duration repair/certificate/churn soak;
- heterogeneous-drive and foreground/degraded/repair performance results against
  the accepted targets;
- container and accepted native artefacts with signed tag, checksums and
  provenance.

Requirements: all non-deferred requirement IDs.

## Post-MUP boundaries

After the first useful product is proven, separately designed extensions may
include additional access adapters, direct-shard clients, disconnected
application-specific semantic merge handlers, more storage-provider
implementations and native Windows hosting. None may bypass the filesystem,
authority, lifecycle or access-control contracts established above.
