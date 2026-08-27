# Design decisions

Status: **draft for review**.

## Accepted in discussion

| ID | Decision |
| --- | --- |
| D-001 | The project and product are named MeshSpan. |
| D-002 | All project-authored licence references use `GPL-2.0-only`. |
| D-003 | Priorities are simplicity, reliability, speed, flexibility and security, in that order. |
| D-004 | One implementation scales from a one-node mesh to many nodes; there is no separate standalone data model. |
| D-005 | Storage is registered existing folders only. Whole-device discovery, formatting and erasure are absent. |
| D-006 | Hosts, daemon nodes and storage targets are distinct identities. |
| D-007 | Hosts and targets may belong to multiple overlapping administrator-defined fault groups. |
| D-008 | A namespace object may have multiple owners, and each owner may be a user or group. |
| D-009 | HTTPS and a standards-compliant embedded SMB service are access adapters over one filesystem service. |
| D-010 | Private node transport uses Quinn with mutual TLS. |
| D-011 | Metadata is designed for portable SQLite-compatible SQL, not database-specific wire messages. |
| D-012 | SQLite is the initial authoritative relational engine; Turso remains a compatibility candidate. |
| D-013 | Every eligible gateway may expose HTTPS and SMB against the same converged namespace plus its newest authorised local branch during isolation; there is no single active gateway design. |
| D-014 | A valid administrator-issued join grant is pre-authorisation within its limits and does not require a second interactive approval. |
| D-015 | Native Linux and macOS nodes and the supported container may be mixed in one mesh; native Windows hosting is deferred. |
| D-016 | The web client uses Solid 2.0, Node.js 26 tooling, TypeScript 7.0 and Temporal, with no production Node.js service. |
| D-017 | `0.1.0` is the first minimal-useful-product candidate and carries no compatibility promise. |
| D-018 | Major storage, access, administration, persistence, consensus, coding, policy, authentication, certificate, notification and observability implementations are replaceable behind versioned contracts. |
| D-019 | Mesh-wide component selection and desired configuration are authoritative replicated metadata; only irreducibly local bindings and private material remain node-local. |
| D-020 | The shipped administration panel is one replaceable client of the public versioned administration API and receives no private database access. |
| D-021 | Replicated configuration selects and configures implementations but never distributes executable plugin code. |
| D-022 | Published data, namespace and configuration use semantic copy-on-write with immutable revisions and atomic head changes; mutable coordination records remain explicitly separate. |
| D-023 | MeshSpan supports cheap read-only volume snapshots, scheduled retention and restore-as-new-head as core functionality. |
| D-024 | Stable redundant voter tiers grow automatically through 3, 5, 7 and 9 independent eligible hosts; one and two voters are supported establishment states. |
| D-025 | Erasure coding uses recorded systematic Reed–Solomon `k+m` stripes: any `k` verified slices reconstruct and any `m` slice losses are recoverable, subject to failure-domain placement proof. |
| D-026 | A growing mesh may use multiple Raft-backed metadata partitions and availability cells; each control record and converged head has exactly one mutation authority, while filesystem outage branches reconcile into it. Small meshes use the same partitioned record model. |
| D-027 | Campus partition tolerance combines cell-local services with durable filesystem branches: disconnected cells may both write ordinary content, while only one majority-owned converged head and control-plane authority exist. |
| D-028 | Volume, folder and file scopes may require complete locally decodable copies in one or more administrator-defined cells; writes remain availability-first and remote cells may be explicitly lagging. |
| D-029 | Filesystem writes may commit durably to local CoW branches without wider quorum, advertise exact durability scope and reconcile automatically without discarding acknowledged alternatives. |
| D-030 | Security-critical control-plane mutations remain authority-gated; offline merge is limited to defined filesystem/content operations unless a later constrained delegation is designed. |
| D-031 | Normal writes use availability-first eventual convergence; a scope may instead require a declarative strong publication barrier over verified nodes, zones and protection predicates followed by one ACID converged-head commit. Only zones marked required hold that barrier. |
| D-032 | MeshSpan exposes one appliance daemon and intent-level controls; internal daemon roles, consensus, placement, coding and reconciliation are automatic and do not become routine operator configuration. |

## Proposed defaults requiring review

| ID | Proposal | Reason |
| --- | --- | --- |
| P-001 | Protobuf encodes private node messages. | Versioned cross-language schemas without exposing Rust or database layout. |
| P-003 | Permissions are allow-only with explicit inheritance control. | Avoids ambiguous deny precedence across nested groups and time windows. |
| P-004 | System administrators do not silently receive file-data access; emergency access is explicit and audited. | Separates infrastructure administration from data ownership. |
| P-005 | Tags are descriptive and searchable but have no implicit permission effect. | Prevents tag editing from becoming privilege escalation. |
| P-006 | Interactive administration supports step-up two-factor authentication; SMB uses a separate scoped credential. | SMB cannot perform an interactive second-factor ceremony. |
| P-008 | Voters keep consensus, replicated state and node-local state in separately recoverable stores. | Makes snapshot installation and local recovery boundaries explicit. |

## Open decisions

| ID | Question |
| --- | --- |
| O-001 | Which Rust Raft implementation meets the storage, membership and testability requirements? |
| O-002 | What exact simultaneous-failure policy shapes are exposed in the ordinary and advanced UI? |
| O-003 | Which SMB dialects and optional features are required for the first MUP? |
| O-004 | What chunk size and erasure geometries meet the first performance and repair targets? |
| O-005 | How is the mesh secret-wrapping key created, rotated, backed up and recovered? |
| O-006 | What measurable latency, throughput, recovery-time and scale targets gate MUP? |
| O-007 | Which native archive and container platforms are mandatory for the first release? |
