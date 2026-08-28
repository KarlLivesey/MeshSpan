# Stage 1 completion evidence

Status: complete on 2026-08-28.

Stage 1 establishes executable contracts and a fast proof loop. It does not
claim a metadata database, networked cluster, storage provider or public file
service; those remain later roadmap stages.

## Delivered boundaries

- `meshspan-domain` owns canonical typed identities, overflow-safe revisions and
  time values, operation replay/conflict classification, lifecycle transitions,
  nested-group and activation decisions, multiple owners, overlapping fault
  groups and exact protection proofs.
- `meshspan-contracts` owns versioned, allocation-bounded interfaces and typed
  deterministic conformance entry points for storage, access connectors,
  administration clients, persistence, consensus, coding, placement,
  authentication, ACME challenge publication and observability.
- `meshspan-protocol` generates the closed private message catalogue with Prost
  and a vendored `protoc`. Length framing rejects excess before decode; generated
  values must not be treated as trusted input until wrapped by family-specific
  semantic validation. Bulk data frames have an independent limit.
- `meshspan-api-contract` remains the single Rust source for OpenAPI and server
  request/response validation. Committed OpenAPI generates strict TypeScript,
  native Fetch and Zod 4 artefacts and parity fixtures.
- Clock, entropy, storage/provider and repository/transport boundaries make
  nondeterministic IO explicit rather than ambient domain state.

## Exit-gate evidence

| Gate | Executable evidence |
| --- | --- |
| Rust format and warning-denied lint | `cargo fmt --check` and workspace/all-target/all-feature Clippy lanes |
| Rust unit and conformance behaviour | Parallel domain/capability, public API and private-protocol lanes |
| Web format, strict type, lint and unit behaviour | Independent Prettier, ESLint, TypeScript and Vitest lanes |
| Normal/replay/conflict/hostile transitions | Lifecycle, operation receipt, IAM/topology, API decoder and wire-frame vectors |
| Rust/OpenAPI/Zod parity | Committed request/response fixtures plus deterministic generation-drift check |
| Protobuf compatibility | Committed canonical v1.0 bytes, unknown-minor-field, malformed frame and shard-authority vectors |
| Clean-checkout entry point | `npm run check` after the documented frozen pnpm install |
| Resource-aware concurrency | Tested scheduler bounded by CPU, memory and optional `MESHSPAN_CHECK_WORKERS` override |

## Measured feedback loop

On the Stage 1 development workstation after a warm build:

- four resource-approved workers: 3.4 seconds;
- forced single worker: 6.0 seconds.

Every run prints each lane duration, total elapsed time and selected worker
count. The targets in [`verification.md`](verification.md) remain regression
budgets as the suite grows.
