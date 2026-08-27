# Top-level dependency inventory

Status: planned future implementation for review; this is not a lockfile and
authorises no dependency installation.

This document records what MeshSpan will use or, where a choice still requires
proof, the exact selection process it will follow. It does not describe work
already implemented.

MeshSpan keeps its direct dependency surface explicit. A dependency is admitted
only when it removes more correctness or maintenance risk than it adds, supports
the required platforms/toolchain, passes a `GPL-2.0-only` compatibility review
and has a bounded interface owned by MeshSpan.

Versions below are resolved and pinned only when implementation begins. Automated
updates must pass the same complete local gates as a human change.

## Toolchains

| Tool | Required line | Purpose |
| --- | --- | --- |
| Rust | Latest tested stable; currently planned around 1.98 | Daemon, embedded services and native tools |
| Node.js | 26 | Reproducible web build/test tooling only; no production Node.js service |
| TypeScript | 7.x | Strict web application and generated API types |
| pnpm | Current pinned stable | Reproducible JavaScript dependency and workspace management |

Solid 2 is available as the `next` release candidate `solid-js@2.0.0-rc.3`.
MeshSpan will pin that exact prerelease rather than accidentally resolving the
`latest` tag, which currently remains on Solid 1. Companion packages must use
their Solid-2-compatible prerelease lines and pass the complete panel suite
before any upgrade.

## Rust production dependencies

### Runtime and transport

| Direct dependency | Need |
| --- | --- |
| `tokio` | One async runtime, sockets, tasks, timers, channels and bounded blocking workers |
| `tokio-util` | Cancellation tokens and framed/stream utilities not present in the core runtime |
| `quinn` | Private QUIC streams and datagrams between mutually authenticated nodes |
| `rustls` | Shared in-process TLS implementation for QUIC, HTTPS and certificate handling |
| `bytes` | Bounded zero-copy-oriented network buffers |

There is no OpenRaft or `raft-rs` runtime dependency. Their behaviour remains a
reference and differential-test oracle for the standard-majority subset of the
MeshSpan-owned core.

### HTTPS, API and encoding

| Direct dependency | Need |
| --- | --- |
| `axum` | Embedded HTTPS API, administration panel assets and HTTP-01 route |
| `tower` | Explicit service boundaries, timeouts, concurrency and observability layers |
| `tower-http` | Narrow HTTP middleware such as tracing, limits and static asset handling |
| `serde` | Typed configuration and public JSON models |
| `serde_json` | Public JSON API and bounded diagnostic documents |
| `prost` | Versioned private Protobuf messages; generated types do not cross domain boundaries |
| `base64` | Strict URL-safe token and wire encodings where the protocol requires them |

Public API client/schema generation remains an open build decision. MeshSpan will
not add both a Rust schema framework and a TypeScript generator until one
round-trip/drift test proves the chosen single source of truth.

### Persistence and local filesystem

| Direct dependency | Need |
| --- | --- |
| `rusqlite` | Initial SQLite-compatible relational repository with explicit transactions and SQL |
| `cap-std` | Capability-scoped access beneath registered state/storage folders |
| `uuid` | Application-generated 128-bit identifiers; exact permitted versions are domain-defined |
| `unicode-normalization` | Canonical Unicode handling for names without locale-dependent behaviour |
| `jiff` | Rust-side expiry, duration and civil-time validation; authoritative instants remain UTC epoch microseconds |

SQL migrations, transaction boundaries and invariants remain MeshSpan code. No
ORM, generic migration framework or distributed database client is required for
the first implementation.

### Cryptography, identity and certificates

| Direct dependency | Need |
| --- | --- |
| `blake3` | Content, manifest, proof and operation digests where the design selects BLAKE3 |
| `argon2` | Password hashing with versioned parameters |
| `ed25519-dalek` | Signed routing, grants, receipts and offline-authority projections |
| `chacha20poly1305` | Authenticated envelope encryption for protected application material |
| `hkdf` | Domain-separated key derivation |
| `sha2` | Standards that mandate SHA-2, including certificate and SMB constructions |
| `getrandom` | Operating-system cryptographic randomness |
| `zeroize` | Best-effort erasure for owned secret buffers |
| `secrecy` | Types that prevent accidental secret formatting/logging |
| `rcgen` | Internal node certificates and certificate requests |

`webauthn-rs` and `totp-rs` are evaluation candidates for the WebAuthn and TOTP
authentication-method adapters. They are not admitted until their parsing,
storage, platform, maintenance and dependency trees pass the security review.

No ACME library is selected yet. The current candidates each miss at least one
mandatory constraint, most importantly first-class HTTP-01 plus DNS-01 control
behind MeshSpan's cluster-wide certificate coordinator. The likely boundary is
a small MeshSpan ACME state machine using the existing HTTPS/TLS/JSON stack and
pluggable DNS publishers; this avoids a second hidden certificate authority or
external daemon.

### Erasure coding

Exactly one implementation will be selected by the Stage 1 correctness and
benchmark harness:

| Candidate | Evaluation purpose |
| --- | --- |
| `reed-solomon-erasure` | Straightforward mature matrix implementation and reference vectors |
| `reed-solomon-simd` | SIMD/FFT-oriented throughput on x86-64 and ARM64 |

Both must round-trip every allowed geometry, reject corrupt/wrong-length slices,
produce stable manifests across platforms and pass Raspberry Pi plus server
benchmarks. Shipping both is not the default; a second implementation is useful
only if it earns a clear profile-specific benefit behind the coding interface.

### Embedded SMB

No SMB server crate is approved as a production dependency today.

The current `smb-server` crate is useful reference code and exposes a promising
backend seam, but its current release does not meet MeshSpan's first profile: it
offers older dialects, does not implement SMB encryption and does not require
signing. It also owns users/passwords in a way that cannot be MeshSpan's
authoritative cluster-wide IAM boundary.

The likely implementation is therefore a MeshSpan-owned bounded SMB 3.0.2/3.1.1
server over `tokio` and `bytes`, using the same filesystem, handle, IAM and crypto
contracts as HTTPS. We may reuse an upstream parser or backend trait only after
adversarial wire tests prove exact bounds and the missing security features can
be added without fighting its architecture.

### Command line, errors and telemetry

| Direct dependency | Need |
| --- | --- |
| `clap` | Validated headless daemon flags, including repeated `--storage-path` |
| `thiserror` | Specific library/domain errors with explicit sources |
| `tracing` | Structured spans/events without a second logging system |
| `tracing-subscriber` | Configurable local formatting and bounded filtering/export plumbing |

No metrics backend is required to run the appliance. The observability contract
emits bounded internal metrics; exporters are replaceable adapters.

## Rust verification-only dependencies and tools

These do not ship in the daemon:

| Dependency/tool | Need |
| --- | --- |
| `proptest` | Generated domain, parser, schema, quorum and state-machine cases with shrinking |
| `stateright` | Executable bounded models for consensus and distributed state machines |
| `loom` | Exhaustive small-schedule concurrency checks for shared-memory primitives |
| `turmoil` | Deterministic network partitions, delay, loss and reconnect scenarios |
| `tempfile` | Isolated real-filesystem fixtures |
| `criterion` | Repeatable microbenchmarks with regression evidence |
| `cargo-nextest` | Fast partitioned Rust test execution |
| `cargo-fuzz` | Coverage-guided wire, manifest, SQL-value and recovery-input fuzzing |
| `cargo-deny` | Advisory, duplicate, source and `GPL-2.0-only` dependency-policy checks |
| `cargo-audit` | Independent Rust advisory check |

Real SMB/HTTPS clients, multi-process daemons, power/fault injection and
multi-machine acceptance remain black-box test infrastructure rather than Rust
library dependencies.

## Web production dependencies

| Direct dependency | Need |
| --- | --- |
| `solid-js` `2.0.0-rc.3` | Pinned Solid 2 reactive runtime from the `next` tag |
| `@solidjs/web` `2.0.0-rc.3` | Solid 2 DOM renderer paired exactly with the runtime prerelease |
| `@solidjs/router` `2.0.0-next.18` | Solid-2-compatible URL routing and nested user/admin panel layouts |
| `@js-temporal/polyfill` | Temporal until every supported browser provides the required API natively |
| `zod` 4.x | Runtime validation and type narrowing for untrusted API, route, persisted-browser and form inputs |
| `openapi-fetch` | Thin typed wrapper over native `fetch`, if OpenAPI is selected as the public API source |
| `@kobalte/core` | Candidate accessible primitives for dialogs, menus, selects and focus management |

`@kobalte/core` is optional until a native implementation proves less risky.
There is no Axios, Redux-style state store, CSS framework, chart framework or
general component suite in the default dependency set. Solid signals/resources,
native `fetch`, CSS and browser platform APIs are sufficient initially.

## Web build and verification dependencies

| Direct dependency | Need |
| --- | --- |
| `typescript` 7.x | Strict type checking and project references |
| `vite` | Fast development/build pipeline and static production bundle |
| `vite-plugin-solid` `3.0.0-next.27` | Solid-2-compatible compiler integration |
| `@types/node` | Node 26 build-script types only |
| `openapi-typescript` | Generated public API types, only if OpenAPI is selected |
| `vitest` | Fast unit and component tests sharing Vite transforms |
| `@solidjs/testing-library` | Behaviour-level component tests once its declared peer range accepts the pinned Solid 2 prerelease; tests use Vitest/browser primitives until then |
| `@testing-library/user-event` | Realistic keyboard/pointer interaction in component tests |
| `happy-dom` | Fast DOM for non-browser unit/component suites |
| `@playwright/test` | Real Chromium, Firefox and WebKit journeys with no manual browser interaction |
| `@axe-core/playwright` | Automated accessibility checks inside the real-browser journeys |
| `eslint` | JavaScript/TypeScript lint runner |
| `@eslint/js` | Maintained core JavaScript correctness baseline for flat configuration |
| `globals` | Explicit browser and Node build-script global sets |
| `typescript-eslint` | Type-aware TypeScript rules |
| `eslint-plugin-solid` | Solid-specific correctness rules |
| `eslint-plugin-jsx-a11y` | Static accessibility checks for JSX |
| `eslint-plugin-sonarjs` | Cognitive-complexity and maintainability rules not supplied by core ESLint |
| `eslint-plugin-import-x` | Import graph, dependency and layer-boundary correctness |
| `eslint-plugin-regexp` | Regular-expression correctness and safety checks |
| `@eslint-community/eslint-plugin-eslint-comments` | Requires used, described and narrowly scoped lint suppressions |
| `@vitest/eslint-plugin` | Vitest correctness and prevention of focused or silently disabled tests |
| `eslint-plugin-n` | Node 26 correctness for build and configuration scripts only |
| `prettier` | Deterministic Markdown, JSON, CSS and TypeScript formatting |

Unit and component suites are split from real-browser acceptance so routine
feedback remains fast. The production daemon embeds only the built static files;
none of the Node.js toolchain is required on an installed appliance.

## Explicit non-dependencies

- no external SQL server, consensus daemon, Samba, reverse proxy or certificate
  process;
- no FUSE layer between SMB/HTTPS and the MeshSpan filesystem service;
- no runtime Node.js service;
- no generic plugin loader or downloaded executable extensions;
- no ORM or framework-owned persistence model; and
- no runtime dependency on a cloud control plane.
