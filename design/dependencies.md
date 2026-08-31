# Top-level dependency inventory

Status: active inventory of admitted Stage 1 dependencies and reviewed future
candidates. Manifests and lockfiles remain authoritative for installed versions.

This document records what MeshSpan uses or, where a choice still requires
proof, the exact selection process it will follow. A planned entry is not an
implemented feature.

MeshSpan keeps its direct dependency surface explicit. A dependency is admitted
only when it removes more correctness or maintenance risk than it adds, supports
the required platforms/toolchain, passes a `GPL-2.0-only` compatibility review
and has a bounded interface owned by MeshSpan.

Installed versions are locked by `Cargo.lock` and `pnpm-lock.yaml`. Automated
updates must pass the same complete local gates as a human change.

Version locking provides reproducibility, not permission to remain on an
obsolete release line. MeshSpan must not resolve an incompatibility by pinning a
version which no longer receives upstream security or bug fixes. It must move to
a maintained release, adapt or replace the dependency boundary, or own the
small required implementation and its maintenance burden.

## Toolchains

| Tool       | Required line                                       | Purpose                                                                                                           |
| ---------- | --------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| Rust       | Latest tested stable; currently planned around 1.98 | Daemon, embedded services and native tools                                                                        |
| Node.js    | 26                                                  | Reproducible web build/test tooling only; no production Node.js service                                           |
| TypeScript | 6.0.3                                               | Strict web application and generated API types; upgrade to 7 when the generator and typed ESLint stack support it |
| pnpm       | Current pinned stable                               | Reproducible JavaScript dependency and workspace management                                                       |

Solid 2 is available as the `next` release candidate `solid-js@2.0.0-rc.3`.
MeshSpan will pin that exact prerelease rather than accidentally resolving the
`latest` tag, which currently remains on Solid 1. Companion packages must use
their Solid-2-compatible prerelease lines and pass the complete panel suite
before any upgrade.

## Admitted Rust dependency licences

These direct dependencies are currently installed. They are build-time tools or
libraries linked into project artefacts as indicated; transitive inventory and
source/advisory policy automation arrive before a release artefact is built.

| Rust dependency                    | Resolved version | Declared licence           |
| ---------------------------------- | ---------------: | -------------------------- |
| `aes`                              |            0.9.3 | `MIT OR Apache-2.0`        |
| `aes-gcm`                          |           0.11.1 | `Apache-2.0 OR MIT`        |
| `axum`                             |            0.8.9 | `MIT`                      |
| `chacha20`                         |           0.10.2 | `MIT OR Apache-2.0`        |
| `jsonschema`                       |           0.52.0 | `MIT`                      |
| `hmac`                             |           0.13.0 | `MIT OR Apache-2.0`        |
| `meshspan-otp` (workspace)         |            0.1.0 | `GPL-2.0-only`             |
| `meshspan-protobuf` (workspace)    |            0.1.0 | `GPL-2.0-only`             |
| `meshspan-passkey` (workspace)     |            0.1.0 | `GPL-2.0-only`             |
| `meshspan-quinn-rustls` (workspace) |           0.1.0 | `GPL-2.0-only`             |
| `meshspan-rustls-provider` (workspace) |        0.1.0 | `GPL-2.0-only`             |
| `sync_wrapper` (workspace)         |            1.0.2 | `GPL-2.0-only`             |
| `p256`                             |           0.14.0 | `Apache-2.0 OR MIT`        |
| `rusqlite`                         |           0.40.2 | `MIT`                      |
| `schemars`                         |            1.2.2 | `MIT`                      |
| `serde`                            |          1.0.229 | `MIT OR Apache-2.0`        |
| `serde_json`                       |          1.0.151 | `MIT OR Apache-2.0`        |
| `sha1`                             |           0.11.0 | `MIT OR Apache-2.0`        |
| `sha2`                             |           0.11.0 | `MIT OR Apache-2.0`        |
| `subtle`                           |            2.6.1 | `BSD-3-Clause`             |
| `thiserror`                        |           2.0.20 | `MIT OR Apache-2.0`        |
| `unicode-normalization`            |           0.1.25 | `MIT OR Apache-2.0`        |
| `tempfile` (test only)             |           3.27.0 | `MIT OR Apache-2.0`        |
| `bytes`                            |           1.12.1 | `MIT`                      |
| `chacha20poly1305`                 |           0.11.0 | `Apache-2.0 OR MIT`        |
| `ed25519-dalek`                    |            3.0.0 | `BSD-3-Clause`             |
| `quinn`                            |          0.11.11 | `MIT OR Apache-2.0`        |
| `rcgen`                            |           0.14.9 | `MIT OR Apache-2.0`        |
| `rustls`                           |          0.23.43 | `Apache-2.0 OR ISC OR MIT` |
| `tokio`                            |           1.53.1 | `MIT`                      |
| `tower`                            |            0.5.3 | `MIT`                      |
| `zeroize`                          |            1.9.0 | `Apache-2.0 OR MIT`        |

The workspace `sync_wrapper` package is a clean-room, narrow compatibility implementation for the
static exclusivity proof consumed by current Axum and Tower. The upstream package is
Apache-2.0-only, so it cannot ship in a `GPL-2.0-only` combined artefact. Cargo patches the exact
transitive package name to MeshSpan's allocation-free implementation; its unsafe surface is limited
to the documented pinned projection and `Sync` proof and is exercised by the normal local gate.

The workspace `meshspan-rustls-provider` package is the narrow, independently extractable
`GPL-2.0-only` Rustls provider boundary. It uses the current stable RustCrypto AES, AES-GCM,
ChaCha20, ChaCha20-Poly1305, P-256, HMAC and SHA-2 releases under their MIT options. Its initial
profile is TLS 1.3 only, with P-256 ECDHE and ECDSA identities plus AES-128-GCM and
ChaCha20-Poly1305 traffic protection. RFC 9001 AES and ChaCha packet/header vectors, tamper
rejection and a real mutually authenticated Rustls handshake are executable tests. Broader
algorithm support is not implied and requires equivalent standards and interoperability proof.

The workspace `meshspan-quinn-rustls` package binds caller-supplied Rustls configurations to the
public cryptography traits in current stable Quinn. It also supplies stateless-reset, retry and
address-validation-token protection without enabling Quinn's Ring or AWS-LC adapters. This keeps
the QUIC transport on maintained upstream Quinn while making the provider boundary explicit and
independently testable. The real transport suite proves mutual TLS, topology binding, independent
streams, saturation isolation, snapshots and federation framing through this adapter.

The production Rustls/Quinn dependency graph no longer resolves `ring`, whose declared licence is
`Apache-2.0 AND ISC`. No MeshSpan release artefact may ship while that conjunctive Apache-2.0
dependency remains. Downgrading is forbidden, and AWS-LC is not a licence solution because its
current sys crate also includes an Apache-2.0-only conjunct. The remaining `ring` resolution is
test-only certificate generation through `rcgen`; it must be removed before the dependency gate is
closed. Experimental providers which explicitly disclaim production readiness are not admissible.

| Web/runtime dependency  | Version | Declared licence |
| ----------------------- | ------: | ---------------- |
| `@js-temporal/polyfill` |   0.5.1 | `ISC`            |
| `zod`                   |   4.4.3 | `MIT`            |

The direct Node.js build/test dependencies in the lockfile are MIT or
Apache-2.0 except `@js-temporal/polyfill` (`ISC`) and
`eslint-plugin-sonarjs` (`LGPL-3.0-only`). SonarJS is an unmodified, separately
executed development tool; it is not linked into or shipped with a MeshSpan
runtime artefact. Exact versions remain visible in each tooling manifest and the
lockfile.

## Rust production dependencies

### Runtime and transport

| Direct dependency | Need                                                                             |
| ----------------- | -------------------------------------------------------------------------------- |
| `tokio`           | One async runtime, sockets, tasks, timers, channels and bounded blocking workers |
| `tokio-util`      | Cancellation tokens and framed/stream utilities not present in the core runtime  |
| `quinn`           | Private QUIC streams and datagrams between mutually authenticated nodes          |
| `rustls`          | Shared in-process TLS implementation for QUIC, HTTPS and certificate handling    |
| `bytes`           | Bounded zero-copy-oriented network buffers                                       |

There is no OpenRaft or `raft-rs` runtime dependency. Their behaviour remains a
reference and differential-test oracle for the standard-majority subset of the
MeshSpan-owned core.

### HTTPS, API and encoding

| Direct dependency | Need                                                                                |
| ----------------- | ----------------------------------------------------------------------------------- |
| `axum`            | Embedded HTTPS API, administration panel assets and HTTP-01 route                   |
| `tower`           | Explicit service boundaries, timeouts, concurrency and observability layers         |
| `tower-http`      | Narrow HTTP middleware such as tracing, limits and static asset handling            |
| `serde`           | Typed configuration and public JSON models                                          |
| `serde_json`      | Public JSON API and bounded diagnostic documents                                    |
| `meshspan-protobuf` | Bounded private Protobuf runtime and pure-Rust schema generation; generated types do not cross domain boundaries |
| `base64`          | Strict URL-safe token and wire encodings where the protocol requires them           |

Rust boundary types and structural constraints generate OpenAPI 3.1 and drive
runtime request/response validation through the admitted `schemars` and
`jsonschema` boundary. Every public route must prove that the same declared
constraint appears in runtime validation, OpenAPI and hostile fixtures without
a second hand-written model.

Private Protobuf encoding and generation use the independently extractable
`GPL-2.0-only` `meshspan-protobuf` workspace crate. It uses only the Rust
standard library, compiles the supported `proto3` schema directly in Rust and
does not invoke or ship an external `protoc`. Generated Rust is compiled in
`OUT_DIR`; canonical encoded fixtures remain committed and checked for drift
and compatibility.

### Persistence and local filesystem

| Direct dependency       | Need                                                                                                       |
| ----------------------- | ---------------------------------------------------------------------------------------------------------- |
| `rusqlite`              | Initial SQLite-compatible relational repository with explicit transactions and SQL                         |
| `cap-std`               | Capability-scoped access beneath registered state/storage folders                                          |
| `uuid`                  | Application-generated 128-bit identifiers; exact permitted versions are domain-defined                     |
| `unicode-normalization` | Canonical Unicode handling for names without locale-dependent behaviour                                    |
| `jiff`                  | Rust-side expiry, duration and civil-time validation; authoritative instants remain UTC epoch microseconds |

SQL migrations, transaction boundaries and invariants remain MeshSpan code. No
ORM, generic migration framework or distributed database client is required for
the first implementation.

### Cryptography, identity and certificates

| Direct dependency  | Need                                                                           |
| ------------------ | ------------------------------------------------------------------------------ |
| `blake3`           | Content, manifest, proof and operation digests where the design selects BLAKE3 |
| `ed25519-dalek`    | Signed routing, grants, receipts and offline-authority projections             |
| `chacha20poly1305` | Authenticated envelope encryption for protected application material           |
| `hkdf`             | Domain-separated key derivation                                                |
| `sha2`             | Standards that mandate SHA-2, including certificate and SMB constructions      |
| `getrandom`        | Operating-system cryptographic randomness                                      |
| `hmac`             | Maintained RFC HMAC construction used by interoperable TOTP verification        |
| `sha1`             | TOTP's interoperable HMAC-SHA-1 profile only; never a content/security digest   |
| `zeroize`          | Best-effort erasure for owned secret buffers                                   |
| `secrecy`          | Types that prevent accidental secret formatting/logging                        |
| `rcgen`            | Internal node certificates and certificate requests                            |

The independently extractable `GPL-2.0-only` `meshspan-passkey` crate owns the
bounded WebAuthn relying-party parser and validation state machine. It initially
uses current `p256` under its MIT option for the mandatory ES256 path and
`subtle` for constant-time binding comparisons. It has no MeshSpan application
dependency and invokes no external service or executable. Additional algorithms
are admitted only with exact standards vectors and a compatible maintained
cryptographic primitive. The independently extractable `GPL-2.0-only`
`meshspan-otp` crate owns bounded TOTP parameter, presentation and RFC-vector
verification. It uses the current RustCrypto `hmac`, `sha1` and `sha2` releases
under their MIT option, has no MeshSpan application dependency and returns the
exact accepted counter for authoritative replay prevention.

No ACME library is selected yet. The current candidates each miss at least one
mandatory constraint, most importantly first-class HTTP-01 plus DNS-01 control
behind MeshSpan's cluster-wide certificate coordinator. The likely boundary is
a small MeshSpan ACME state machine using the existing HTTPS/TLS/JSON stack and
pluggable DNS publishers; this avoids a second hidden certificate authority or
external daemon.

### Erasure coding

Exactly one implementation will be selected by the Stage 1 correctness and
benchmark harness:

| Candidate              | Evaluation purpose                                                 |
| ---------------------- | ------------------------------------------------------------------ |
| `reed-solomon-erasure` | Straightforward mature matrix implementation and reference vectors |
| `reed-solomon-simd`    | SIMD/FFT-oriented throughput on x86-64 and ARM64                   |

Both must round-trip every allowed geometry, reject corrupt/wrong-length slices,
produce stable manifests across platforms and pass Raspberry Pi plus server
benchmarks. Shipping both is not the default; a second implementation is useful
only if it earns a clear profile-specific benefit behind the coding interface.

### Embedded SMB

No SMB server crate is approved as a production dependency today.

The current `smb-server` crate is useful reference code and exposes a promising
backend seam, but its current release does not meet MeshSpan's first profile: it
offers older dialects, does not implement SMB encryption and does not require
signing. It also owns users/credentials in a way that cannot be MeshSpan's
authoritative cluster-wide IAM boundary.

The likely implementation is therefore a MeshSpan-owned bounded SMB 3.1.1-only
server over `tokio` and `bytes`, using the same filesystem, handle, IAM and crypto
contracts as HTTPS. We may reuse an upstream parser or backend trait only after
adversarial wire tests prove exact bounds and the missing security features can
be added without fighting its architecture.

### Command line, errors and telemetry

| Direct dependency    | Need                                                                 |
| -------------------- | -------------------------------------------------------------------- |
| `clap`               | Validated headless daemon flags, including repeated `--storage-path` |
| `thiserror`          | Specific library/domain errors with explicit sources                 |
| `tracing`            | Structured spans/events without a second logging system              |
| `tracing-subscriber` | Configurable local formatting and bounded filtering/export plumbing  |

No metrics backend is required to run the appliance. The observability contract
emits bounded internal metrics; exporters are replaceable adapters.

## Rust verification-only dependencies and tools

These do not ship in the daemon:

| Dependency/tool | Need                                                                            |
| --------------- | ------------------------------------------------------------------------------- |
| `proptest`      | Generated domain, parser, schema, quorum and state-machine cases with shrinking |
| `stateright`    | Executable bounded models for consensus and distributed state machines          |
| `loom`          | Exhaustive small-schedule concurrency checks for shared-memory primitives       |
| `turmoil`       | Deterministic network partitions, delay, loss and reconnect scenarios           |
| `tempfile`      | Isolated real-filesystem fixtures                                               |
| `criterion`     | Repeatable microbenchmarks with regression evidence                             |
| `cargo-nextest` | Fast partitioned Rust test execution                                            |
| `cargo-fuzz`    | Coverage-guided wire, manifest, SQL-value and recovery-input fuzzing            |
| `cargo-deny`    | Advisory, duplicate, source and `GPL-2.0-only` dependency-policy checks         |
| `cargo-audit`   | Independent Rust advisory check                                                 |

Real SMB/HTTPS clients, multi-process daemons, power/fault injection and
multi-machine acceptance remain black-box test infrastructure rather than Rust
library dependencies.

## Web production dependencies

| Direct dependency                 | Need                                                                                              |
| --------------------------------- | ------------------------------------------------------------------------------------------------- |
| `solid-js` `2.0.0-rc.3`           | Pinned Solid 2 reactive runtime from the `next` tag                                               |
| `@solidjs/web` `2.0.0-rc.3`       | Solid 2 DOM renderer paired exactly with the runtime prerelease                                   |
| `@solidjs/router` `2.0.0-next.18` | Solid-2-compatible URL routing and nested user/admin panel layouts                                |
| `@js-temporal/polyfill`           | Temporal until every supported browser provides the required API natively                         |
| `zod` 4.x                         | Runtime validation and type narrowing for untrusted API, route, persisted-browser and form inputs |
| `@kobalte/core`                   | Candidate accessible primitives for dialogs, menus, selects and focus management                  |

`@kobalte/core` is optional until a native implementation proves less risky.
There is no Axios, Redux-style state store, CSS framework, chart framework or
general component suite in the default dependency set. Solid signals/resources,
native `fetch`, CSS and browser platform APIs are sufficient initially.

## Web build and verification dependencies

| Direct dependency                                 | Need                                                                                                                                               |
| ------------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
| `typescript` 6.0.3                                | Strict type checking; 7 remains the next ecosystem-supported upgrade                                                                               |
| `vite`                                            | Fast development/build pipeline and static production bundle                                                                                       |
| `vite-plugin-solid` `3.0.0-next.27`               | Solid-2-compatible compiler integration                                                                                                            |
| `@types/node`                                     | Node 26 build-script types only                                                                                                                    |
| `@hey-api/openapi-ts`                             | Generates committed TypeScript types and Zod 4 schemas from Rust-generated OpenAPI                                                                 |
| `vitest`                                          | Fast unit and component tests sharing Vite transforms                                                                                              |
| `@solidjs/testing-library`                        | Behaviour-level component tests once its declared peer range accepts the pinned Solid 2 prerelease; tests use Vitest/browser primitives until then |
| `@testing-library/user-event`                     | Realistic keyboard/pointer interaction in component tests                                                                                          |
| `happy-dom`                                       | Fast DOM for non-browser unit/component suites                                                                                                     |
| `@playwright/test`                                | Real Chromium, Firefox and WebKit journeys with no manual browser interaction                                                                      |
| `@axe-core/playwright`                            | Automated accessibility checks inside the real-browser journeys                                                                                    |
| `eslint`                                          | JavaScript/TypeScript lint runner                                                                                                                  |
| `@eslint/js`                                      | Maintained core JavaScript correctness baseline for flat configuration                                                                             |
| `globals`                                         | Explicit browser and Node build-script global sets                                                                                                 |
| `typescript-eslint`                               | Type-aware TypeScript rules                                                                                                                        |
| `eslint-plugin-solid`                             | Solid-specific correctness rules                                                                                                                   |
| `eslint-plugin-jsx-a11y`                          | Static accessibility checks for JSX                                                                                                                |
| `eslint-plugin-sonarjs`                           | Cognitive-complexity and maintainability rules not supplied by core ESLint                                                                         |
| `eslint-plugin-import-x`                          | Import graph, dependency and layer-boundary correctness                                                                                            |
| `eslint-plugin-regexp`                            | Regular-expression correctness and safety checks                                                                                                   |
| `@eslint-community/eslint-plugin-eslint-comments` | Requires used, described and narrowly scoped lint suppressions                                                                                     |
| `@vitest/eslint-plugin`                           | Vitest correctness and prevention of focused or silently disabled tests                                                                            |
| `eslint-plugin-n`                                 | Node 26 correctness for build and configuration scripts only                                                                                       |
| `prettier`                                        | Deterministic Markdown, JSON, CSS and TypeScript formatting                                                                                        |

Unit and component suites are split from real-browser acceptance so routine
feedback remains fast. The production daemon embeds only the built static files;
none of the Node.js toolchain is required on an installed appliance.

Generated OpenAPI and web client/validator output are committed, never edited by
hand and regenerated deterministically by the local gate. Generated files are
exempt from responsibility/size lint ceilings but must compile strictly, contain
no `any` and pass the same valid/invalid contract fixtures as Rust.

The native-Fetch client has no runtime wrapper dependency. A small MeshSpan
generator reads the same OpenAPI operations and emits the route/method bindings,
bounded response reader and generated Zod request/response checks.

## Explicit non-dependencies

- no external SQL server, consensus daemon, Samba, reverse proxy or certificate
  process;
- no FUSE layer between SMB/HTTPS and the MeshSpan filesystem service;
- no runtime Node.js service;
- no generic plugin loader or downloaded executable extensions;
- no ORM or framework-owned persistence model; and
- no runtime dependency on a cloud control plane.
