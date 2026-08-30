# MeshSpan

MeshSpan aims to turn storage folders on ordinary machines into one dependable shared storage
system. It should behave like an appliance: simple to operate, difficult to misuse, and capable of
recovering from routine failures without an administrator repairing internal state by hand.

## Product goals

- Combine one or more machines and storage folders into a single shared namespace.
- Protect data across independent machine and storage-device failures, then detect damage and heal
  automatically.
- Start usefully on one machine and grow without requiring a redesign or specialist administration.
- Keep ordinary file work available on disconnected nodes/sites and reconcile it automatically when
  links return, while preserving every acknowledged version.
- Provide simple cluster-wide users, permissions and administration.
- Serve files through built-in access endpoints, initially HTTPS and SMB, without exposing raw
  storage folders.
- Run headlessly with sensible defaults while providing clear user and administrator interfaces.

## Governing principles

### 1. Simplicity is absolute

The machine should do what the user asks and make safe, sensible decisions automatically. Routine
operation must not require choosing between conflicting internal versions, locating shards, or
manually reconstructing data. When MeshSpan cannot act safely, it must explain the problem plainly
instead of guessing or pretending success.

### 2. Reliability governs the system

Correct transactions are only the beginning. MeshSpan must remain available within its declared
failure limits, preserve every acknowledged change, detect corruption, recover after interruption,
and heal redundancy automatically. It must never claim protection or durability it has not proved.

### 3. Speed matters

Normal work must be fast and efficient. Small operations must not stall behind unrelated global
work, and large transfers must use bounded parallelism without wasting memory, CPU, disk or network
capacity. The development feedback loop must also stay fast enough to catch failures locally before
code is pushed.

### 4. Flexibility enables growth

Storage, metadata and access protocols need narrow, deliberate interfaces. That should allow new
storage implementations, workloads and access endpoints to be added without rewriting the system
or weakening its guarantees. Flexibility must come from clear boundaries, not speculative
complexity.

### 5. Security is fundamental

Users and permissions must work consistently across the whole mesh. Sign-in, administration and
node enrolment must be straightforward, with safe defaults and least-privilege access. MeshSpan
must manage node identity and certificate issuance, distribution and renewal without requiring the
administrator to operate a separate certificate system.

## Status

MeshSpan is a clean-slate, pre-alpha project. No compatibility or stability guarantee applies
before version 1.0. The executable foundations through Stage 5 and the accepted authentication,
federation and topology retrofit are complete. Stage 6 is next. See the
[retrofit evidence](design/pre-stage-6-retrofit-evidence.md),
[federation contract](design/federation.md) and [roadmap](design/roadmap.md).
The accepted requirements, architecture and implementation order are in the
[design review pack](design/README.md).

## Development

MeshSpan currently requires Rust 1.98.0, Node.js 26 and pnpm 11.19.0. Install the pinned web
dependencies, then run the complete fast local gate:

```sh
npx --yes pnpm@11.19.0 install --frozen-lockfile
npm run check
```

The command checks generated-contract drift before running independent Rust and web lanes in
parallel. `MESHSPAN_CHECK_WORKERS` may set a bounded worker count from 1 to 32; the default is the
smallest safe limit derived from four workers, available CPU parallelism and available system
memory. Regenerate the committed OpenAPI, TypeScript, native-Fetch and Zod artefacts with
`npm run generate:api`.

Early development uses local verification only. There are deliberately no GitHub Actions yet.

## GPL-2.0-only

**Valid licence identifier: `GPL-2.0-only`.**

MeshSpan is licensed exclusively under [`GPL-2.0-only`](LICENSE). No
later-version option is offered.
