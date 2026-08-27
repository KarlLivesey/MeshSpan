# MeshSpan

MeshSpan aims to turn storage folders on ordinary machines into one dependable shared storage
system. It should behave like an appliance: simple to operate, difficult to misuse, and capable of
recovering from routine failures without an administrator repairing internal state by hand.

## Product goals

- Combine one or more machines and storage folders into a single shared namespace.
- Protect data across independent machine and storage-device failures, then detect damage and heal
  automatically.
- Start usefully on one machine and grow without requiring a redesign or specialist administration.
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
code reaches CI.

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
before version 1.0.

## GPL-2.0-only

MeshSpan is licensed under [`GPL-2.0-only`](LICENSE).
