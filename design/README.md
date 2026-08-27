# MeshSpan design review

Status: **draft for review**.

This folder separates what MeshSpan must do from how it will be built. A proposal in these files is
not a locked decision until it is moved to the accepted section of [decisions.md](decisions.md).

## Review order

1. [requirements.md](requirements.md) — normative, testable product and system requirements.
2. [domain-model.md](domain-model.md) — system concepts and ownership boundaries.
3. [interfaces.md](interfaces.md) — internal contracts and permitted dependency directions.
4. [identity-access.md](identity-access.md) — users, groups, authentication, permissions, owners and tags.
5. [security.md](security.md) — trust boundaries, threats, keys, capabilities and recovery controls.
6. [metadata.md](metadata.md) — persistence engines and transaction boundaries.
7. [schema.md](schema.md) — logical records, fields, relations and invariants.
8. [data-lifecycle.md](data-lifecycle.md) — write, read, deletion, repair and drain state machines.
9. [protocol.md](protocol.md) — private node protocol over Quinn.
10. [flows.md](flows.md) — complete create, join, access and failure operation sequences.
11. [verification.md](verification.md) — fast local suites, simulation, real clients and release proofs.
12. [roadmap.md](roadmap.md) — dependency order and observable exit gates.
13. [decisions.md](decisions.md) — accepted, proposed and unresolved design decisions.

## Document rules

- `MUST`, `MUST NOT`, `SHOULD` and `MAY` have their ordinary requirements meanings.
- Every normative requirement has a stable ID and one primary acceptance gate.
- Requirements describe behaviour. They do not name database tables, Rust crates or tests.
- Architecture explains how requirements are satisfied but cannot weaken them.
- Roadmap status reports demonstrated behaviour, not document or line counts.
- Examples and test clients do not become product requirements.
- Deferred features have explicit boundaries; they cannot appear as implicit fallbacks.
- Project-authored licence references use only `GPL-2.0-only`.

## Locking the design

Review can change anything while the pack is draft. Once accepted, changes to an invariant or
public behaviour require a short decision entry stating the reason, compatibility impact and new
acceptance evidence. Pre-1.0 changes may break compatibility, but they must remain deliberate.
