# MeshSpan design review

Status: **draft for review**.

This folder separates what MeshSpan must do from how it will be built. A proposal in these files is
not a locked decision until it is moved to the accepted section of [decisions.md](decisions.md).

## Review order

1. [requirements.md](requirements.md) — normative, testable product and system requirements.
2. [appliance-experience.md](appliance-experience.md) — the simplicity budget and forbidden operator complexity.
3. [domain-model.md](domain-model.md) — system concepts and ownership boundaries.
4. [interfaces.md](interfaces.md) — internal contracts and permitted dependency directions.
5. [identity-access.md](identity-access.md) — users, groups, authentication, permissions, owners and tags.
6. [security.md](security.md) — trust boundaries, threats, keys, capabilities and recovery controls.
7. [metadata.md](metadata.md) — persistence engines and transaction boundaries.
8. [schema.md](schema.md) — logical records, fields, relations and invariants.
9. [erasure-coding.md](erasure-coding.md) — data/recovery slices and failure-policy proof.
10. [locality.md](locality.md) — complete local copies, regional availability and placement policy.
11. [copy-on-write.md](copy-on-write.md) — immutable state roots, snapshots, restore and reclamation.
12. [disconnected-writes.md](disconnected-writes.md) — availability-first local commits and reconciliation.
13. [consistency.md](consistency.md) — eventual writes and declarative strong acknowledgement barriers.
14. [consensus.md](consensus.md) — owned consensus core, flexible quorums and safety proof obligations.
15. [scaling.md](scaling.md) — campus-scale availability cells and metadata partitioning.
16. [data-lifecycle.md](data-lifecycle.md) — write, read, deletion, repair and drain state machines.
17. [protocol.md](protocol.md) — private node protocol over Quinn.
18. [flows.md](flows.md) — complete create, join, access and failure operation sequences.
19. [verification.md](verification.md) — fast local suites, simulation, real clients and release proofs.
20. [roadmap.md](roadmap.md) — dependency order and observable exit gates.
21. [decisions.md](decisions.md) — accepted, proposed and unresolved design decisions.
22. [stage-0-review.md](stage-0-review.md) — concrete recommendations for the remaining lock decisions.
23. [dependencies.md](dependencies.md) — planned direct runtime, build and verification dependencies.

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
