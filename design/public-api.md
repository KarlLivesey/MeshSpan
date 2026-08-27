# Public HTTPS API and validation

Status: draft for review. This document defines the public contract to be built;
it does not describe an implemented API.

## 1. One source of structural truth

Rust endpoint, request and response boundary types are authoritative. A
constraint expressible in OpenAPI—required/optional, nullable, enum, format,
length, range, pattern, collection shape or discriminator—is declared once on
the Rust type and drives:

```text
Rust boundary types and structural constraints
                  |
                  v
          generated OpenAPI
                  |
                  v
    generated TypeScript + native-Fetch SDK + Zod 4 schemas
```

Rust performs structural validation independently at ingress and before emitting
a response. It then applies stateful domain validation for permissions,
revisions, uniqueness, topology, capacity and cross-record invariants. OpenAPI
and Zod never become server security boundaries, and external clients are never
required to use the generated SDK.

The initial Rust schema stack is selected only after a focused proof shows one
set of constraints can drive runtime validation and OpenAPI 3.1 without a second
hand-maintained model. The web generator is `@hey-api/openapi-ts` with its
TypeScript, native-Fetch SDK and Zod 4 outputs.

Handwritten Zod is limited to browser-only state absent from the public API,
such as a password-confirmation field or an unfinished local wizard step. It
must not recreate an API payload schema.

## 2. Version paths

MeshSpan exposes three kinds of direct route; none redirects:

| Path | Meaning |
| --- | --- |
| `/api/latest` | Rolling edge contract; may change incompatibly |
| `/api/v1.x` | Rolling pin to the newest published compatible `1.*` fixed point |
| `/api/v1.0` | Exact immutable published fixed point |

Before MeshSpan 1.0 only `/api/latest` exists. Publishing the first stable API
creates `/api/v1.0`; later compatible fixed points may create `/api/v1.1`, while
breaking generations use `/api/v2.0`. Product and API versions are independent.

A numbered candidate remains mutable and is served only as `latest` until a
signed release manifest publishes its exact API version, OpenAPI digest and
generated-client fixture digest. Publication freezes that exact contract.
Support lifetime is not promised yet. A security or data-integrity emergency may
disable unsafe behaviour, but must identify affected versions, return a stable
error and publish remediation/replacement guidance rather than silently
reinterpret the contract.

Every available route exposes its exact document at `openapi.json`, for example
`/api/v1.0/openapi.json`. OpenAPI documents contain no secrets and are available
without authentication. Every response carries informational headers naming the
resolved contract (`latest` or an exact fixed point) and schema digest:

```text
MeshSpan-API-Version: 1.0
MeshSpan-API-Schema: sha256:...
```

Every generated OpenAPI `info.license` identifies MeshSpan as exactly
`GPL-2.0-only`; generated clients preserve the same source/header metadata.

Build/release gates verify the signed manifest and all generated fixtures. The
daemon performs only a cheap digest check over each embedded OpenAPI document;
it does not load web-client fixtures at runtime.

## 3. Message validation

Every request and response is suspect regardless of origin or authentication.
Validation covers path/query parameters, headers, cookies, JSON bodies, response
bodies and streaming control records.

- Requests reject unknown object fields unless a named field is deliberately an
  extensible map.
- Responses tolerate additive unknown fields only where the contract declares
  forward compatibility; those fields are discarded before application use.
- Unknown discriminated-union variants, control operations and security record
  variants fail closed.
- Missing means not sent/unchanged. `null` means explicitly blank/clear and is
  accepted only by a nullable Rust field.
- The API performs no implicit coercion: strings do not silently become numbers
  or Booleans. Form code may make explicit field-specific conversions before
  generated request validation.
- Normalisation, including whitespace handling, occurs only where the Rust
  contract explicitly declares it.
- A structurally valid request may still fail domain validation or
  authorisation.

If Rust detects an invalid outgoing response before transmission, it suppresses
the body, emits a generic internal-contract error and records a bounded
security/diagnostic event. A stream already in progress terminates; the receiver
does not publish output until its final integrity contract passes.

## 4. Contract completeness

Generation fails by default for missing/duplicate operation IDs, undocumented
outcomes, unspecified access requirements, ambiguous unions, accidental
additional properties, incomplete error envelopes or mutations lacking
idempotency/outcome semantics. Individual messages and in-memory collections are
bounded. A logically unbounded operation uses bounded streaming/chunks and
durable state.

Contextual exceptions—such as an anonymous health route, intentional map or
streamed body—are narrow, explicit and tested. They cannot arise from an omitted
annotation.

## 5. Authentication and early rejection

Every endpoint is default-deny and explicitly declares one access profile, such
as anonymous, authenticated, recent step-up administration or internal node.
Missing access metadata prevents route generation.

The initial replaceable authentication profile is:

- secure HTTP-only session cookie plus CSRF protection for browsers;
- scoped bearer token or client certificate for CLIs/applications; and
- a separate SMB-compatible credential for SMB.

Credentials never appear in URLs. Additional authentication handlers may be
added later without changing endpoint domain semantics.

Processing rejects cheap failures before expensive work:

1. connection/header/declared-body bounds;
2. route, method and media type;
3. authentication and coarse authorisation;
4. endpoint quota/concurrency/capability admission;
5. structural parse/validation;
6. current domain authorisation and execution.

Anonymous routes such as schema, health, login, enrolment and ACME HTTP-01 are
explicit, cheap and bounded. Endpoint resource policy uses concrete bounds and
measured admission budgets, not a rigid cost-category enum. A later admission
hint, if measurement justifies one, is a numeric weight.

## 6. Outcomes, errors and idempotency

Every mutation requires a client-generated operation ID. Repeating that ID with
the same canonical request digest returns the existing durable outcome; reuse
with different input is rejected. Connection loss never implies success or
failure.

One validation/error envelope carries:

```text
stable error code
plain message
request ID and operation ID where applicable
retry/unknown-outcome classification
bounded list of field path, constraint and safe detail
bounded remediation detail
```

Independent field failures may be returned together. Raw payloads, credentials,
secrets, internal paths and implementation details never appear.

Long-running mutations use one durable operation underneath both behaviours:

- asynchronous HTTPS returns `202` plus an operation/status URL; or
- wait mode holds only until a bounded deadline for a terminal outcome.

SMB maps operations to its own acknowledgement contract. It never reports
definite success for an unknown outcome.

## 7. Filtering and pagination

Potentially large collections provide indexed server-side filters and stable
ordering appropriate to their domain. Clients never download weeks of events or
millions of files merely to filter them locally.

For example, events support bounded time range, severity, node, actor, operation
and event-type filters and return newest first. Pagination uses an opaque cursor
within that filtered range. Every response with more results includes a
ready-to-follow relative `next_page_url` that preserves filters, ordering and
limit. With no next page the value is `null`. `previous_page_url` is optional
where reverse traversal is efficient.

Cursors bind the caller identity, query, ordering, collection revision/frontier
and scan position, but do not freeze old permissions. Every page applies current
users, group closure, grants, ownership and time rules server-side. Revoked
records disappear without forcing the client to restart and replay prior pages.
The server fills the requested page within a bounded internal scan/query budget
using indexed authorisation data; clients do not loop across hidden pages.

Exact total counts are optional. They are returned only when cheap/indexed or
requested through a distinct count operation; normal browsing never waits for a
full count.

## 8. Bulk atomic operations

A logical bulk operation may contain an effectively unbounded number of items,
but each request, frame, chunk and in-memory collection remains bounded:

1. create a durable operation;
2. upload and validate item IDs in bounded chunks;
3. seal an immutable input manifest;
4. validate every item, permission and expected revision;
5. prepare every owning metadata partition;
6. commit one durable global decision; and
7. publish or abort the complete batch.

All-or-nothing mode is mandatory across metadata partitions. Before the global
decision, an unreachable required partition leaves the operation pending until
its deadline; a coordinator that retains authority then records `abort` with no
globally visible effect. Without coordinator authority the transaction remains
in doubt until the decision can be recovered. A participant timeout alone can
never infer abort, because a commit decision may already exist. After a commit
decision, every participant completes automatically after crash or partition.
Prepared participants fence affected records. Until they learn the decision,
reads and conflicting mutations of those records wait or return a typed
unavailable/in-progress result; they never expose an old value beside a committed
new value from another participant. Unrelated records and partitions continue
working.

Availability-first deletion may first produce `branch_deleted` for the complete
batch on a local/cell branch. `globally_deleted` means every owning partition has
committed the atomic transaction. `bytes_reclaimed` means guarded asynchronous
cleanup has physically removed obsolete shards. Offline storage nodes never
block logical deletion unless policy explicitly requires them; they apply
tombstones and cleanup on return.

## 9. Concurrent deletion and version history

Reconciliation uses causal order first:

- a deletion causally after the latest version wins;
- an explicit recreation after observing deletion is a new surviving object;
- a genuinely concurrent content write/truncate or rename survives;
- a tag, timestamp, permission or ownership change alone does not resurrect a
  deleted object.

For an atomic batch, one concurrent conflict affects the complete batch. The
system does not delete only uncontested members.

MeshSpan initially performs no content-aware merge. One concurrent edit becomes
visible deterministically and every acknowledged alternative remains in
immutable version history. Users may `restore` a historical version as a new
current version or `restore as copy`; neither rewinds or erases history. A future
file-type merge interface may create a new version from immutable sources, but
can never overwrite those sources.

Ordinary version history is enabled by default and may be disabled per volume.
Retention combines a hard minimum age, optional minimum version count and one of
`after_age` or `under_pressure` reclamation. The default retains eligible
versions until storage pressure. Conflict versions use an independent minimum
safety retention even when ordinary history is disabled. Snapshots, explicit
pins and holds override automatic reclamation.

## 10. Streaming files

File content is never placed in JSON or passed through Zod. Generated OpenAPI
and Zod schemas validate control metadata, headers and terminal results.

- Declared length/range and bounded frames are checked before allocation/use.
- Integrity is accumulated incrementally and compared with the final content
  identity.
- Invalid, truncated, excessive or mismatched streams never publish a file
  version.
- Resume binds operation ID, content identity and independently verified ranges;
  it never trusts a claimed client offset.
- The Solid client normally uses the generated SDK. One reviewed streaming
  adapter may use native Fetch primitives while retaining generated control
  types and validators.

## 11. Events, polling and cache safety

Resumable Server-Sent Events provide optional one-way change notifications;
mutations remain ordinary HTTPS requests. No browser, CLI or third-party client
is required to implement events. Correctness rests on current validation and
authorisation at every request.

Missed permission-revision events are harmless. The Solid client may use one
event to evict affected cached records without automatically refetching every
list. Later responses also carry the current authorisation revision.

Read/status endpoints support revision-derived `ETag`/`If-None-Match` where
applicable. Authenticated validators incorporate both resource revision and the
caller-visible authorisation projection so revoked access cannot receive an
incorrect `304`. Cache controls remain private/no-store according to sensitivity.

## 12. Generated artefacts and proof

Generated OpenAPI, TypeScript, Fetch SDK and Zod 4 files are committed and must
not be hand-edited. Local generation is deterministic and fails on drift.
Generated code is exempt from human responsibility/size ceilings, but must:

- compile under strict TypeScript;
- contain no `any`;
- pass valid and invalid behavioural fixtures;
- prove unknown-field, nullable/missing, bound, format and union behaviour;
- validate both requests and responses; and
- preserve exact operation and error types.

Every published exact API fixture is regenerated and compared locally. Draft
work under `latest` may change. An emergency compatibility waiver is explicit,
signed and accompanied by replacement guidance.
