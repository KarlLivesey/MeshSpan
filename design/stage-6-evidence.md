# Stage 6 implementation evidence

Status: complete on 2026-09-02.

Stage 6 delivers the first usable HTTPS appliance slice. This is implementation
evidence, not a release declaration; release creation remains disabled pending
the dependency review.

## Delivered surfaces

| Surface                 | Executable evidence                                                                                                                                                                       |
| ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| First start             | Claim-bound create and join flows work through the public HTTPS boundary and headless configuration, survive restart, and reject changed replay.                                          |
| Authentication          | API keys, passkeys, TOTP, recovery codes, sessions, CSRF, step-up and revocation use the replicated authentication authority and fail closed at the HTTP boundary.                        |
| Native file API         | The MeshSpan-specific API provides paged directory listing, object metadata, bounded range reads and resumable authenticated upload without relying on the browser client for validation. |
| Administration          | Public typed APIs and Solid panels cover identities, permissions, volumes, storage folders, topology and operation status.                                                                |
| Storage activation      | Registered folders reopen as exact live providers with replicated permits; sibling host files are neither interpreted nor exposed.                                                        |
| Multi-gateway operation | A three-daemon process proof creates the mesh over HTTPS, transfers exact non-empty bytes through different gateways, and remains readable after the original node is lost.               |
| Contracts               | Rust authors OpenAPI; generated TypeScript, native Fetch and Zod artefacts are drift-checked, and requests and responses are validated at their trust boundaries.                         |
| Adversarial boundaries  | Tests cover malformed, oversized, ambiguous and substituted inputs; unauthenticated expensive bodies are rejected before consumption.                                                     |
| Operator flow           | A clean-machine-style process test uses only CLI configuration and public HTTPS for creation, folder registration, administration and an exact file round trip.                           |

## Exit-gate result

The final local gate ran under the NVM default Node.js 26.8.1 environment:

```text
PASS generated contract drift
PASS Rust format
PASS Rust lint
PASS Rust dependency licences
PASS JavaScript dependency licences
PASS workspace format
PASS web lint
PASS web typecheck
PASS scheduler tests
PASS Rust workspace tests (751.71s)
PASS web tests (2.13s)
DONE 794.46s with 4 workers
```

The focused affected-package run also passed 156 daemon unit tests, all three
real headless-process tests, 188 filesystem unit tests, the filesystem integration
proofs and Clippy with warnings denied.
