# Pre-Stage 6 accepted-decision retrofit evidence

Status: **complete on 2026-08-30**.

This evidence closes the D-074–D-077 retrofit without treating the earlier
authentication or direct-remote-principal scaffolds as implementation. Stages
1–5 retain their existing behavioural evidence under the accepted contract.

## Authority invariant

Each swarm is the intrinsic root principal for every volume, folder, file and
version it owns. The owner may grant local users/groups and receiving swarms
independently. These are sibling delegations from ownership; there is no
self-federation relationship or self-grant. A receiving swarm assigns its grant
to its own principals and may re-delegate only through an explicit, narrowing
hop.

## Executable closure

| Retrofit obligation                                                             | Evidence                                                                                                                                                                                                                                                                                                                                                |
| ------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Remove password, user-client-certificate and service-specific credential models | Rust-authored `CreateSessionRequest` accepts passkey or login-capable API-key input. Metadata has typed passkey, TOTP, recovery-code and scoped API-key records. The committed hostile fixtures reject the removed password shapes. Generated OpenAPI, TypeScript, Fetch and Zod drift passes.                                                          |
| Persist one protected, single-use first-boot claim bundle                       | `meshspan-daemon` claim-service and claim-file tests prove owner-only output, restart recovery, exact rotation, substitution rejection, consumption, cleanup and lost-response replay. The daemon suite is a distinct parallel root-gate lane.                                                                                                          |
| Replace imported remote-principal authority                                     | Swarm-targeted grants name only the recipient swarm. Recipient-local assignments cover users and nested groups, optional activation, time bounds and immediate identity/session fencing. Remote actor attestations describe lifecycle only and cannot grant rights or create a local principal.                                                         |
| Preserve root ownership and narrow A→B→C authority                              | `intermediary_verifies_downstream_then_countersigns_for_the_root_owner` proves C cannot address A directly, B validates C, the child loses rights and further-delegation authority, B countersigns for A, and A admits the immutable mutation while retaining C as the original actor. A imports neither C's user record nor the child consensus state. |
| Propagate expiry and revocation safely                                          | `relay_rejects_forgery_and_withholds_new_signatures_after_upstream_expiry` rejects a forged C acknowledgement and withholds B's signature after A→B expiry. `upstream_revocation_quarantines_later_downstream_work_after_restart` admits pre-revocation work, quarantines later work and preserves that decision after reopening the database.          |
| Persist exact relay attribution and history bindings                            | Federation evidence stores the original actor and accountable accepting swarm separately. Both fields are signed, encoded in branch history format 3, persisted with the acknowledgement and revalidated during admission and quarantine recovery.                                                                                                      |
| Report device protection independently from machine HA                          | `one_machine_reports_device_protection_separately_from_machine_ha` proves one host with three independent targets can survive two backing-device losses while correctly reporting that loss of its sole machine is not survivable.                                                                                                                      |

## Complete local gate

The root gate ran under the active NVM default, Node.js `26.8.1`, pnpm `11.19.0`
and Rust `1.98.0` with four workers. On 2026-08-30 it passed generated-contract
drift; Rust formatting and workspace-wide Clippy; every domain, contract, API,
metadata, consensus, protocol, QUIC transport, storage, data-plane, filesystem,
cluster and daemon test lane; Prettier; ESLint; TypeScript; scheduler tests; and
web tests in `173.48s`.

Negative fixtures and security guards deliberately retain forbidden strings as
hostile inputs. No accepted API model, handler, authentication record or
service-specific credential kind provides password, user-client-certificate or
SMB-only authentication.
