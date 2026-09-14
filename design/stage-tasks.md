# Remaining stage tasks

This is the task/status index for Stages 10–12. Each stage has its own numbered
list. Refer to work as **Stage 10, task 1**, for example. Keep numbers stable:
append new tasks rather than renumbering existing ones, and explain scope changes.
The [roadmap](roadmap.md) defines stage order; [requirements](requirements.md) and
[accepted decisions](stage-6-11-decisions.md) define acceptance, not this inventory.

The owner adopted the MeshSpan Viability Pack on 2026-09-14 as the implementation
breakdown. Its ticket IDs cross-reference these stable stage tasks; they do not
replace accepted requirements or count as completed acceptance. The first active
slice is CORE-01 (Stage 3 / Stage 11 task 4), ACC-02 (truthful browser outcomes),
DATA-05 (Stage 10 task 17, pack lifecycle) and NET-01 (external TLS). Daemon
lifecycle, first-credential onboarding and SMB lease renewal follow their
dependency-ready boundaries. The first integrated checkpoint requires two users
to sign in independently, share exact bytes over HTTPS and SMB, retain an open
beyond 60 seconds, restart and recover exact outcomes. Snapshot provenance and
focused results are recorded in [the existing evidence log](stage-10-evidence.md#viability-pack-adoption-and-core-01-prefix-proof).

Status baseline: 2026-09-06, after merge `f27acad`. This is a reconciliation of
recorded evidence and implementation entry points, not a new test run or a full
code audit. **Recorded complete** means the stated task has linked implementation
and passing evidence, not that every later-stage proof has passed. **Partial**
means work exists but the stated acceptance remains open. **Open** means completion
has not been established; it does not assert that no supporting code exists.

Update the relevant task when work changes its status. Report the current task,
what behaviour changed, what remains and what was tested. Do not replace this
with “nearly done”, a count of commits or an unweighted completion percentage.

Remaining-effort estimate, 2026-09-09: **Stage 10: 81 points; Stage 11: 126
points; Stage 12: 55 points.** These are preliminary engineering judgements from
the task scope and recorded gaps, not measured hours or completion guarantees.
Uncertainty is high until the open integration/proof work is exercised.

Use the same scale across tasks: **1** small bounded adjustment; **2** focused
implementation and regression; **3** modest integrated change; **5** medium
cross-component feature/proof; **8** substantial integration or test campaign;
**13** large subsystem or multi-scenario campaign. Points include implementation,
tests, necessary corrections and integration. They estimate work still left,
not work already spent; a recorded-complete task has zero remaining points.

Hardware/credential access, owner approval, independent-review scheduling and
the seven-day soak's elapsed duration are separate calendar constraints. Stage
11 review points cover preparation, coordination and known work, not unknowable
future findings. No point-to-hour conversion is calibrated yet. Stage 12 remains
outside the 0.1.0 total. Finishing Stage 10 does not finish the product proof.

Progress reports state **stage/task; task points left; stage points left; change
since the last report; current result/blocker**. Reduce estimates only when
evidence-backed work closes scope; explain increases or discovered work openly.
Keep these totals consistent with the task entries. Do not imply that a testing
failure has been fixed, or an external gate passed, just to reduce the total.

Publication remains prohibited: no release, tag, package/image publication or
publication workflow may run until the owner explicitly lifts the hold. Local
preparation does not satisfy requirements that explicitly require publication.
Hardware, external-service and independent-review evidence must be labelled
unavailable until actually obtained, not replaced with simulated evidence.

## Stage 10 — certificates, packaging and operations

Status: **in progress**. Finish and verify the open scope below before closing
the stage; publication-dependent acceptance remains held separately and visible.

1. **Mesh-local CA and domain-free HTTPS — Recorded complete.** **0 points remaining.**
   PKI-001/002/008. [CA implementation](../crates/meshspan-certificates/src/mesh_local_ca.rs)
   is linked to the [lifecycle evidence](stage-10-evidence.md#task-1-integration-closure):
   create/join/restart, trust-bundle download, automatic gateway delivery and
   clear domain guidance without weakening private node identity. The real-process provisioning,
   trust, join, rotation and restart test passed in 52.89 seconds after correcting
   original receipt timestamps, stale join-code TLS pins and same-certificate
   recipient rewrapping. Eight focused certificate tests passed in 0.25 seconds.
   Panel trust-download verification passed. The integration run exposed parallel
   startup timeouts; profiling identified repeated full OpenAPI generation per
   route, now replaced with shared immutable schema data. All five headless
   workflows then passed in parallel. OS-aware listener-port allocation also
   removes the observed collision with the outbound ephemeral pool; six tests
   (including its range parser) pass in 26.68 seconds. The final integration gate
   on `b9ff3de` passed in 852.44 seconds, including Rust workspace tests in 796.77
   seconds and web tests in 9.35 seconds. This closes the profiled startup issue
   and task acceptance; it does not establish invitation continuity across later
   leaf changes. The estimate fell 5 → 3 → 1 → 0 as this scope was verified.

2. **Automatic ACME and DNS challenge handling — Implemented; assembled renewal verification remains.** **1 point remaining.**
   PKI-003/004/006/010; accepted decisions §7.
   [ACME components](../crates/meshspan-acme/src/lib.rs) and
   [renewal scheduling](../crates/meshspan-daemon/src/certificate_renewal_scheduler.rs)
   exist. Verify HTTP-01, DNS-01, RFC 2136, Cloudflare and the authenticated webhook,
   plus durable manual-DNS tasks, authoritative probes and advance renewal notices.
   Record fencing, interrupted-order recovery, retry/rate-limit behaviour and
   no new order merely because gateways join. Live CA proof is task 5.
   [CA-directed error retry correction](stage-10-evidence.md#task-2--ca-directed-error-retry-deadlines)
   has focused and real TLS-to-command proof. The full dependency-update gate on
   `d83002b` passed, including the local integration gate in 1,059.56 seconds.
   This closes error-response retry guidance (8 → 7 points), not the remaining
   complete challenge lifecycle, worker replacement or gateway-sharing proof.
   The [real HTTP-01 lifecycle proof](stage-10-evidence.md#task-2--real-http-01-issuance-restart-and-gateway-delivery)
   now passes issuance, cleanup, restart and second-gateway installation with
   exactly one CA order. The full dependency-update gate on `7fb130c` passed,
   including the integration gate in 909.68 seconds. This closes the basic HTTP-01
   issuance/restart/delivery acceptance slice (7 → 6 points); DNS and interrupted
   or long-running orders, polling guidance and active challenge distribution remain.
   The [combined DNS/deadline candidate](stage-10-evidence.md#combined-candidate-and-bounded-rust-test-scheduling)
   passed the complete local gate on `510748f` in 892.62 seconds: Rust tests in
   803.13 seconds and web tests in 6.69 seconds. The Rust harness now receives the
   existing selected worker budget; this is not a claimed startup-speed improvement.
   Basic DNS-01 issuance/restart/delivery is now verified (6 → 5 points), as are
   owned response deadlines and normal expired-claim handling. Cloudflare/webhook/
   manual lifecycle, interrupted and long-running orders, successful polling hints
   and active-gateway challenge distribution remain. Higher-concurrency startup
   costs, absent SMB test-image prerequisites and external proofs remain explicit.
   [Successful-response polling guidance](stage-10-evidence.md#successful-response-polling-guidance)
   now retains receipt-time deadlines across checkpoints and replacement fences,
   with no early CA requests. Real HTTP-01/DNS-01 lifecycles enforce notification
   and finalisation delays. The full gate on `c48a078` passed in **751.75 seconds**
   (Rust **688.03**, web **5.69**), closing this scope **5 → 4 points**.
   [Publication recovery integration](stage-10-evidence.md#integrated-publication-recovery-candidate)
   retains original material/receipt/lifetime, continues the same manual task under
   replacement claims and verifies ordinary legacy lifetime candidates. The full
   gate on `aa4f5e8` passed in **748.09 seconds** (Rust **687.72**, web **5.46**).
   The [independent-lifetime and takeover proof](stage-10-evidence.md#integrated-independent-lifetime-and-takeover-proof)
   now passes actual process loss, the unmodified five-minute lease expiry, exact
   HTTP challenge restoration and completion of the same CA order. Its final
   opt-in run passed in **325.02 seconds**, and the full gate on `86be66f` passed
   in **792.30 seconds** (Rust **717.65**, web **9.94**), closing **4 → 3 points**.
   [Explicit retirement and atomic fresh retry](stage-10-evidence.md#exact-retirement-and-atomic-fresh-order-retry)
   now handles exhausted publication budgets and terminal CA resource rejection,
   keeping exact cleanup and CA deadlines through restart. Its full local gate on
   `6dc6dbe` passed in **590.19 seconds** (Rust **536.36**, web **6.19**), including
   the focused transaction-fault/reopen and daemon recovery checks.
   [Rejected-order process recovery](stage-10-evidence.md#rejected-order-process-restart-and-replacement-issuance)
   now proves exact cleanup, queued-daemon restart, retained deadline/key and a
   distinct replacement issuance in **336.68 seconds**. The existing lease-loss
   process regression also passed in **319.68 seconds** on this candidate. The
   full gate on `789ce79` passed in **494.96 seconds** (Rust **453.22**, web
   **5.09**), closing this slice **3 → 2 points**. Remaining CA error-response
   handling, DNS-provider process lifecycles and active-gateway challenge
   distribution are still outstanding.
   [Semantic CA-response rejection](stage-10-evidence.md#rejected-ca-responses-retain-accepted-state)
   now queues retry without replacing accepted state or masking local corruption.
   Its full gate on `17e633d` passed in **489.14 seconds**, and both opt-in
   process-recovery cases passed in parallel in **336.74 seconds**.
   [Response and certificate retry guidance](stage-10-evidence.md#retry-guidance-survives-parsing-and-terminal-certificate-refusal)
   now preserves valid hints when parsing or terminal certificate validation
   rejects a response, and separates remote trust refusal from invalid local
   trust configuration. The full gate on `9ff95fe` passed in **619.72 seconds**
   (Rust **568.60**, web **8.40**); both opt-in recovery cases passed together in
   **337.22 seconds**. This closes the identified response-guidance/trust gaps,
   not the remaining provider lifecycles or active-gateway challenge distribution.
   Task 2 remains **2 points** pending that integrated acceptance.
   The [shared HTTP-01 gateway candidate](stage-10-evidence.md#task-2--shared-http-01-gateway-challenges)
   now passes a real CA probe of both active gateways, exact cleanup and gateway
   restart with one issuance. It also fixes the missing founding-node endpoint
   which prevented a joined gateway restoring its private route after restart.
   The first full integration run **failed in 353.00 seconds**. The
   [recovery corrections](stage-10-evidence.md#recovery-corrections-awaiting-final-integration)
   address cross-process port collisions, cancelled control-connection reuse,
   election-timer suppression and a backup-provider refresh race. The strengthened
   headless suite passed **10 enabled tests in 36.64 seconds** before the final
   wrong-plan timer regression. [Final recovery integration](stage-10-evidence.md#final-recovery-integration)
   on signed source `115a6c5` passed in **780.44 seconds** (Rust **732.27**, web
   **5.58**), and both opt-in real-time recovery cases passed together in
   **337.90 seconds**. These results verify the owning-boundary corrections;
   they do not establish the cause of the older independent cluster-startup timeout.
   DNS-provider process lifecycles remain open; the estimate is unchanged.
   The [isolated provider lifecycle candidate](stage-10-evidence.md#task-2--isolated-dns-provider-process-lifecycles)
   now passes real-daemon Cloudflare, webhook and manual-DNS cases in separate
   offline Linux networks (**18.46**, **18.48** and **13.35 seconds** respectively).
   The first integration gate failed at an existing nested-runtime backup export;
   its [focused correction](stage-10-evidence.md#provider-integration-finding--remote-backup-export)
   now passes the operator proof through both gateways in **16.88 seconds**.
   [Final corrected-source integration](stage-10-evidence.md#final-provider-integration)
   on `4449f5d` passed in **601.03 seconds** (Rust **564.43**, web **4.82**).
   All three isolated provider cases passed on that source, as did both real-time
   ACME recovery cases together in **340.25 seconds**. This closes the provider
   lifecycle slice **2 → 1 points**. Advance renewal notification delivery
   remains an explicit dependency on task 21; it is not waived or replaced by
   simply listing tasks in the panel.
   [Notification integration](stage-10-evidence.md#tasks-221--complete-notification-transport-and-gateway-integration)
   now verifies delivery for all four manual-DNS phases with restart and exact
   retry. The missing integration above is implemented; the final assembled
   renewal acceptance remains, with live CA proof tracked separately in task 5.

3. **Encrypted certificate delivery and rotation — Partial.** **5 points remaining.**
   PKI-001/002/005/007/010; accepted decisions §7.
   [Gateway installation](../crates/meshspan-daemon/src/public_certificate_installation.rs)
   and [rotation](../crates/meshspan-daemon/src/public_certificate_rotation.rs) exist.
   Record end-to-end recipient-bound envelopes, installation acknowledgements,
   same-generation gateway activation, restart/failover and make-before-break.
   Include internal node/federation rotation independently of public CA schedules;
   identity private keys must remain node-local.
   The [private-peer retirement correction](stage-10-evidence.md#task-3--retire-private-peer-admission-on-reused-connections)
   reproduces and corrects stale admission on reused QUIC connections, including
   requests waiting on backpressure. Nine focused network tests and nine transport
   tests pass; affected Clippy passes. [Full integration](stage-10-evidence.md#private-peer-retirement-integration)
   on `209f373` passed in **710.14 seconds**, all three isolated provider proofs
   passed, and both real-time recovery cases passed in **337.29 seconds**. This does not
   complete automatic internal issuance, staged installation or federation rollover.
   The [live internal TLS candidate](stage-10-evidence.md#task-3--live-internal-tls-credential-selection)
   now selects newer local credentials in both directions without rebinding sockets
   or breaking existing connections. Exact generations survive metadata reopen;
   12 transport, 10 network and 10 enabled headless tests pass, as does affected
   Clippy. Full integration remains pending; durable automatic lifecycle work is
   still required and the estimate remains unchanged.
   The [automatic daemon renewal implementation](stage-10-evidence.md#automatic-daemon-renewal-implementation)
   now passes a real two-process renewal/join/forced-restart proof in **14.91 seconds**,
   with exact private TLS selection and unchanged identity key. Scheduling,
   installation acknowledgement and overlap retirement are wired into the daemon.
   Expired/offline readmission, issuer/federation rollover and stage-wide integration
   remain open; task 3 remains partial, not a blocker on implementing other Stage 10 tasks.

4. **External automated certificate publisher — Implemented; stage-wide verification pending.** **1 point remaining.**
   PKI-009. [API tests](../crates/meshspan-daemon/src/external_certificate_publisher_api_tests.rs)
   and [request contracts](../crates/meshspan-certificates/src/external_request.rs)
   exist. Close with a scoped external caller's complete publish/install/activate
   cycle, rejected names/chains/keys/lifetimes/generations and interrupted rollover.
   No manual-upload UI or private-key disclosure.
   The [real external-publisher cycle](stage-10-evidence.md#task-4--external-publisher-gateway-lifecycle)
   now verifies publication, joining-gateway delivery, exact retries, refused
   names/chains/keys/lifetimes/generations and interrupted rollover against two
   actual daemons. Full TLS handshakes verify exact replacement leaf bytes.
   Focused proof passes in **19.55 seconds**; remaining work is assembled-stage
   acceptance, reducing this task **5 → 1 points**.

5. **Live ACME acceptance — Open; external prerequisites required.** **3 points remaining.**
   Stage 10 exit gate, PKI-003–007/010. Run and retain real staging-CA evidence for
   both challenges, worker loss, renewal and gateway delivery. Local fake-CA tests
   do not close this task. Record required domain/DNS credentials and permissions
   as blockers if unavailable; never expose them in evidence.

6. **Automatic backup scheduling, local/remote-node copies and retention — Recorded complete.** **0 points remaining.**
   PER-004; accepted decisions §7. Evidence covers the
   [schedule API](stage-10-evidence.md#automatic-metadata-backup-policy-api),
   [retention](stage-10-evidence.md#automatic-retention-and-physical-reclamation),
   [defaults](stage-10-evidence.md#automatic-configuration-defaults) and
   [real multi-node placement correction](stage-10-evidence.md#bootstrap-node-remote-backup-identity).
   This closes the existing folder-backed automatic workflow, not external
   destinations, orphan retirement or disaster recovery (tasks 7, 9 and 10).

7. **Backup providers, federation destinations and failure overlap — Partial.** **3 points remaining.**
   PER-004/005, OPS-003/007; accepted decisions §7. Local target failure
   assessments and local/remote-node provider ownership are recorded in
   [backup evidence](stage-10-evidence.md#current-local-backup-failure-assessments).
   Implement/verify external provider and other-swarm destinations, authenticated
   transfer and current remote failure relationships. Unknown overlap must stay
   unknown rather than counting as independent protection.
   [Typed destination configuration and retained-provider pause](stage-10-evidence.md#task-7--typed-destination-configuration-and-retained-provider-pause)
   now expose the existing binding variants through the native API and preserve
   them in panel pause/resume controls. This does not close runtime delivery.
   [Federation consensus integration](stage-10-evidence.md#task-7--federation-consensus-command-integration)
   now carries all 25 existing federation operations through the canonical
   command adapter. Real consensus exercises relationship, grant and allocation
   lifecycles. Native pairing, endpoint/identity runtime and other-swarm backup
   transfer still need integration; library transport tests are not that proof.
   [Native invitation issuance and cancellation](stage-10-evidence.md#task-7--native-federation-invitation-api)
   now provide real consensus-backed HTTPS operations and exact retry receipts,
   distinct from node enrolment.
   [Two-swarm pairing over pinned HTTPS](stage-10-evidence.md#task-7--two-swarm-pairing-over-pinned-https)
   now consumes the invitation, retains outbound intent before IO and commits
   mutual approval through independent consensus authorities. The real TLS proof
   recovers a withheld approval reply after reopening local state and rejects
   changed intent before another network call. This reduces the remaining estimate
   from 13 to 8 points; it does not establish live federation service.
   [Native QUIC session lifecycle](stage-10-evidence.md#task-7--native-quic-session-lifecycle)
   now starts from committed pairing, reconnects automatically and retires a live
   connection after committed revocation, without rebinding or manual intervention.
   This closes the socket/session-owner slice: task 7 **8 → 6**, Stage 10
   **95 → 93**. Connections are transient; paired identities/routes are persisted.
   Native backup execution and provider delivery, post-expiry
   pairing recovery, automatic lifecycle restart and remote failure-overlap
   acceptance remain. Identity chaining/rollover remain under task 3; this proof
   does not establish quorum-derived time or multi-process federation operation.
   [Backup authority and provider composition](stage-10-evidence.md#task-7--backup-authority-and-provider-composition)
   now connect exact backup identities, shared allocation accounting and real
   folder capacity with restart recovery. This is provider-level acceptance, not
   signed federation wire dispatch or native cross-swarm delivery; the remaining
   estimate is unchanged.
   [Signed backup transfer and current authority](stage-10-evidence.md#task-7--signed-backup-transfer-and-current-authority)
   now prove signed capability issuance, current revocation/MAC fencing and
   store/retry/read/verify/delete through real QUIC and a real namespaced directory
   provider. Short/corrupt/excess uploads and pre-upload capacity rejection are
   covered. Native backup execution, destination resolution and multi-process
   delivery/restart/failure overlap remain open; no task-completion claim follows
   from this library-level network proof.
   [Native application-stream dispatch](stage-10-evidence.md#task-7--native-application-stream-dispatch)
   now serves signed authority pages through live paired sessions with separate
   stream/metadata budgets, reused readers, shared replay admission and observed
   shutdown. A stalled control stream and a rejected replay do not prevent valid
   requests. Allocation-route discovery and native backup delivery remain open.
   [Native backup-capability dispatch](stage-10-evidence.md#task-7--native-backup-capability-dispatch)
   now issues signed exact permits through those sessions under current bilateral
   authority; replay and committed grant revocation reject issuance. This reserves
   no space and does not claim stored bytes. Execution and delivery remain open.
   [Native backup-allocation discovery](stage-10-evidence.md#task-7--native-backup-allocation-discovery)
   now returns signed, revision-fenced pages over paired sessions; the native
   proof uses the discovered scope for capability issuance. Automatic grant and
   allocation provisioning, consumer selection, execution and retained-copy
   routing remain open, alongside non-local provider and multi-process proofs.
   [Native allocated-folder backup execution](stage-10-evidence.md#task-7--native-allocated-folder-backup-execution)
   now serves store/retry/read/verify/delete through the production dispatcher,
   with real folder/allocation accounting, independent bulk workers and retained
   catalogue ownership. The wire proof checks control responsiveness during a
   stalled upload and exact data recovery after catalogue retirement/reopen.
   Native local-provider execution closes **6 → 5 points**, Stage 10 **93 → 92**;
   automatic provisioning, consumer delivery, retained-copy routing, other-node
   forwarding and independent-process failure/overlap acceptance remain open.
   [Durable consumer routes and native client](stage-10-evidence.md#task-7--durable-consumer-routes-and-native-client)
   add immutable route intent, signed streaming client operations and a native
   provider facade used by the backup worker and export service. The facade
   resolves existing routes through lifecycle-owned sessions. Real QUIC proves
   exact client/provider round trips; this is not automatic first-copy placement.
   Grant/allocation provisioning and selection, refreshing changed remote grant
   revisions without moving stored objects, other-node forwarding and the
   independent-daemon restart/failure-overlap proof remain. The estimate stays
   **5 points**, Stage 10 **92**.
   [Automatic selection from existing allocations](stage-10-evidence.md#task-7--automatic-selection-from-existing-allocations)
   now fetches signed grant/allocation pages and commits the initial route before
   the publisher sends bytes. Exact retries reuse that route. This closes initial
   discovery/selection integration, not allocation provisioning: advertised
   ceilings do not reserve free bytes. Capacity-aware provisioning and safe
   recovery from a full selected allocation, remote revision refresh, forwarding
   and independent-process delivery proof remain; the estimate is unchanged.
   [Capacity admission before route commitment](stage-10-evidence.md#task-7--capacity-admission-before-route-commitment)
   now skips a confirmed full allocation before persisting a route or sending
   object bytes. The admitted stream is retained through route commitment and
   completed by the production provider. Automatic provisioning, post-admission
   failure recovery, remote revision refresh, forwarding and independent-process
   acceptance remain open; this is not closure of task 7.
   [Renewal contract finding](stage-10-evidence.md#task-7--renewal-requires-separating-storage-identity-from-grant-authority):
   grant replacement changes the ID used by allocation authority, physical backup
   routing and quota grouping. A revision-only refresh cannot fix renewal.
   The owner approved the cross-contract correction (D-084).
   [Metadata authority and accounting](stage-10-evidence.md#task-7--approved-renewal-correction-metadata-authority-and-accounting)
   now preserve allocations and charges under explicit grant succession. Wire
   namespace separation, consumer refresh and native renewal proof remain;
   the complete correction is not yet claimed.
   [Stable namespace and native renewal](stage-10-evidence.md#task-7--stable-backup-namespace-and-native-permission-renewal)
   now closes that wire/consumer gap: real native QUIC proves retained bytes and
   references remain usable after grant succession, with unchanged routing and
   accounting, and fresh requests reject retired/revoked permissions. Native
   proof **6.50 s**; this is not independent-daemon restart or power-loss evidence.
   Automatic provisioning, post-admission/unknown-outcome recovery, other-node
   forwarding and independent-process delivery/failure-overlap acceptance remain.
   Remaining estimate stays **5 points**, Stage 10 **92**.

   [Provider-owned automatic provisioning](stage-10-evidence.md#task-7--provider-owned-automatic-allocation-provisioning)
   now turns approved grants and eligible live folders into consensus-committed
   allocations during bounded maintenance. Real consensus/folder tests prove
   exact capacity, stale-plan rejection and cursor-restart idempotency (**0.51 s**).
   Assigned-quota reconciliation, uncertain-upload recovery, other-node forwarding
   and independent-process automatic-delivery/failure acceptance remain; task
   **5 points**, Stage 10 **92**, unchanged until those integration gates close.

   [Native interrupted-upload and withheld-receipt recovery](stage-10-evidence.md#task-7--native-interrupted-upload-and-withheld-receipt-recovery)
   now verifies an actually unpublished partial upload, a withheld final store
   response, fresh consumer resolution, unchanged routing and exact one-copy
   accounting over real QUIC. This corrects the earlier fixture's already-stored
   short-upload case; it is not a process-restart or network-partition proof.
   Assigned-quota fencing/reconciliation, other-node forwarding and independent
   daemon automatic-delivery/failure acceptance remain open; estimates unchanged.

   [Durable provider capacity seals](stage-10-evidence.md#task-7--durable-provider-capacity-seals)
   now stop new shard/backup admission atomically while retaining stored and
   uncertain charges across restart. Schema-14 migration, rollback and a real
   two-connection admission race pass.
   [Authenticated quota handoff](stage-10-evidence.md#task-7--authenticated-provider-quota-handoff)
   adds consensus acceptance of signed ceilings, keeps retained read authority,
   and reserves those charges before granting renewed write allowances. Altered
   stored signatures cannot release extra credit. Maintenance now assigns freed
   quota to a distinct successor and does not duplicate it after cursor restart;
   real consensus/folder proof passes in **0.51 s**.
   [Automatic provider sealing and recovery](stage-10-evidence.md#task-7--automatic-provider-sealing-and-recovery)
   now closes production key registration, seal selection/submission and pending
   evidence recovery. With 128 reserved bytes, the worker retains that charge and
   assigns only 896 of a 1,024-byte allowance; healthy scans, ledger/worker restart
   and key-mismatch rejection pass (**0.65 s**). Other-node forwarding and
   independent-daemon automatic-delivery/failure acceptance remain open.
   [Storage-owner relay authentication](stage-10-evidence.md#task-7--storage-owner-relay-framing-and-authentication)
   now preserves the original signed consumer frame over node-mTLS and rejects
   substituted senders, signatures, allocations, expiry and replay. Owner-side
   current-authority admission also passes real node-mTLS and consensus-enrolment
   checks. The [shared owner transfer service](stage-10-evidence.md#task-7--shared-storage-owner-transfer-service)
   now verifies directory capacity-before-ready, truncated upload, reopen,
   successful storage and exact replay over QUIC.
   [Native storage-owner dispatch](stage-10-evidence.md#task-7--native-storage-owner-dispatch)
   connects this hop to the registered-folder provider and shared allocation,
   catalogue, replay and bulk-worker ownership. Real QUIC tests cover truncated
   upload with retained reservation, exact retry, read/verify/delete and a direct
   request using the same catalogue. This closes **5 → 4 points**, Stage 10
   **92 → 91**. Gateway byte/reply forwarding and independent-daemon failure
   acceptance remain open; the native owner proof is not complete three-role
   consumer/gateway/storage-owner delivery.
   [Gateway forwarding integration](stage-10-evidence.md#task-7--gateway-forwarding-and-setup-gap)
   is now connected in production code, with ordered owner-reply validation and
   frame/digest/FIN checks. Full three-role delivery is still unverified, so this
   does not reduce the remaining proof estimate. Preparing that workflow exposed
   a missing administrator API for storage-grant issuance/restriction/revocation:
   current tests commit these typed commands directly. Add the real setup path
   and prove it through the native daemon; do not seed SQL to claim appliance
   acceptance. This adds **3 points**, task 7 **4 → 7**, Stage 10 **91 → 94**.
   The associated simple panel controls remain part of task 12.
   [Provider storage-offer administration](stage-10-evidence.md#provider-storage-offer-administration)
   now implements exact lookup and conditional issue/replace/revoke through the
   production router and existing consensus commands, with generated client
   validation and real-router lifecycle/retry tests. This closes **2 points**:
   task 7 **7 → 5**, Stage 10 **94 → 92**. Independent-daemon setup, forwarding
   and failure proof remain open; the new three-process test is not yet verified.
   [Three-daemon delivery and storage-owner restart](stage-10-evidence.md#three-daemon-delivery-and-storage-owner-restart)
   now proves setup through HTTPS, automatic remote storage and verification,
   encrypted export through a gateway distinct from its storage owner, and exact
   readback after that owner's process is killed and restarted. This closes
   **2 points**, task 7 **5 → 3**, Stage 10 **92 → 90**. Remote failure-overlap
   assessment and remaining provider denial/interruption acceptance are still
   open; this is not host power-loss or a complete integration-gate result.

8. **Backup history, encrypted export and restore-readiness API/panel — Recorded complete.** **0 points remaining.**
   OPS-001, PER-004/005. Evidence:
   [history](stage-10-evidence.md#native-backup-history-and-panel),
   [export](stage-10-evidence.md#native-encrypted-backup-export) and
   [restore checks](stage-10-evidence.md#gateway-restore-check-api-and-panel).
   This means bounded history, verified encrypted download and non-destructive
   checks, not offline decryption, live restore or catastrophe recovery.

9. **Interrupted backup publication and abandoned-object retirement — Recorded complete.** **0 points remaining.**
   PER-004/005, TST-002/007. [Empty unpublished reservations recover](stage-10-evidence.md#recovery-of-empty-unpublished-backup-reservations).
   Finish authoritative recovery/retirement of published-but-unindexed or
   otherwise unadmitted generations, including lost retained admission evidence.
   Prove restart/exact-retry behaviour, durable accounting and no deletion based
   solely on a pathname, expired lease or missing catalogue entry.
   [Reservation-backed provider recovery](stage-10-evidence.md#task-9--reservation-backed-provider-recovery)
   now restores a missing local provider index after verifying published bytes
   against the durable target reservation. Reopened objects are readable before
   another upload, with unchanged capacity charges. This closes the local
   published-but-unindexed recovery slice **8 → 7 points**; replicated admission,
   lost admission evidence and authoritative abandoned-generation retirement remain.
   [Recorded-generation source recovery](stage-10-evidence.md#task-9--recorded-generation-source-recovery)
   now lets the owned worker reconstruct missing/corrupt local staging from exact
   admitted provider copies, page unavailable sources, resume after local journal
   loss and finish the same generation. Real encrypted-folder/reopen tests and
   a live-daemon source-loss/completion/restart proof pass: **7 → 5 points**.
   Generations which never reached replicated admission, authoritative abandonment
   and remote-worker takeover acceptance remain; no timeout grants deletion authority.
   [Unrecorded-generation abandonment](stage-10-evidence.md#task-9--unrecorded-generation-abandonment)
   now commits exact expired-claim supersession and queues a fresh identity on the
   next worker pass, while recorded generations retain their recovery identity.
   Real consensus, canonical command and transactional recovery tests pass:
   **5 → 4 points**. Physical orphan retirement, lost admission evidence and full
   process-loss takeover acceptance remain; abandonment alone does not delete bytes.
   [Local abandoned-staging cleanup](stage-10-evidence.md#task-9--local-abandoned-staging-cleanup)
   now reclaims exact journal-owned local files after committed unadmitted
   abandonment, with bounded seek pages and durable file-before-journal removal.
   Remote provider objects and lost admission evidence remain outstanding.
   [Exact abandoned-object retirement authority](stage-10-evidence.md#task-9--exact-abandoned-object-retirement-authority)
   now commits immutable object/receipt-bound retirement only for an exact terminal,
   unadmitted run. Reopen/replay and rejection tests, migration from schema 100,
   canonical wire tests and real consensus-to-encrypted-folder deletion pass.
   This closes the retirement-authority slice **4 → 3 points**, Stage 10 **90 → 89**.
   Automatic discovery/receipt recovery, durable cleanup completion, provider-worker
   integration and full process-loss takeover remain; this is not automatic
   cross-swarm orphan cleanup.
   [Receipt-backed abandoned-object cleanup](stage-10-evidence.md#task-9--receipt-backed-abandoned-object-cleanup)
   now feeds admitted orphan retirements into the existing paged cleanup worker,
   persists exact provider completion separately from admitted copies, and resumes
   deletion after provider reopen and a lost completion commit. This closes
   **3 → 2 points**, Stage 10 **89 → 88**. Automatic discovery/receipt recovery
   and full process-loss takeover acceptance remain; the real folder/consensus
   worker proof is not cross-swarm orphan-cleanup acceptance.
   [Pre-IO upload intent](stage-10-evidence.md#task-9--pre-io-upload-intent)
   now retains exact upload identity in consensus before a provider can store
   bytes, including through the real three-daemon federated path. This removes
   dependence on the publishing worker's memory for the intended object. Receipt
   discovery/retirement and process-loss takeover remain open; no further points
   are closed by intent alone.
   [Automatic exact receipt discovery](stage-10-evidence.md#task-9--automatic-exact-receipt-discovery)
   now pages abandoned intents, obtains provider-owned references through local,
   same-swarm and federated lookup, and feeds exact evidence into retirement and
   durable cleanup completion. Real folder/consensus, signed QUIC lifecycle and
   lost federated-reply recovery checks pass. Missing lookup stays pending;
   no path formula or missing-object inference grants deletion. This closes
   **2 → 1 point**, Stage 10 **88 → 87**. Full process-loss takeover acceptance
   remains open; these component/composition proofs do not substitute for it.
   [Real-process worker takeover](stage-10-evidence.md#task-9--real-process-worker-takeover)
   closes that final gap: three daemon executables, a provider-catalogue write
   lock after physical publication, publisher `SIGKILL`, the unchanged five-minute
   production lease, a different node claiming the replacement, original-node
   restart, exact orphan retirement and protected replacement export/restore check.
   The isolated slow test passed in **325.81 seconds**. This closes
   **1 → 0 points**, Stage 10 **87 → 86**. Physical power-loss and hardware tests
   remain separate Stage 11 obligations, not claims made by this process proof.

10. **Offline verification and disaster recovery — Recovered HTTPS/SMB file access verified; operational closure remains.** **3 points remaining.**
    PER-004/005/007, TST-007. Recovery-bundle foundations and task 8 exist;
    [product-facing recovery remains outstanding](stage-10-evidence.md#remaining-backup-integration).
    Complete the documented offline verification and recovery-authority workflow,
    exact-position restoration, membership/secret checks and safe service
    admission. Restore-readiness must not masquerade as a completed restore.
    The [2026-09-14 Linux continuation](stage-10-evidence.md#tasks-1027--linux-directory-durability-prerequisite)
    reproduced PR #269's zero-root failure with deterministic startup-backup
    ordering. Requiring a fresh post-upload capture passes the original history
    assertions. Retained histories and live diagnostics explain the later
    unknown-peer failure: a fetch interrupted by gateway death legitimately uses
    its 30-second deadline before automatic catch-up, exceeding the fixture's
    15-second routing allowance. The post-restart readiness budget now includes
    that protocol deadline. The corrected full workflow passed in **139.28 s**,
    including committed cleanup/replay and file preservation. A preceding earlier,
    unlabelled post-restart timeout remains unexplained and retained; a passing
    retry does not close it. The full local gate then failed in **510.74 s**
    at a federation-pairing/backup session library test (`DeadlineExceeded`);
    headless and later Rust targets were not reached. Task 10 and integration
    remain open. Subsequent contextual reproduction identified an expired store
    request created before unrelated federation proofs; moving each attempt's
    deadline to its start passed all 440 daemon library tests. The new full gate
    passed the library and offline recovery, then failed three other headless
    cases (federated protection, successor peer startup and executable upload).
    Later Rust targets were not reached; the separate storage-snapshot
    `Unavailable` also remains unexplained.
    [Headless offline verification](stage-10-evidence.md#task-10--headless-offline-backup-verification)
    now consumes the actual encrypted export, independently saved digest and
    setup recovery bundle/code, checks exact SQLite state and stored recovery
    identity, and removes its private temporary plaintext. The real export/stop/
    verify/failure workflow passes in **8.13 seconds**, including exact-position
    comparison, wrong code, corruption and preservation of existing data.
    The command also now decrypts every retained secret generation, including
    historical keys, with the offline bundle. Indexed pagination and exact-key/
    ciphertext rejection checks pass; the real process workflow passes in
    **7.29 seconds**. This verifies retained rows, not completeness of every
    content-key reference or replacement-cluster admission.
    [Signed offline recovery preparation](stage-10-evidence.md#task-10--signed-offline-recovery-preparation)
    now binds exact recovery intent to the saved offline root, restores a new
    isolated database, retains its signed proposal and refuses normal consensus
    startup until explicit admission. Real encrypted-copy/reopen, substitution
    and schema-103 migration tests pass. This is not a completed recovery command:
    replacement/inventory validation, new authority and keys, credential fencing
    and activation remain open; no additional points close for preparation alone.
    [Replacement key preparation](stage-10-evidence.md#task-10--replacement-key-preparation)
    now produces fresh encrypted CA/permit generations and recovers retained
    authentication/content-secret envelopes for the exact replacement recipients.
    It preserves source metadata. [Durable control-key preparation](stage-10-evidence.md#task-10--durable-control-key-preparation)
    now retains the exact encrypted CA/permit pair across reopening, validates its
    offline decryption and certificate binding, and rejects conflicting retries.
    It does not install active keys;
    credential fencing and live recovery acceptance remain outstanding.
    [Restartable retained-secret inventory](stage-10-evidence.md#task-10--restartable-retained-secret-inventory)
    now saves exact per-generation replacement envelopes and atomically seals the
    complete verified source-secret set; incomplete inventories cannot seal.
    This preserves source keys and is not an active recipient grant or proof of
    complete file-content references.
    [Root-authorised replacement selection](stage-10-evidence.md#task-10--root-authorised-replacement-selection)
    now binds the exact identities, roles, endpoints, quorum specification and
    prepared key set to the signed recovery digest and retains the validated plan
    across reopening. A root signature cannot bypass recipient, source-incarnation
    or successor-epoch checks. It does not prove node installation or open the
    admission gate. [Isolated recovery credential fencing](stage-10-evidence.md#task-10--isolated-recovery-credential-fencing)
    now atomically revokes copied transient credentials, excludes old temporary
    activations and prevents runtime use of retired operational key generations,
    while preserving account credentials and archived ciphertext. Reopening,
    exact replay and failed-write rollback pass; this does not fence unreachable
    old nodes or activate the replacement cluster.
    [Node-side recovery key installation](stage-10-evidence.md#task-10--node-side-recovery-key-installation)
    now exports the signed encrypted key set and installs it through a real
    headless daemon command, with local decryption, owner-only durable publication,
    signed attestation, exact retry and corruption rejection. The real backup-to-key
    installation workflow passes in **9.51 seconds**. Certificate installation,
    all-node acknowledgement collection and service activation are not implied by that
    result. The coordinator now has a typed per-node acknowledgement journal:
    it reconstructs the expected encrypted bundle/transcript, verifies the selected
    node's signature and retains its first receipt across reopening. This remains
    key-installation evidence, not an all-node readiness or admission barrier.
    The current transfer also issues, verifies and durably installs the exact
    replacement node certificate alongside those keys; its digest is covered by
    the same node acknowledgement. Selecting it for live services remains gated
    by the outstanding recovery admission workflow.
    The headless `prepare-recovery` command now assembles that isolated preparation
    and exports per-node bundles from an independently verified backup and bounded
    public selection file. It explicitly reports that inventory verification and
    service admission have not occurred. `collect-recovery-installation` now
    consumes a saved installer report, independently verifies its selected-node
    signature and durably records one acknowledgement with exact retry semantics.
    It does not count that attestation as storage readiness or service admission.
    Preparation now publishes a complete isolated SQLite snapshot before exporting
    any node bundles. Exact retries verify and reuse it, retaining keys,
    certificates and collected receipts; unpublished interrupted work is rebuilt
    under an exclusive workspace lock. Missing exports are regenerated without
    overwriting changed existing material.
    The `stage-recovery-history` command now snapshots surviving filesystem
    journals without modifying the donor and checks retained root, manifest/layout
    and content-key references against the isolated preparation. It does not prove
    physical shards or grant service authority. Automatic backup preparation now
    archives both journals with the exact control snapshot, using the existing
    encrypted export and provider transport. The real HTTPS backup/stop/recovery
    workflow passes after making the original journals unavailable: history and
    its content-key envelope are recovered from the authenticated archive alone.
    [Backup capture now pins revision-windowed namespace roots](stage-10-evidence.md#task-10--backup-owned-namespace-retention) before copying,
    seals its exact source roots at admission and releases only its own retention.
    Metadata root enumeration and the filesystem cleanup proof include these pins;
    component tests do not prove the assembled physical-reclamation lifecycle.
    [Offline storage salvage and file reconstruction](stage-10-evidence.md#task-10--surviving-pack-salvage-and-verified-file-reconstruction)
    now recover exact multi-chunk plaintext from surviving encrypted packs without
    original target journals, including tested two-target loss. The source reader
    preserves crash-left WAL and original files, and reconstruction checks shard,
    encrypted-chunk and complete-file integrity. These are composed storage and
    filesystem capabilities; daemon recovery orchestration remains open.
    [Exact retained-tree selection](stage-10-evidence.md#task-10--exact-retained-tree-selection-in-backup-and-recovery)
    now connects backup capture and history staging to the existing bounded,
    restartable graph walker without requiring all causal ancestors. Separate
    tokens/cursors preserve the unchanged replication-history contract.
    [Persistent inventory and headless file verification](stage-10-evidence.md#task-10--persistent-pack-inventory-and-headless-file-verification)
    now connect the authenticated archive to exact file reconstruction through
    copied encrypted packs. Original filesystem and target journals are absent
    in the passing real-daemon proof (**18.96 s**); bad generations, corrupt bytes
    and source-overlapping work fail. Complete-file checks are not inventory-
    commitment validation or service admission. Low-level inventory capture resumes;
    the complete verification command currently requires a new work directory.
    [Verified inventory commitment before signing](stage-10-evidence.md#task-10--verified-inventory-commitment-before-recovery-signing)
    now derives the canonical commitment from authenticated metadata and copied
    pack bytes only after complete-file verification. Published retries recheck
    retained copies without original media; missing/changed copies and unsafe
    input/workspace overlap fail. The final real recovery workflow passed in
    **20.40 s**. Both preparation and independent verification now validate the
    signed inventory commitment, without granting service authority.
    [Successor startup and access](stage-10-evidence.md#task-10--successor-incarnation-through-real-daemon-startup)
    now carry the committed incarnation through consensus, private transport,
    gateway access, worker claims and new-peer bootstrap. Two real successor
    workflows pass in **12.50 s**, including HTTPS/QUIC enrolment and an external
    SMB client's exact-byte upload/download/deletion. Their stopped-node fixture
    supplies the successor projection; this fixes a necessary runtime boundary,
    not recovery admission, so the remaining estimate is unchanged.
    [Encrypted replacement-state delivery](stage-10-evidence.md#task-10--encrypted-replacement-state-delivery)
    now exports and installs prepared metadata/history with the selected node's
    encrypted keys, a root-signed exact-file binding and a durable node-signed
    report. The real command workflow passes in **23.27 s**, including corruption
    rejection, preserved existing destinations and a still-closed admission fence.
    This delivers verified private state, not copied shards or restored service.
    [Normal-provider shard restoration](stage-10-evidence.md#task-10--restoring-encrypted-shards-into-normal-storage)
    now reconstructs all selected slices once per stripe, durably writes them with
    normal reservations/receipts, and resumes partial batches. Real-folder proof
    reopens replacement stores and reads exact content without the salvage source,
    including two further target losses. Coordinator target selection, authoritative
    route installation and live recovery admission remain to be connected.
    [Replacement target preparation and collection](stage-10-evidence.md#task-10--replacement-target-preparation-and-collection)
    now prepare real capability-probed folders on selected nodes and collect their
    signed identities into isolated coordinator state. The real daemon proof
    preserves sibling files, retries exactly and rejects changed intent/reports;
    the consensus fence remains closed. These records are not active providers,
    restored shards or an admission barrier. Physical restoration must still use
    the selected targets and install authoritative routes before service admission.
    [Node-side physical restoration](stage-10-evidence.md#task-10--node-side-retained-shard-restoration)
    now traverses authenticated retained manifests and copies an original target's
    slices into its prepared replacement through normal durable providers. The
    real daemon proof runs with original media and target journals unavailable,
    verifies reopened encrypted bytes and reproduces identical signed receipts
    after output-report loss without duplicate shard records. This closes the
    node-side copying gap **8 → 7 points**, Stage 10 **86 → 85**. Coordinator
    validation/completeness, authoritative route installation, replacement
    membership and live service admission remain outstanding.
    [Coordinator restoration collection](stage-10-evidence.md#task-10--archive-matched-restoration-receipt-collection)
    now independently matches the complete signed receipt stream to retained
    archive layouts before storing it atomically. Real-command proof rejects a
    validly signed wrong operation and truncated stream, rolls back interrupted
    inserts and preserves exact replay after reopening. Original media remains
    unavailable. This closes collection/completeness **7 → 6 points**, Stage 10
    **85 → 84**; it does not install routes or activate replacement membership.
    [Replacement route preparation and delivery](stage-10-evidence.md#task-10--replacement-route-preparation-and-delivery)
    now project archive-matched receipts into an isolated catalogue and bind it into
    the existing encrypted/root-signed state package. Actual node installation
    exposes those exact candidate routes without clearing its consensus fence;
    corrupt stored receipts prevent export. The folder recovery proof uses the
    same projection and reads exact bytes after restart/two further target losses.
    Candidate route delivery closes **6 → 5 points**, Stage 10 **84 → 83**.
    The reserved activation revision is not committed yet: active provider/key
    installation, replacement membership/readiness and live service remain open.
    [Exact state-package installation collection](stage-10-evidence.md#task-10--exact-state-package-installation-collection)
    now records selected-node acknowledgements against independently expected
    signed transfers. Old/key-only acknowledgements cannot satisfy a newer package;
    the typed set check requires every selected node exactly once. Real-command
    proof covers substitution, signature checks, failed insert and exact replay,
    while retaining the consensus fence. This is an installation check, not
    present health or selection of one consistent final runtime view. The
    **5-point** estimate is unchanged pending the combined activation workflow.
    [Single-snapshot set export](stage-10-evidence.md#task-10--common-recovery-state-across-selected-nodes)
    now gives every selected node the same encrypted
    metadata/history and routes with node-specific key bundles. The installation
    check rejects mixed exports even when every individual signature is valid.
    [Canonical replacement node/key projection](stage-10-evidence.md#task-10--canonical-replacement-node-and-key-records)
    now installs normal node/host/role, wrapping-key, certificate and complete
    secret-recipient records into that common copy atomically, preserving retained
    ciphertext and withholding decryption envelopes from storage-only nodes.
    Real two-node installation checks those normal records and unchanged source
    coordinator heads. [Restored provider records with offline-root provenance](stage-10-evidence.md#task-10--restored-provider-records-with-offline-root-provenance)
    now reuse normal registration validation/persistence in the same transaction.
    Real export/install/reopen proof verifies target/marker/capacity binding with
    original storage unavailable, without impersonating an administrator or
    changing the coordinator. Original targets are retired only in the candidate.
    This closes provider-record projection **5 → 4 points**, Stage 10 **83 → 82**.
    [Recovered folder/journal attachment](stage-10-evidence.md#task-10--recovered-folder-and-journal-attachment)
    now persists node-local mount bindings and reuses original target journals.
    The real installer reopens and scrubs restored bytes, rejects missing journals
    without recreating them, and keeps consensus startup fenced. Normal folder
    discovery/listing includes recovered bindings and provider opening requires
    current applied authority. [Runtime layout and interrupted-installation fencing](stage-10-evidence.md#task-10--runtime-layout-and-interrupted-installation-fencing)
    now install normal metadata filenames, original node keys and local ceremony
    keys without creating a first-boot claim. A normal daemon start explicitly
    refuses pending recovery, including a partially installed directory.
    [Replacement consensus permission](stage-10-evidence.md#task-10--root-authorised-replacement-consensus-permission)
    now binds the exact common state to one durable offline-root decision after
    every selected installation is acknowledged. Missing receipts and competing
    state sets are rejected; retries preserve the decision. Issuance does not
    apply membership or clear either startup fence.
    [Replacement activation and gateway startup](stage-10-evidence.md#task-10--replacement-activation-and-gateway-startup)
    now consume the signed permission, apply membership/epoch/revision atomically,
    preserve applied history and resume interrupted local admission without a
    first-boot claim. The recovered gateway reaches configured HTTPS startup.
    The two-node process acceptance still fails on the storage-only node: daemon
    composition assumes a consensus member and gateway services. This requires
    a role-appropriate runtime, not granting storage-only nodes broader roles or
    gateway keys. Fresh readiness and recovered file access remain open; no
    passing two-node recovery claim is made.
    [Role-specific recovery keys](stage-10-evidence.md#task-10--role-specific-recovery-keys)
    now separate the provider's fresh permit-MAC key from gateway and historical
    keys. Storage-only nodes receive just that permit key; metadata-only nodes
    receive no secret envelopes. The signed role selection must exactly match
    both recipient sets. This corrects a separate provider-opening prerequisite,
    without adding consensus roles or completing storage-only startup.
    [Private network startup roles](stage-10-evidence.md#task-10--admitted-roles-in-private-network-startup)
    now reflect admitted services and actual quorum membership instead of always
    claiming gateway/voter roles. Non-member metadata synchronisation and the
    storage-only runtime remain open. An ordinary HTTPS upload/restart check had
    an unexplained `503 busy` before a passing diagnostic rerun; it is not a
    resolved reliability claim.
    [Non-voting metadata application](stage-10-evidence.md#task-10--non-voting-metadata-application)
    now applies bounded committed history with durable restart/replay and exact
    membership-phase changes, without constructing a voter or learner runtime.
    Live authority-owner reads and [authenticated bulk history transfer](stage-10-evidence.md#task-10--authenticated-bulk-metadata-history)
    are implemented, including real Quinn application/reopening tests and a daemon
    source dispatcher. The [owned passive worker](stage-10-evidence.md#task-10--automatic-non-voting-catch-up)
    now retries lost transfers, continues bounded pages, resumes durable state
    after restart and hands off on committed learner admission.
    [Initial storage-only daemon composition](stage-10-evidence.md#task-10--storage-only-startup-and-shard-service)
    now starts the recovered non-member process, forwards folder registration and
    serves capability-checked shard reads/writes without gateway keys. Live
    privileged-authority checks and destructive/maintenance RPCs remain open;
    health stays explicitly degraded. The subsequent real two-node recovery
    proof now restores the original file onto the storage-only node and reads it
    through the replacement gateway's HTTPS and embedded SMB services with the
    original credentials. It checks exact bytes before and after abrupt storage
    restart while original storage/journals are unavailable. This exposed and
    fixed the install/runtime journal-path mismatch and missing replacement-local
    branch projection. A real storage-certificate privilege-forgery regression
    also now rejects unrelated metadata commands and node/host/actor substitution.
    The full-file access milestone closes **task 10: 4 → 3; Stage 10: 82 → 81**.
    **Stage 11 remains 126/not started**. This is not healthy all-node readiness,
    unrestricted maintenance authority or assembled-stage completion.
    The [new-write recovery proof](stage-10-evidence.md#new-writes-after-replacement-recovery)
    additionally creates files through HTTPS and SMB with the original credential,
    reads them through both protocols, and preserves their exact bytes across
    abrupt storage and gateway restarts without uploading again. The original
    backed-up file remains readable; operational acceptance remains open and the
    estimate stays **3 points**.
    Both replacement services also explicitly reject the actual pre-recovery node
    certificate before and after restart, while admitted peers retain service.
    [Storage-only private renewal](stage-10-evidence.md#storage-only-private-certificate-renewal)
    now installs and acknowledges the committed candidate without CA keys or
    voter membership. The real recovery proof verifies generation 2 and exact
    HTTPS/SMB bytes through both restarts; cached control connections select the
    renewed leaf without cancelling in-flight callers. Remaining operational
    acceptance and the **3-point** estimate are unchanged.
    [Fresh metadata read fences](stage-10-evidence.md#fresh-authority-read-prerequisite)
    now work over private QUIC after leader changes and recovered-daemon restarts.
    [Storage-only cleanup admission](stage-10-evidence.md#storage-only-committed-cleanup-admission)
    now connects passive catch-up to exact frontier, identity, target and committed
    permit/completion checks before tombstone or reclamation IO. Focused tests
    pass. The **78.95-second** real HTTPS/SMB recovery proof also rejects a gateway's
    valid-MAC/no-commit deletion and preserves shard bytes across restarts;
    The [committed cleanup proof](stage-10-evidence.md#committed-cleanup-acceptance--in-progress)
    now also passes through real recovered daemons after adding a gateway. It
    preserves storage-only permit-key access, completes exact tombstone and
    reclamation RPCs, and recovers identical receipts after abrupt process loss
    before metadata completion and before reclamation accounting. Original/new
    HTTPS and SMB files remain readable. The expanded proof passed in **127.85 s**.
    Whole-candidate integration, backup reclamation and broader operational
    recovery acceptance remain open; this is not arbitrary power-loss coverage.
    Storage-only health remains degraded; the **3-point** estimate is unchanged.
    This is live identity fencing, not full returning-node recovery-authority
    lifecycle closure. The competing foreground/background publication digest
    mismatch exposed by new writes is corrected and has a deterministic regression.
    Remaining: end-to-end retained-backup reclamation and broader archive acceptance,
    all-node readiness, returning-node
    recovery-authority fencing, complete secret recoverability,
    complete role-specific operational admission, plus assembled-stage
    acceptance. Offline-command integration previously reduced this estimate
    **13 → 8 points**. Exercising a non-empty filesystem exposed missing automatic
    history archive coverage, so the remaining estimate is corrected to **13**
    (Stage 10 **86 → 91**); the surviving-donor path did not close that requirement.
    The subsequent archive-to-surviving-pack verification closes **3 points**:
    task 10 **13 → 10**, Stage 10 **91 → 88**. Verified commitment binding then
    closes **10 → 8**, Stage 10 **88 → 86**. Recovery admission remains open.

11. **Self-contained embedded web panels — Recorded complete.** **0 points remaining.**
    SYS-007, OPS-001/002. [Embedded panel evidence](stage-10-evidence.md#embedded-appliance-panels)
    covers real HTTPS delivery before claim and after join, built-asset equality,
    deep links and denied source/traversal requests without a runtime Node service.
    Dashboard completeness and platform/package acceptance are tasks 12 and 27.

12. **Plain-language operational dashboard and administration — Partial.** **8 points remaining.**
    OPS-001–009/013–016. Panels exist, but the complete operational acceptance
    needs reconciliation against the [accepted operations/metrics decisions](stage-6-11-decisions.md#8-metrics).
    Finish independent read/write/protection/capacity status, security/audit views,
    federation connection and storage-offer controls backed by the same APIs,
    resumable work and action-required states, honest change estimates and bounded
    incremental updates. Verify accessible, responsive, non-blocking behaviour
    through equivalent APIs and panels, including degraded/unknown states.

13. **Complete redacted diagnostic bundle — Implemented; stage-wide verification pending.** **1 point remaining.**
    OPS-011/020. [Metadata diagnostics](stage-10-evidence.md#native-metadata-diagnostics)
    and [runtime bundle/download](stage-10-evidence.md#runtime-diagnostic-bundle-and-download-control)
    have passing evidence. Reconcile all required versions, configuration,
    logs/events, topology, target health, quorum and work sections; close missing
    coverage and prove bounded collection, absent/stale evidence and secret/content
    exclusion. Collection must not start repair or depend on remote telemetry.
    The [completed projection implementation](stage-10-evidence.md#task-13--complete-diagnostic-projection-implementation)
    adds allow-listed operational configuration and bounded indexed pending work
    to the existing version/topology/health/quorum/event bundle. Focused Rust,
    SQLite, generated-client/download and actual two-daemon HTTPS checks pass;
    no source subjects, keys or raw configurations are serialised. Remaining
    effort is the assembled-stage acceptance pass, not further feature scaffolding.

14. **Bounded metrics foundation and authenticated exporter — Recorded complete.** **0 points remaining.**
    OPS-012/017/018/020. [Exporter integration](stage-10-evidence.md#replicated-opt-in-and-authenticated-exporter-integration)
    and the [catalogue](metrics.md) cover typed observations, fixed units/buckets,
    bounded encoding, opt-in policy, current authorisation, revocation and panel
    controls. Complete instrumentation and history are tasks 15–20; an exporter
    that works does not mean the catalogue is complete.

15. **Protection and locality measurements — Implemented; stage-wide verification pending.** **1 point remaining.**
    OPS-019. Instrument protection/locality debt and distinguish observations
    from authoritative protection/read availability. Close the corresponding
    [catalogue gap](metrics.md#remaining-stage-10-measurements) with exact fixtures
    and degraded/recovery process evidence, including unavailable/stale samples.
    [Recorded-layout observations](stage-10-evidence.md#task-15--protection-and-locality-observations)
    now assess bounded local catalogue pages using the placement component's
    fault and cell predicates. Exporter/history families distinguish receipt
    deficits, protection debt, locality debt, coverage, unknowns and observation
    age without claiming live byte availability. Stable identity cursors survive
    volume renames. The real upload/restart/folder-loss/reconnection/readback
    workflow passes in **10.24 seconds**. It also exposed and fixed startup
    incorrectly requiring every data mount to exist. Remaining work is the
    assembled-stage acceptance pass: **3 → 1 points**.

16. **Capacity, target IO and background-work measurements — Core collection implemented; attribution and stage-wide verification pending.** **1 point remaining.**
    OPS-019. [Target accounting and selected attempts](stage-10-evidence.md#target-accounting-and-selected-maintenance-measurements)
    now include mounted-filesystem space counted once per filesystem and durable
    queued/claimed/completed jobs, recorded debt and execution demand for all
    five maintenance kinds. The real two-daemon exporter/restart/node-loss flow
    passes in **10.93 seconds**. Target read/write/scrub calls, durations, payload
    bytes and corruption reports are now observed; real folder-corruption and
    daemon upload/restart/folder-loss/readback proofs pass. Durable progress now
    reuses replacement receipts, scrub/reconciliation checkpoints and effects,
    rebalance pages and safe-drain state. Missing remote-worker evidence remains
    explicit; checkpoints and effects are not double-counted. Finish underlying
    shared-pool attribution and assembled acceptance. Execution budgets are not bytes left to transfer; filesystem
    totals do not prove independent underlying pool
    capacity. [Evidence](stage-10-evidence.md#task-16--filesystem-space-and-durable-maintenance-jobs).
    [Target IO evidence](stage-10-evidence.md#task-16--target-io-and-integrity-observations).
    [Durable progress evidence](stage-10-evidence.md#task-16--durable-maintenance-progress).

17. **Gateway and data-path measurements — Partial; pack lifecycle and same-volume upload reuse implemented.** **16 points remaining.**
    OPS-019. [HTTPS/SMB dispatch](stage-10-evidence.md#https-and-smb-dispatch-measurements)
    is recorded. HTTPS/SMB transport bytes/errors and coding calls, failures,
    bytes, duration and missing-systematic-slice reconstruction are implemented.
    Exact real-socket counters and Reed–Solomon healthy/degraded/failure vectors
    pass; daemon upload/restart/folder-loss/readback metrics pass in **20.24 s**.
    Shared adapter outcomes now distinguish returned errors, verified read bytes,
    durable stage bytes and verified publication acknowledgements by scope.
    Exact upload/read/missing-file counters and restart reset pass in the real
    daemon flow (**20.41 s**). Pack database extent/reusable-page evidence now
    passes real guarded cleanup and the daemon lifecycle (**20.94 s**).
    The reopened prerequisites now stand as follows:

    - **8 points:** finish Stage 4 DAT-021 lifecycle acceptance and actual
      amplification/reclamation accounting. Journal-owned payload/record rollover,
      indexed routing and automatically retried CoW compaction are implemented;
      real local restart/cutover fixtures pass. Remaining: bounded operation-log
      growth, oversized legacy-pack treatment, complete metrics beyond 32 packs,
      concurrent-reader/fault and daemon-maintenance acceptance and measured IO cost.
    - **8 points:** finish Stage 5 D-058/accepted decisions §5 mesh-wide reuse.
      Independently uploaded same-volume files now reuse verified compatible
      encrypted layouts without additional provider payload, while keeping their
      file/version/creator identities and logical byte accounting. Remaining:
      remote-only layout discovery/import, automatic terminal reservation
      cancellation, assembled rights/quota/cleanup and federation acceptance,
      then actual physical-savings measurements. Exact operation/shard replay
      alone is not content deduplication.

    These include integration/acceptance, not two new optional features. The
    prior **2-point** estimate assumed both prerequisites existed; code inspection
    contradicted that assumption. Reopened work is counted here once, adding
    **24 points** to Stage 10 rather than silently declaring earlier stages done.
    [Rollover and CoW implementation](stage-4-evidence.md#journal-owned-pack-rollover)
    now closes a coherent provider behaviour slice: **26 → 21 points**, reducing
    Stage 10 **131 → 126**. This does not close task 17 or its deduplication scope.
    [Independent upload reuse](stage-5-evidence.md#independent-same-volume-uploads-now-reuse-compatible-layouts)
    subsequently closes its first working reuse slice: **21 → 16 points**,
    Stage 10 **126 → 121**. Remote-only discovery and the listed acceptance
    remain required; this is not a claim of complete mesh-wide deduplication.
    Dispatch completion and accepted transport bytes are not client delivery or
    durable file completion. [Evidence](stage-10-evidence.md#task-17--transport-and-coding-measurements).
    [Filesystem outcomes](stage-10-evidence.md#task-17--shared-filesystem-outcomes).
    [Pack evidence and reopened prerequisites](stage-10-evidence.md#task-17--pack-space-and-reopened-storage-prerequisites).

18. **Consensus and federation measurements — Partial.** **2 points remaining.**
    OPS-019. Close the [consensus/catch-up and federation backlog gaps](metrics.md#remaining-stage-10-measurements).
    Cover quorum/authority observations, catch-up and federation progress with
    bounded cardinality, age and unknown states. Collection must not add consensus
    writes, scan remote providers on scrape or become an admission authority.
    [Local reactor measurements](stage-10-evidence.md#task-18--local-consensus-measurements)
    now expose coherent role/term/positions, queue counts, persistence blocking,
    observation age and failures. Focused tests and a real two-gateway restart
    proof pass. This closes local instrumentation **5 → 3 points**.
    [Replica catch-up measurements](stage-10-evidence.md#task-18--replica-catch-up-measurements)
    now expose current-plan remote-member counts, local apply lag, unknown replica
    positions and the largest tracked committed-entry gap. Isolation/catch-up,
    step-down and real two-gateway exporter/restart tests pass: **3 → 2 points**.
    Recorded match positions do not establish fresh quorum or peer liveness.
    Current authority and federation progress remain open.

19. **Security, operational lifecycle, resource and clock measurements — Partial.** **3 points remaining.**
    OPS-019/020. Close remaining authentication-rejection, certificate, backup,
    update, runtime-resource and clock-uncertainty categories in the
    [catalogue](metrics.md#remaining-stage-10-measurements). Use existing owning
    components and fixed schemas; test exact outcomes, redaction and missing data.
    [Operational worker observations](stage-10-evidence.md#task-19--operational-worker-observations)
    now cover certificate automation/installation, backup and update preparation
    through the exporter and local history. Real daemon restart/folder-loss proof
    passes. These are worker-pass outcomes, not unique jobs, readiness or complete
    rollout success. [HTTPS access rejection measurements](stage-10-evidence.md#task-19--https-access-rejection-measurements)
    now distinguish 401/403 responses with exact real-endpoint counter proof;
    this does not cover SMB authentication, TLS admission or concealed 404s.
    Remaining: SMB authentication rejection, certificate expiry/delivery coverage,
    retained backup/update inventory, resources, clock uncertainty and assembled
    acceptance remain. This functional slice closes **8 → 6 points**.
    [SMB authentication rejection measurements](stage-10-evidence.md#task-19--smb-authentication-rejection-measurements)
    now count actual shared-credential rejection independently of unavailable
    authority or malformed packets. Real SMB 3.1.1 bad/valid login, exact exporter
    count and restart reset pass in **7.51 seconds**. The complete 214-family
    history passes Rust/OpenAPI/Zod checks. This closes **6 → 5 points**,
    Stage 10 **106 → 105**; the other categories above remain open.
    [Certificate and retained inventory measurements](stage-10-evidence.md#task-19--certificate-and-retained-inventory-measurements)
    now expose selected certificate expiry/delivery and paged backup/update state,
    preserving missing/stale evidence without IO on scrape. Real daemon public-API
    comparison and restart pass in **20.58 seconds**; the complete 242-family
    history and generated-client validation pass. This closes **5 → 3 points**,
    Stage 10 **105 → 103**. Runtime resources, clock uncertainty and assembled-stage
    acceptance remain; host-clock certificate classification is not clock agreement.

20. **Bounded local metric history — Implemented; stage-wide verification pending.** **1 point remaining.**
    OPS-018; accepted decisions §8. Implement the selected downsampled local panel
    history with explicit retention/resource bounds and gaps, rather than a
    distributed time-series database. [Process counters are not this history](metrics.md#remaining-stage-10-measurements).
    Prove long-window boundedness and panel access without loading every sample.
    [Local history implementation](stage-10-evidence.md#task-20--bounded-local-metric-history)
    provides six-hour minute and seven-day hourly windows, 30-sample pages,
    exact counter/histogram values, unknown samples and restart-bound cursors.
    The panel loads only on request. Simulated 14-day retention, focused API/UI
    checks and a real two-gateway restart proof pass. Remaining work is the
    assembled-stage pass: **5 → 1 points**.

21. **Durable notifications — Implemented; assembled-stage verification remains.** **1 point remaining.**
    OPS-010/020. Implement/verify optional email and authenticated generic webhooks
    from durable deduplicated events, with explicit configuration, allow-listing,
    redaction, retry and restart behaviour. Include manual-DNS renewal tasks from
    task 2. Delivery failure must not stop local healing or status reporting.
    [Replicated outbox evidence](stage-10-evidence.md#task-21--durable-notification-outbox)
    covers encrypted configuration references, real committed ACME source events,
    deduplication, fenced claims, retries, cancellation and file-backed restart.
    Bounded scheduling reads and real local authenticated HTTPS/SMTP transport
    tests also pass. The manager API, generated client, panel and owned daemon
    worker now connect configuration to real receiver delivery. A real daemon
    proves authenticated configuration, transient failure, restart, exact replay,
    credential retention and changed-retry rejection. Gateway recipient
    redistribution is wired. Remaining: exercise that redistribution through a
    newly joined delivery gateway, SMTP through the daemon and manual-DNS alert
    lifecycle. The API and panel now expose retained pending, accepted, rejected
    and cancelled totals, independent of local worker health.
    This integrated slice reduces the estimate **8 → 3 points**; it does not
    close the task or the assembled-stage acceptance pass.
    [Completed delivery integration](stage-10-evidence.md#tasks-221--complete-notification-transport-and-gateway-integration)
    now passes both real-daemon SMTP modes, new-gateway credential redistribution
    and delivery after source loss, and all four manual-DNS task notifications
    through restart and retry. This closes **3 → 1 points**, Stage 10
    **108 → 106**; only the assembled-stage pass remains for this task.

22. **Mesh-wide rolling updates — Partial; automatic interruption-allowed installation implemented; availability-preserving coordination remains.** **7 points remaining.**
    The Linux continuation now executes a verified static-PIE musl binary.
    Both PR #269 handoff regressions and the single-copy restart-refusal scenario
    passed together after measured artifact verification exposed an invalid
    generic control-wait budget. The final bounded-HTTP-poll review passes all
    three scenarios and musl Clippy; earlier peer-startup failures remain open
    reliability observations.
    Full supported-platform update and assembled-stage acceptance remain open.
    Accepted decisions §7, PER-003/006, TST-007. Provide one administrator-selected
    signed candidate, compatibility checks, availability-aware node ordering,
    durable progress and stop-on-failed-probe behaviour. Prove interrupted update
    recovery and voter/gateway availability; manual per-node replacement is not
    the normal path. Do not publish a candidate to test this without approval.
    [Local candidate admission](stage-10-evidence.md#tasks-2225--signed-local-candidate-admission)
    now verifies a separately pinned signature and exact executable in the daemon
    without opening mesh state. The [replicated journal](stage-10-evidence.md#task-22--replicated-rollout-journal-and-restart-admission)
    now stores independent signer trust, exact candidate selection, per-node
    progress, pause/resume/cancel and ambiguous restart ownership. Fresh root
    quorum/gateway admission uses the real stable/joint predicates.
    [Manager API and panel](stage-10-evidence.md#task-22--native-update-administration)
    now pin/revoke publisher trust, select signed manifests, show checkpoint counts
    and pause/resume/cancel with exact retries across daemon restart.
    [Executable upload](stage-10-evidence.md#task-22--verified-executable-upload)
    now streams signed bytes to a private fsynced cache and commits an exact
    node/incarnation source advertisement, through HTTPS, the SDK and panel.
    [Automatic peer distribution](stage-10-evidence.md#task-22--automatic-private-executable-distribution)
    now fetches each node's signed platform over authenticated QUIC, verifies the
    streamed bytes locally and publishes that node as a source. A real three-node
    lifecycle proves one upload fans out without per-node administration.
    [Runtime staging](stage-10-evidence.md#task-22--executable-compatibility-and-durable-staging)
    now executes the authenticated candidate's bounded read-only report, checks
    the signed build/API/platform and unchanged persistence/command formats,
    retains evidence and commits staged or failed/paused. Real daemon bytes pass
    on the current macOS target; dummy executable bytes pause without restarting.
    GNU development builds are not accepted as static-musl distribution binaries.
    The [private process probe](stage-10-evidence.md#task-22--authenticated-process-readiness-observations)
    now returns real reactor/format/listener observations with exact rollout,
    identity, quorum-plan and catch-up binding. A real enrolled peer exercises it
    across daemon restart and rejected stale barriers. This is not a restart grant.
    [Executable handoff](stage-10-evidence.md#task-22--durable-executable-handoff)
    now consumes an already committed restart reservation, retains an authenticated
    installation selection, self-execs after service shutdown, and verifies the
    new process through a committed checkpoint. The original launch command follows
    the retained installation before opening databases. The two-node fixture proves
    both replacements and cold-launch recovery, using prepared real cache bytes and
    typed private admission commands in its original proof.
    [Automatic interruption-allowed installation](stage-10-evidence.md#task-22--automatic-interruption-allowed-installation)
    now selects one staged node, commits fixed-barrier preparation and restart,
    verifies the replacement, and advances automatically to the next node. The
    real two-node test now uses no private admission commands. Status counts and
    rollout sequences share one database read view. The panel distinguishes this
    working interruption-allowed path from unfinished uninterrupted installation.
    Bounded concurrent peer-probe collection is wired into automatic admission;
    the reconnect/witness/replacement proof passes in **47.13 seconds**. All-scope workload/locality/delegated-group
    readiness and real rolling availability remain open. The estimate is unchanged
    because that remaining integration and proof is still a large work item.
    [Surviving encrypted-content checks](stage-10-evidence.md#task-22--surviving-encrypted-content-checks)
    now reconstruct verified ciphertext using only selected survivors, without
    keys or storage mutations. The availability inventory includes acknowledged
    stripes with pending optional replicas. These filesystem operations are
    tested; all-scope daemon admission and active-publication fencing remain open.
    The [incremental whole-volume verifier](stage-10-evidence.md#task-22--incremental-whole-volume-survivor-verification)
    now walks committed publications, verifies global and required-cell survivors,
    retains bounded progress between calls and invalidates it on catalogue changes.
    Real-provider failure/return, concurrent-publication and reopening checks pass.
    [Daemon-owned preparation](stage-10-evidence.md#task-22--daemon-owned-uninterrupted-preparation)
    now invokes that component from the owned update worker, excludes the selected
    node's targets, pages volumes and retains an explicitly non-authoritative
    local observation. Real single-copy preparation and two-node replacement/
    cold-launch tests pass together in **82.95 seconds**, after correcting the
    fixture's omission of durable installation selection from its progress model.
    This closes **13 → 12 points**, Stage 10 **112 → 111**.
    [Authenticated peer observations](stage-10-evidence.md#task-22--authenticated-local-content-observations)
    now carry exact-bound local scan progress over QUIC; the two-daemon exchange
    passes in **34.04 seconds**. This is not aggregate mesh-wide readiness.
    [Durable publication replay and historical gateway keys](stage-10-evidence.md#task-22--durable-publication-replay-and-historical-gateway-keys)
    now recover pre-enrolment writes after source restart and supply unchanged
    historical volume keys to a new gateway. The two-daemon exact-byte proof
    passes in **12.61 seconds**, including another restart of both daemons.
    This closes **12 → 11 points**, Stage 10 **111 → 110**. Divergent-head,
    retired-history and source-loss/transitive catch-up remain open alongside
    the existing workload coverage requirements below.
    [Merge-history transfer](stage-10-evidence.md#task-22--merge-history-transfer-and-continued-file-work)
    now carries reconciled roots through the existing paged receiver, survives
    restart and allows continued file work after adoption. It does not yet wire
    the daemon's automatic authoritative convergence coordinator; that and
    snapshot-restore history transfer remain required. The estimate is unchanged.
    [Automatic disconnected-write convergence](stage-10-evidence.md#task-22--automatic-disconnected-write-convergence)
    now retains divergent heads, resumes durable attempts, publishes through
    authoritative CAS and relays the selected merge automatically. The real
    two-daemon isolated-write/reconnect/restart proof passes in **31.35 seconds**,
    closing **11 → 9 points**, Stage 10 **110 → 108**. This supersedes the missing
    coordinator above, not the remaining restore/retired-history/source-loss
    or controlled strong-publication race acceptance.
    [Snapshot-restore history transfer](stage-10-evidence.md#task-22--snapshot-restore-history-transfer)
    now carries exact restore receipts and non-ancestor snapshot dependencies
    through bounded, restart-resumable history. Imported evidence does not activate
    a head; native receipt adoption checks restore ancestry against replicated
    metadata authority. Three focused restore-transfer tests pass in **2.37 s**;
    both real-daemon history/reconnect regressions pass in **31.44 s**. This closes
    the missing transfer capability **9 → 8 points**, Stage 10 **103 → 102**,
    not live user-facing snapshot/restore workflow or rolling availability proof.
    [Strong-publication completion](stage-10-evidence.md#task-22--strong-publication-completion-after-background-convergence)
    now recognises exact retained publication evidence when another metadata
    publisher wins or a later head advances. The controlled consensus-backed
    regression and real strong-upload/restart flow pass; no old head is republished.
    This closes that reproduced race **8 → 7 points**, Stage 10 **102 → 101**.
    Retired-history and transitive source-loss acceptance remain alongside the
    workload coverage below. This is not coverage of every possible concurrency
    schedule or a replacement for assembled-stage fault testing.
    All-scope discovery, namespace/policy/key/gateway coverage and
    the final handoff fence remain required; uninterrupted restart is still disabled.

23. **Migration and supported recovery acceptance — Partial.** **7 points remaining.**
    PER-003–007, TST-007. Verify real artefact transitions, transactional/restartable
    migration or pre-admission refusal, exact backup restoration and voter-local
    databases. Explicitly document unsupported pre-1.0 downgrade/rollback; do not
    invent a compatibility promise. Published-artefact evidence remains held by
    the publication prohibition, even if local candidate tests pass.
    [Supported-schema backup restoration](stage-10-evidence.md#task-23--supported-schema-backup-restoration)
    now verifies the original capture, migrates only a new copy and preserves its
    exact committed position/revision. Real schema-92 plaintext and encrypted
    fixtures restore to schema 93; altered migration history is rejected.
    This does not close task 10's recovery authority and service admission.

24. **Native and container packaging — Partial.** **8 points remaining.**
    REL-003/004, TST-009. Prepare self-contained Linux/macOS artefacts and the
    supported minimal container image, including built-in HTTPS/SMB and panels.
    Verify entry points, state/storage paths and dependency/licence inventory.
    The development daemon build and an SMB test-client image do not close this
    product packaging task. Local preparation only while publication is held.
    The Linux continuation prepared verified local musl compiler tooling. Actual
    linked standard-library/compiler-runtime notices must be included alongside
    Cargo/npm notices in the final dependency inventory; build/acceptance remains.
    [Local package assembly](stage-10-evidence.md#tasks-2427--local-native-package-and-packaged-process-execution)
    now builds an inspected macOS ARM64 dev archive with embedded panels,
    licence/inventory/provenance/checksums and passes a packaged setup/join/renewal/
    restart proof. Static Linux packaging and a minimal container recipe are
    implemented but not executed; musl tooling, other native targets and complete
    candidate acceptance remain outstanding. No publication command was added.
    The local command now requires source notices and a CycloneDX 1.6 SBOM,
    includes them in checksums and copies them into the image. The real dependency
    scan currently refuses packaging for missing `unicode-casefold@0.2.0` notice
    text; its upstream is archived. This dependency needs resolution, not a notice
    exception or invented attribution. See the [packaging evidence](stage-10-evidence.md#tasks-2425--package-sbom-and-upstream-notices).

25. **Local signed release/update tooling — Partial; publication held.** **3 points remaining.**
    REL-001/003/004; accepted decisions §7. Prepare complete local validation,
    packaging and update/release scripts, checksum/provenance/SBOM generation and
    clear one-way-migration notes. Keep publication explicitly gated and GitHub
    Actions absent. Review and safely test non-publishing paths; do not run the
    release/tag/publication path while the owner's hold remains.
    [Signed local candidate preparation](stage-10-evidence.md#tasks-2225--signed-local-candidate-admission)
    binds clean source/API provenance and exact native executables, with real
    Node-to-daemon verification. The SBOM/notice tooling is now integrated, but
    dependency notice clearance, candidate acceptance and
    remaining update workflow preparation are outstanding: **5 → 3 points**.

26. **Dependency/toolchain admission — Recorded complete.** **0 points remaining.**
    Accepted decisions §7, REL-004. [Admission evidence](stage-10-evidence.md#dependency-update-admission)
    records the full dependency-update command, Rust/JavaScript advisory checks,
    licence checks and complete local suite against an actual update. Each new
    candidate still needs fresh evidence; this is not perpetual advisory clearance
    or the independent security review required by Stage 11.

27. **Packaged-platform HTTPS/SMB acceptance — Partial; current-tree workflow corrections verified.** **6 points remaining.**
    The [Linux continuation](stage-10-evidence.md#tasks-1027--linux-directory-durability-prerequisite)
    fixed independently reproduced directory-fsync failures in folder and backup
    providers; all 72 affected provider tests pass. Corrected full Linux offline
    recovery passes in **139.28 s**, but a separate post-restart timeout remains
    unexplained. The local Linux SMB client now reaches loopback listeners;
    real successor IO, authentication metrics, three-gateway file work and
    offline HTTPS/SMB recovery pass. The six-process protection fixture instead
    has exposed setup readiness, strong-publication confirmation and delayed
    immutable-history transfer failures. The confirmation correction is under
    focused validation; the readiness and transfer evidence remains open. These
    development-binary results do not close packaged-platform acceptance.
    Stage 10 exit gate, TST-004/007/009, REL-003. Run complete real-client file
    cycles, backup/recovery and upgrade paths using the accepted native/container
    artefacts, including Linux-only, macOS-only and mixed-host meshes. Keep local
    candidate results separate from the still-held published-artefact gate.
    Ignored SMB-container tests and headless DOM checks are not this proof.
    The [packaged macOS process proof](stage-10-evidence.md#tasks-2427--local-native-package-and-packaged-process-execution)
    passes setup, embedded assets, join and private TLS renewal/restart. Broader
    tests exposed an isolated-backup-restore `409` and delayed cross-gateway SMB
    file propagation. The [current-tree corrections](stage-10-evidence.md#task-27--gateway-history-and-backup-recipient-workflows)
    now pass the unchanged three-gateway SMB cycle twice and the complete HTTPS
    operator cycle. Backup checks distinguish pre-enrolment recipient absence
    from invalid backup bytes, and prove post-enrolment restoration on both
    gateways. This closes two concrete workflow gaps **8 → 6 points**, Stage 10
    **114 → 112**. These are development-binary proofs, not the remaining native/
    container candidate matrix, physical failures or partition reconciliation.

## Stage 11 — minimal useful product proof

Status: **not started as a stage**. Earlier-stage tests are inputs, not completion
of these integrated gates. Each task must retain candidate/build identity,
commands, expected outcomes and reproducible results. Applies to all non-deferred
requirements; [accepted proof decisions](stage-6-11-decisions.md#9-release-proof-and-pre-10-scale-work)
extend the roadmap's high-level scenarios.

1. **Topology and scale matrix — Open.** **13 points remaining.**
   Prove useful one-node operation including multiple independent drives, two-node
   growth, real 1/2/3/6-machine topologies and 20 real nodes when available. Run at
   least 100 daemon/emulated nodes and deterministic 1,000/10,000-node workloads
   across single and federated swarms. Record hardware versus simulated evidence
   separately, plus declared fault policies. TST-003/005/009; accepted decisions §9.

2. **Two simultaneous machine failures — Open; hardware required.** **8 points remaining.**
   Use six real machines and verify exact surviving reads, acknowledged writes
   and automatic healing through two simultaneous machine losses. Exercise
   declared device/custom-fault combinations too; multiple processes on one host
   are not machine-failure evidence. TST-005/010; Stage 11 roadmap gate.

3. **Corruption, storage exhaustion and interrupted IO — Open.** **8 points remaining.**
   Inject real corruption/bitrot, read-only storage, full storage and partial
   writes, alongside process death and abrupt power-loss tests. Assert no corrupt
   bytes reported valid, lost acknowledged content or false protection; retain
   exact recovery evidence. TST-002/005/006.

4. **Physical churn and multi-way partitions — Open; hardware required in part.** **13 points remaining.**
   Repeatedly unplug/reconnect links, hosts and devices during foreground IO,
   flush, repair, scrub, drain, configuration rollout and rotation. Split at least
   five network components; prove authority fencing, durable authorised local
   writes and automatic rejoin/convergence without manual conflict selection.
   TST-003/006/010; accepted decisions §9.

5. **One-hour Home/Office isolation — Open.** **5 points remaining.**
   Two nodes lose their link for one hour, continue real HTTPS and SMB eventual
   writes on both sides through restarts, then reconnect. Independently retained
   receipts and expected versions must reconcile with no administrator and no
   lost admissible acknowledgement. Stage 11 roadmap gate.

6. **Campus/building isolation — Open.** **8 points remaining.**
   Disconnect one building's uplink while its complete-local scopes remain usable;
   verify declared local availability, disconnected writes, catch-up and replica
   healing after reconnection. Do not claim availability for data the building
   cannot decode. Stage 11 roadmap gate; locality/consistency requirements.

7. **Strong acknowledgement zones — Open.** **3 points remaining.**
   A strong operation waits for exactly its two selected required zones; eventual
   zones do not hold acknowledgement. Interrupt/restart participants and prove
   pending versus committed outcomes without weakening the policy. Stage 11
   roadmap gate; consistency requirements.

8. **Full real-client appliance workflows — Open.** **8 points remaining.**
   Exercise users, groups, permissions/revocation, volumes, files and failure
   recovery through real HTTPS/SMB clients. Assert shared create/write/flush/read/
   rename/delete behaviour, concurrent repair/scrub/drain and exact bytes on
   supported Linux/macOS/container and mixed-host deployments. Reuse Stage 10,
   task 27 evidence where it proves the same candidate/behaviour. TST-004/006/009.

9. **Federation and delegated authority — Open.** **13 points remaining.**
   Prove editable peers, hierarchical governance, opaque backups, multi-partner
   placement, disconnected/restarted edits, automatic convergence, revocation
   quarantine, identity rotation, downstream narrowing and relationship removal.
   Verify permanent root authority, manual delegated groups and operation/key-range
   routing without dual writers. Automatic splitting belongs to Stage 12, not
   this task. FED requirements and accepted decisions §9.

10. **Candidate backup, restore, upgrade and recovery — Open.** **8 points remaining.**
    Run every documented supported path against the candidate artefacts with
    exact committed-position, membership and secret checks, including interruption.
    Reuse verified Stage 10 tasks 6–10/22/23 evidence without silently omitting
    candidate integration. Actual published-artefact acceptance remains held.
    PER-003–007, TST-007.

11. **Candidate certificate lifecycle — Open.** **5 points remaining.**
    Integrate both ACME challenges, renewal, key delivery and worker/gateway loss
    with live service and churn. Reuse task-level Stage 10 proofs, but verify the
    integrated candidate and internal/public rotation separation. PKI-001–010,
    TST-008/010.

12. **Performance and heterogeneous-drive acceptance — Open.** **13 points remaining.**
    Measure Raspberry Pi-class and server-class throughput, tail latency, repair,
    recovery, reconciliation, memory and concurrency against the accepted targets.
    Include small/large files, unequal drives, normal/degraded/repair workloads and
    scale variation. Declare methodology and any targets still awaiting a locked
    baseline; never invent benchmark results. TST-008; accepted decisions §9.

13. **Seven-day active candidate soak — Open; elapsed time/hardware required.** **8 points remaining.**
    Use a restart-safe controller, reproducible fault schedule/seed, out-of-band
    expected hashes/receipts and signed result manifest across repair, renewal and
    churn. Accelerated-time, real-process and controlled hardware evidence are
    complementary. A 30-day observation run is non-blocking, not a replacement.
    TST-011; accepted decisions §9.

14. **Independent security review and unresolved reliability findings — Open.** **8 points remaining.**
    Obtain the required independent threat/operation-boundary review; retain fuzz
    corpora and fresh advisory/licence evidence; close every critical/high finding.
    Investigate the unexplained TLS close and backup timing/transport observations
    retained in [Stage 10 evidence](stage-10-evidence.md). A passing retry is not
    their explanation. A paid penetration test is preferred, not an invented
    prerequisite or a substitute for the required independent review.

15. **Final requirement reconciliation and publication decision — Open; publication held.** **5 points remaining.**
    Map every non-deferred requirement to candidate evidence and resolve all
    release blockers: lost acknowledgements, accepted corrupt bytes, unauthorised
    access/deletion, dual writers, false success, manual ordinary reconciliation
    or failed documented metadata recovery. Validate native/container artefacts,
    checksums, provenance and `GPL-2.0-only` metadata. Do not create a signed tag or
    publish anything before explicit owner approval; report a prepared candidate
    and held publication separately. REL-001/003/004; accepted decisions §9.

## Stage 12 — automatic metadata-group scaling

Status: **not started**; depends on Stage 11 measurement evidence. Required after
0.1.0 and before 1.0, not a 0.1.0 blocker. Existing delegation contracts are the
foundation, not proof that automatic splitting is implemented.

1. **Capacity-normalised group measurements — Open.** **8 points remaining.**
   Measure load, headroom and migration cost per authoritative group using the
   Stage 11 baselines. Distinguish Raspberry Pi-class and server-class capacity;
   do not trigger splitting on node count or a universal operations threshold.
   SCL-013/014, DEF-005.

2. **Automatic group creation and direct delegation — Open.** **13 points remaining.**
   Create eligible groups and route exact operation families/key ranges directly
   with epoch fencing and bounded lookup/cache invalidation. Root authority over
   identity, enrolment, federation and the delegation directory remains intact.
   SCL-010/013/014, DEF-005.

3. **Online split, merge and rebalance — Open.** **13 points remaining.**
   Implement prepare/copy/fence/activate/retire transitions with restartable work
   and one authoritative writer. Keep filesystem/API semantics unchanged and
   preserve routability during handoff. SCL-010/013/014, DEF-005.

4. **Automatic voter placement and stable decisions — Open.** **8 points remaining.**
   Place eligible caught-up voters against shared-failure groups. Use measured
   migration cost, locality, resource class and hysteresis to avoid oscillation
   and preserve quorum safety. SCL-013/014, DEF-005.

5. **Interrupted-transition and performance proof — Open.** **13 points remaining.**
   Interrupt every prepare, copy, fence, activation and retirement boundary in
   deterministic and process tests; reject dual writers and unroutable scopes.
   Demonstrate a measured bottleneck improvement and safe reversal when load
   changes on both small-machine and server-class groups, without changing
   ordinary API semantics or root-owned authority. SCL-010/013/014, DEF-005.
