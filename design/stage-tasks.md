# Remaining stage tasks

This is the task/status index for Stages 10–12. Each stage has its own numbered
list. Refer to work as **Stage 10, task 1**, for example. Keep numbers stable:
append new tasks rather than renumbering existing ones, and explain scope changes.
The [roadmap](roadmap.md) defines stage order; [requirements](requirements.md) and
[accepted decisions](stage-6-11-decisions.md) define acceptance, not this inventory.

Status baseline: 2026-09-06, after merge `f27acad`. This is a reconciliation of
recorded evidence and implementation entry points, not a new test run or a full
code audit. **Recorded complete** means the stated task has linked implementation
and passing evidence, not that every later-stage proof has passed. **Partial**
means work exists but the stated acceptance remains open. **Open** means completion
has not been established; it does not assert that no supporting code exists.

Update the relevant task when work changes its status. Report the current task,
what behaviour changed, what remains and what was tested. Do not replace this
with “nearly done”, a count of commits or an unweighted completion percentage.

Remaining-effort estimate, 2026-09-06: **Stage 10: 141 points; Stage 11: 126
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

2. **Automatic ACME and DNS challenge handling — Partial; current task.** **2 points remaining.**
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
   process-recovery cases passed in parallel in **336.74 seconds**. Valid retry
   guidance on malformed successful-response bodies still needs a separate
   correction; this does not close the remaining task-2 scope or reduce its estimate.

3. **Encrypted certificate delivery and rotation — Partial.** **5 points remaining.**
   PKI-001/002/005/007/010; accepted decisions §7.
   [Gateway installation](../crates/meshspan-daemon/src/public_certificate_installation.rs)
   and [rotation](../crates/meshspan-daemon/src/public_certificate_rotation.rs) exist.
   Record end-to-end recipient-bound envelopes, installation acknowledgements,
   same-generation gateway activation, restart/failover and make-before-break.
   Include internal node/federation rotation independently of public CA schedules;
   identity private keys must remain node-local.

4. **External automated certificate publisher — Partial.** **5 points remaining.**
   PKI-009. [API tests](../crates/meshspan-daemon/src/external_certificate_publisher_api_tests.rs)
   and [request contracts](../crates/meshspan-certificates/src/external_request.rs)
   exist. Close with a scoped external caller's complete publish/install/activate
   cycle, rejected names/chains/keys/lifetimes/generations and interrupted rollover.
   No manual-upload UI or private-key disclosure.

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

7. **Backup providers, federation destinations and failure overlap — Partial.** **13 points remaining.**
   PER-004/005, OPS-003/007; accepted decisions §7. Local target failure
   assessments and local/remote-node provider ownership are recorded in
   [backup evidence](stage-10-evidence.md#current-local-backup-failure-assessments).
   Implement/verify external provider and other-swarm destinations, authenticated
   transfer and current remote failure relationships. Unknown overlap must stay
   unknown rather than counting as independent protection.

8. **Backup history, encrypted export and restore-readiness API/panel — Recorded complete.** **0 points remaining.**
   OPS-001, PER-004/005. Evidence:
   [history](stage-10-evidence.md#native-backup-history-and-panel),
   [export](stage-10-evidence.md#native-encrypted-backup-export) and
   [restore checks](stage-10-evidence.md#gateway-restore-check-api-and-panel).
   This means bounded history, verified encrypted download and non-destructive
   checks, not offline decryption, live restore or catastrophe recovery.

9. **Interrupted backup publication and abandoned-object retirement — Partial.** **8 points remaining.**
   PER-004/005, TST-002/007. [Empty unpublished reservations recover](stage-10-evidence.md#recovery-of-empty-unpublished-backup-reservations).
   Finish authoritative recovery/retirement of published-but-unindexed or
   otherwise unadmitted generations, including lost retained admission evidence.
   Prove restart/exact-retry behaviour, durable accounting and no deletion based
   solely on a pathname, expired lease or missing catalogue entry.

10. **Offline verification and disaster recovery — Partial.** **13 points remaining.**
    PER-004/005/007, TST-007. Recovery-bundle foundations and task 8 exist;
    [product-facing recovery remains outstanding](stage-10-evidence.md#remaining-backup-integration).
    Complete the documented offline verification and recovery-authority workflow,
    exact-position restoration, membership/secret checks and safe service
    admission. Restore-readiness must not masquerade as a completed restore.

11. **Self-contained embedded web panels — Recorded complete.** **0 points remaining.**
    SYS-007, OPS-001/002. [Embedded panel evidence](stage-10-evidence.md#embedded-appliance-panels)
    covers real HTTPS delivery before claim and after join, built-asset equality,
    deep links and denied source/traversal requests without a runtime Node service.
    Dashboard completeness and platform/package acceptance are tasks 12 and 27.

12. **Plain-language operational dashboard and administration — Partial.** **8 points remaining.**
    OPS-001–009/013–016. Panels exist, but the complete operational acceptance
    needs reconciliation against the [accepted operations/metrics decisions](stage-6-11-decisions.md#8-metrics).
    Finish independent read/write/protection/capacity status, security/audit views,
    resumable work and action-required states, honest change estimates and bounded
    incremental updates. Verify accessible, responsive, non-blocking behaviour
    through equivalent APIs and panels, including degraded/unknown states.

13. **Complete redacted diagnostic bundle — Partial.** **3 points remaining.**
    OPS-011/020. [Metadata diagnostics](stage-10-evidence.md#native-metadata-diagnostics)
    and [runtime bundle/download](stage-10-evidence.md#runtime-diagnostic-bundle-and-download-control)
    have passing evidence. Reconcile all required versions, configuration,
    logs/events, topology, target health, quorum and work sections; close missing
    coverage and prove bounded collection, absent/stale evidence and secret/content
    exclusion. Collection must not start repair or depend on remote telemetry.

14. **Bounded metrics foundation and authenticated exporter — Recorded complete.** **0 points remaining.**
    OPS-012/017/018/020. [Exporter integration](stage-10-evidence.md#replicated-opt-in-and-authenticated-exporter-integration)
    and the [catalogue](metrics.md) cover typed observations, fixed units/buckets,
    bounded encoding, opt-in policy, current authorisation, revocation and panel
    controls. Complete instrumentation and history are tasks 15–20; an exporter
    that works does not mean the catalogue is complete.

15. **Protection and locality measurements — Open.** **3 points remaining.**
    OPS-019. Instrument protection/locality debt and distinguish observations
    from authoritative protection/read availability. Close the corresponding
    [catalogue gap](metrics.md#remaining-stage-10-measurements) with exact fixtures
    and degraded/recovery process evidence, including unavailable/stale samples.

16. **Capacity, target IO and background-work measurements — Partial.** **5 points remaining.**
    OPS-019. [Target accounting and selected attempts](stage-10-evidence.md#target-accounting-and-selected-maintenance-measurements)
    are implemented and tested. Finish physical-space attribution without
    double-counting shared filesystems, target IO/integrity measurements and
    durable queue/debt/progress/completion coverage for repair, scrub, drain,
    rebalance and reconciliation. Attempts and payload accounting are not job
    completion or physical free space.

17. **Gateway and data-path measurements — Partial.** **5 points remaining.**
    OPS-019. [HTTPS/SMB dispatch](stage-10-evidence.md#https-and-smb-dispatch-measurements)
    is recorded. Add transfer throughput and actual operation outcomes, coding
    and degraded reads, pack amplification/compaction and deduplication savings.
    Verify exact units and interrupted/degraded cases; dispatch completion is
    not delivery or durable file completion.

18. **Consensus and federation measurements — Open.** **5 points remaining.**
    OPS-019. Close the [consensus/catch-up and federation backlog gaps](metrics.md#remaining-stage-10-measurements).
    Cover quorum/authority observations, catch-up and federation progress with
    bounded cardinality, age and unknown states. Collection must not add consensus
    writes, scan remote providers on scrape or become an admission authority.

19. **Security, operational lifecycle, resource and clock measurements — Open.** **8 points remaining.**
    OPS-019/020. Close remaining authentication-rejection, certificate, backup,
    update, runtime-resource and clock-uncertainty categories in the
    [catalogue](metrics.md#remaining-stage-10-measurements). Use existing owning
    components and fixed schemas; test exact outcomes, redaction and missing data.

20. **Bounded local metric history — Open.** **5 points remaining.**
    OPS-018; accepted decisions §8. Implement the selected downsampled local panel
    history with explicit retention/resource bounds and gaps, rather than a
    distributed time-series database. [Process counters are not this history](metrics.md#remaining-stage-10-measurements).
    Prove long-window boundedness and panel access without loading every sample.

21. **Durable notifications — Open.** **8 points remaining.**
    OPS-010/020. Implement/verify optional email and authenticated generic webhooks
    from durable deduplicated events, with explicit configuration, allow-listing,
    redaction, retry and restart behaviour. Include manual-DNS renewal tasks from
    task 2. Delivery failure must not stop local healing or status reporting.

22. **Mesh-wide rolling updates — Open.** **13 points remaining.**
    Accepted decisions §7, PER-003/006, TST-007. Provide one administrator-selected
    signed candidate, compatibility checks, availability-aware node ordering,
    durable progress and stop-on-failed-probe behaviour. Prove interrupted update
    recovery and voter/gateway availability; manual per-node replacement is not
    the normal path. Do not publish a candidate to test this without approval.

23. **Migration and supported recovery acceptance — Open.** **8 points remaining.**
    PER-003–007, TST-007. Verify real artefact transitions, transactional/restartable
    migration or pre-admission refusal, exact backup restoration and voter-local
    databases. Explicitly document unsupported pre-1.0 downgrade/rollback; do not
    invent a compatibility promise. Published-artefact evidence remains held by
    the publication prohibition, even if local candidate tests pass.

24. **Native and container packaging — Open.** **8 points remaining.**
    REL-003/004, TST-009. Prepare self-contained Linux/macOS artefacts and the
    supported minimal container image, including built-in HTTPS/SMB and panels.
    Verify entry points, state/storage paths and dependency/licence inventory.
    The development daemon build and an SMB test-client image do not close this
    product packaging task. Local preparation only while publication is held.

25. **Local signed release/update tooling — Open; publication held.** **5 points remaining.**
    REL-001/003/004; accepted decisions §7. Prepare complete local validation,
    packaging and update/release scripts, checksum/provenance/SBOM generation and
    clear one-way-migration notes. Keep publication explicitly gated and GitHub
    Actions absent. Review and safely test non-publishing paths; do not run the
    release/tag/publication path while the owner's hold remains.

26. **Dependency/toolchain admission — Recorded complete.** **0 points remaining.**
    Accepted decisions §7, REL-004. [Admission evidence](stage-10-evidence.md#dependency-update-admission)
    records the full dependency-update command, Rust/JavaScript advisory checks,
    licence checks and complete local suite against an actual update. Each new
    candidate still needs fresh evidence; this is not perpetual advisory clearance
    or the independent security review required by Stage 11.

27. **Packaged-platform HTTPS/SMB acceptance — Open.** **8 points remaining.**
    Stage 10 exit gate, TST-004/007/009, REL-003. Run complete real-client file
    cycles, backup/recovery and upgrade paths using the accepted native/container
    artefacts, including Linux-only, macOS-only and mixed-host meshes. Keep local
    candidate results separate from the still-held published-artefact gate.
    Ignored SMB-container tests and headless DOM checks are not this proof.

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
