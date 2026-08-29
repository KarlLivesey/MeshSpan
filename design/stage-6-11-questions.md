# Stage 6–11 design questions

Status: **open for review**.

These are the remaining product decisions for Stages 6–11. Decisions already
locked in the requirements, protocol, federation contract and Stage 4–5 design
are deliberately not repeated. Each question includes why the answer matters
and a recommended starting position.

Answers may reference the question identifiers, for example `6.1 yes`,
`7.3 amend`, or `10.1 option B`.

## Stage 6 — HTTPS appliance and panels

### 6.1 How should an unclaimed daemon expose first-time setup?

**Why:** Exposing cluster creation publicly before an administrator exists creates
a takeover risk, but setup must remain headless and simple.

**Recommendation:** Bind first-time administration to loopback by default and
generate a short-lived, single-use bootstrap code. The same code works through
the browser, CLI or public API. Remote bootstrap requires an explicit bind or
configuration option.

### 6.2 Which authentication combinations must work in `0.1.0`?

**Why:** The model supports passwords, passkeys, TOTP, recovery codes, API tokens
and client certificates, but the release acceptance gate must be explicit.

**Recommendation:** Require password with optional or required TOTP, passwordless
passkeys, one-time recovery codes, scoped API tokens and client certificates for
headless automation. Authentication policy may require an exact factor count or
factor class.

### 6.3 Should the user and administrator panels be one application?

**Why:** Separate applications duplicate authentication, navigation and
deployment, while one undifferentiated interface would confuse ordinary users.

**Recommendation:** Use one web application with a normal file interface and a
clearly separated, permission-gated Administration area. Users without the
required rights never receive or see administrative controls.

### 6.4 How should federated content appear in the user interface?

**Why:** Users need to understand availability and ownership without confronting
federation logs, branches or trust chains.

**Recommendation:** Show shared remote content in the ordinary file hierarchy.
A small origin indicator and status view show the owning swarm and whether the
operation is durable locally, accepted by the owner and satisfying its protection
policy. Disconnection and quarantine remain explicit.

### 6.5 Should federation administration use the same sharing flow as local sharing?

**Why:** A separate federation administration model would undermine the appliance
experience.

**Recommendation:** Yes. Connect a swarm, select a file, folder or volume, then
choose `view`, `edit` or `manage`; alternatively offer capacity and choose whether
it serves ordinary reads. Quotas, offline validity, resharing and placement
restrictions belong under Advanced.

### 6.6 How should anonymous and unlisted shares be presented?

**Why:** Public-anonymous, unlisted and authenticated sharing have materially
different security properties.

**Recommendation:** Present three explicit choices: public with no secret,
unlisted with an unguessable URL, and restricted with normal authentication.
Each may target either the live object or an exact pinned version.

## Stage 7 — embedded SMB

### 7.1 Which SMB dialects must `0.1.0` support?

**Why:** Supporting the entire SMB surface immediately would slow and weaken the
implementation; supporting too little harms interoperability.

**Recommendation:** Support SMB 3.1.1 and SMB 3.0.2 only. Reject SMB1. Defer
compression, SMB Direct, clustering extensions, POSIX extensions and legacy
browsing protocols.

### 7.2 What should the default SMB signing and encryption policy be?

**Why:** Requiring encryption everywhere can reduce interoperability or
performance, while accepting unsigned sessions is unsafe.

**Recommendation:** Always require signing. Support encryption and require it for
untrusted networks and confidential shares. Allow trusted-LAN encryption to be
configurable. Never permit anonymous unsigned mutation.

### 7.3 Must SMB clients transparently survive a gateway process failure?

**Why:** Full SMB clustered continuous availability, witness support and invisible
handle migration substantially expand Stage 7.

**Recommendation:** Preserve durable staged-write and handle state so a client can
reconnect safely through any gateway, but do not promise completely invisible
clustered failover in `0.1.0`. No acknowledged bytes may be lost, and ambiguous
operations resolve through their operation identity.

### 7.4 May SMB clients edit MeshSpan permissions directly?

**Why:** Full Windows security-descriptor editing is a large compatibility surface
that does not map cleanly to nested groups, activation and time-bounded grants.

**Recommendation:** Initially expose accurate effective permissions over SMB but
perform authoritative permission administration through the public API and panel.
A deliberately mapped SMB ACL mutation profile can follow later.

### 7.5 How should SMB discovery work?

**Why:** Explicit hostnames are reliable but less appliance-like; legacy NetBIOS
discovery adds complexity and attack surface.

**Recommendation:** Explicit DNS or IP access always works. Offer local-network
mDNS/DNS-SD advertisement where supported. Do not implement NetBIOS or SMB1
browsing.

### 7.6 How should federated users reach shared data over SMB?

**Why:** Their credentials must not be copied to the owning swarm.

**Recommendation:** A user authenticates to a gateway in their home swarm. That
gateway evaluates the local identity and federated authority, then accesses the
shared namespace as a qualified remote principal. Passwords, factors and raw
sessions never cross the federation link.

## Stage 8 — protection and erasure coding

### 8.1 Which ordinary failure-policy presets should the UI offer?

**Why:** Users should express the failure they need to survive, not select coding
geometry or individual shard locations.

**Recommendation:** Offer `Single node — no redundancy`, `Survive one drive
failure`, `Survive one machine failure`, `Survive two machine failures` and
`Custom protection`. Custom protection supports simultaneous promises such as
two machines or three backing devices, including overlapping fault groups.

### 8.2 What initial chunk-size and coding bounds should be accepted?

**Why:** Small chunks increase metadata and request overhead; large chunks increase
random-write, repair and memory costs.

**Recommendation:** Use benchmark-selected power-of-two chunk profiles, aiming for
roughly 1,024 logical chunks per file, with hard bounded streaming. Select `k+m`
automatically. Keep exact sizes and the maximum geometry open until the Stage 8
benchmark harness supplies evidence.

### 8.3 What happens when a requested protection policy is not currently achievable?

**Why:** One- and two-node growth states must remain useful without falsely
reporting protected data.

**Recommendation:** Retain the policy as desired state, use the strongest currently
valid layout, report exact protection debt and upgrade online when resources
arrive. An explicit strong write waits or fails by its deadline; ordinary eventual
writes continue with an honest receipt.

### 8.4 When may another swarm count as an independent failure location?

**Why:** Two autonomous swarms might still occupy the same building, power circuit
or upstream network.

**Recommendation:** Never infer independence from swarm identity alone. Remote
capacity carries declared location and fault-group evidence. Uncertain overlap
reduces its protection contribution, although it may still store replicas.

### 8.5 Can a strong acknowledgement policy require another swarm?

**Why:** Some deployments may require data to reach a remote office or backup
partner before success is reported.

**Recommendation:** Yes, only when explicitly configured. A remote location marked
`required_before_commit` must return its exact durable receipt. An `eventual`
partner never blocks acknowledgement.

### 8.6 Should deduplication cross autonomous swarm boundaries?

**Why:** Global cross-organisation deduplication creates content-existence,
key-management, accounting and deletion problems.

**Recommendation:** Do not perform implicit cross-swarm deduplication. Reuse is
allowed only for an explicitly shared object or layout under the same owning
authority and a compatible encryption and protection contract.

### 8.7 Who controls the protection policy for federated content?

**Why:** The owner, consuming swarm and storage provider can each have legitimate
restrictions.

**Recommendation:** The owning swarm defines minimum durability and canonical
policy. Every participant may impose stricter local ceilings or refuse placement,
but cannot weaken the owner's promise. Effective placement is the intersection
of all applicable contracts.

## Stage 9 — healing, scrub, rebalance and drain

### 9.1 When should a failing storage target be automatically quarantined?

**Why:** Continuing to use a target producing corruption or partial writes can
spread damage; reacting to one transient error may create needless churn.

**Recommendation:** Stop destructive operations immediately after an integrity
violation. Use a bounded error score for transient IO faults, then quarantine at
the threshold. Heal elsewhere automatically. Re-admission requires capability
and integrity probes to pass.

### 9.2 How should scrub frequency be configured?

**Why:** A fixed calendar interval ignores media type, data age, redundancy and
observed errors.

**Recommendation:** Use continuous risk-based scheduling with a configurable
maximum verification age. Prioritise under-protected, old, error-prone and
recently returned data. Scheduled and manual scrub update the same observations.

### 9.3 How much foreground performance may repair consume?

**Why:** Repair must restore safety quickly without making the appliance unusable.

**Recommendation:** Adapt to latency, throughput and protection risk. Imminent
loss of recoverability may consume most available resources; routine rebalance
yields aggressively to client IO. Advanced users may set ceilings, not schedule
individual shards.

### 9.4 Should a returning node's old shards be trusted immediately?

**Why:** A node may have missed deletion, policy, key or placement changes while
absent.

**Recommendation:** Its journal may make independently verified immutable shards
available for bounded reads, but reappearance is not authority. Reconcile
inventory, generation, capabilities and placement before writes or retirement.

### 9.5 Who coordinates repair involving federated storage?

**Why:** Either swarm acting without exact authority could exceed quota, leak data
or delete the wrong shard.

**Recommendation:** The owning swarm authorises desired placement and lifecycle.
Eligible workers transfer encrypted shards directly using short-lived
capabilities. Each side enforces its restrictions and signs receipts; metadata
leaders never proxy bulk bytes.

### 9.6 What should happen during extreme repeated node flapping?

**Why:** Immediate repair after every disconnect wastes bandwidth, but excessive
debounce can destroy recoverability.

**Recommendation:** Use risk-based hysteresis: repair immediately with no remaining
recovery margin, briefly debounce a safe degraded layout, use a longer debounce
with excess redundancy, and increase suspicion after repeated flaps so repair
cannot be postponed indefinitely.

## Stage 10 — certificates, packaging and operations

### 10.1 Which DNS-01 providers must be built in for `0.1.0`?

**Why:** DNS-01 cannot be universally automated without a DNS provider, and manual
renewal is not appliance-like.

**Recommendation:** Define a small provider interface and initially ship RFC 2136,
Cloudflare and a documented external webhook provider. Manual DNS-01 may exist
for testing or emergency use but is not automatic renewal.

### 10.2 How should HTTP-01 work when several gateways serve the same address?

**Why:** The ACME server may reach any gateway even though one fenced worker owns
the order.

**Recommendation:** One fenced worker performs the order while bounded challenge
material is securely distributed to every eligible gateway. Any gateway can
answer the exact token; only the worker contacts the CA or finalises the order.

### 10.3 What should happen for local-only installations without public DNS?

**Why:** ACME may be impossible, but HTTPS must remain usable without silently
becoming insecure.

**Recommendation:** Create a mesh-local CA and issue gateway certificates
automatically. Provide an explicit downloadable trust bundle and installation
guidance. Never fall back to plaintext HTTP or globally disable verification.

### 10.4 Which release artefacts are mandatory?

**Why:** Linux and macOS support still leaves architecture and libc requirements
ambiguous.

**Recommendation:** Publish native Linux x86-64 and ARM64, native macOS Apple
Silicon and Intel, and OCI images for linux/amd64 and linux/arm64. Provide WSL and
container guidance for Windows. Decide glibc versus additional musl artefacts from
compatibility evidence.

### 10.5 When should GitHub automation be re-enabled?

**Why:** Local-only testing accelerates current work, but signed reproducible
multi-platform releases and dependency automation eventually need controlled
remote builders.

**Recommendation:** Keep pull-request CI disabled during early implementation.
At Stage 10, add tag-triggered release workflows and narrowly parallel dependency
validation. A signed `vX.Y.Z` tag triggers production only after the complete
local release gate.

### 10.6 How should automatic dependency and toolchain updates work?

**Why:** Dependabot covers Cargo and npm dependencies but does not completely
manage toolchain pins or compatibility decisions.

**Recommendation:** Use Dependabot for Cargo, npm, container bases and Actions,
plus a separate scheduled updater for stable Rust and the supported Node and
TypeScript versions. Auto-merge compatible patch and minor updates only after
all gates. Major or licence-changing updates require review.

### 10.7 What rollback guarantee should pre-`1.0` releases provide?

**Why:** Some SQLite migrations may be irreversible, while pretending arbitrary
downgrade works would be dangerous.

**Recommendation:** Take and verify an exact metadata backup before upgrade.
Support direct rollback only while the old schema remains readable; otherwise
restore the pre-upgrade backup through the documented recovery flow. Pre-`1.0`
does not promise arbitrary downgrade compatibility.

### 10.8 Must public HTTPS certificates and federation identities remain separate?

**Why:** ACME certificates identify DNS names and expire frequently; federation
trust identifies an autonomous swarm and must survive public certificate changes.

**Recommendation:** Yes. ACME covers user-facing HTTPS only. Federation uses its
recovery-root-chained rotating identity. HTTPS renewal must never revoke a
federation relationship or alter swarm identity.

## Stage 11 — `0.1.0` proof

### 11.1 What physical hardware matrix blocks release?

**Why:** Simulation finds state-machine faults, but not filesystem, controller,
power-loss or real-network behaviour.

**Recommendation:** Require one- and two-node growth states, six physical machines
surviving two simultaneous machine failures, low-power ARM and x86-64 server
classes, heterogeneous storage, Linux-only, macOS-only, mixed Linux/macOS and OCI
deployments. Make a 20-Raspberry-Pi churn rack a named physical target when the
hardware is available rather than replacing it with process-only simulation.

### 11.2 What scale levels require real, emulated and deterministic proof?

**Why:** Physically testing 10,000 nodes is unrealistic, but the architecture must
not contain accidental scale ceilings.

**Recommendation:** Test 1, 2, 3, 6 and ideally 20 real nodes; at least 100
multi-process or emulated nodes; and deterministic model/protocol loads at 1,000
and 10,000 nodes. Include many smaller federated swarms as well as one large
swarm. Passing means bounded work and no ordinary global scans.

### 11.3 Which federation scenarios block `0.1.0`?

**Why:** Later stages must expose and operate federation, not merely retain its
internal data model.

**Recommendation:** Require horizontal editable sharing, head-office governance
over at least three shop swarms, storage-only opaque backups, placement across
several partners, one-hour disconnected edits, deterministic reconnection,
retroactive revocation quarantine, identity rotation and relationship removal.
Federated peers must never become local voters or principals implicitly.

### 11.4 What initial performance floors block release?

**Why:** Fast is not testable without numbers, but arbitrary numbers chosen before
measurement may target the wrong hardware.

**Recommendation:** Benchmark first, then lock separate low-power and server floors
for HTTPS and SMB throughput, small-file operations, p50/p95/p99 metadata latency,
degraded reads, repair impact, leader recovery, node-return reconciliation,
memory per connection and concurrent-client scaling.

### 11.5 How long must soak testing run?

**Why:** Renewal, slow leaks, queue starvation and repeated churn often escape
short tests.

**Recommendation:** Require a seven-day active release-blocking soak with client
IO, repair, link interruption, restart and certificate activity. Also run a
longer non-blocking 30-day observation soak when release cadence permits.

### 11.6 What constitutes a release-blocking integrity failure?

**Why:** The acceptance bar must be explicit before testing begins.

**Recommendation:** Apply zero tolerance to lost acknowledged versions, corrupted
bytes returned as valid, unauthorised access, concurrent authoritative control
writers, false success, unauthorised cleanup, manual conflict selection for
ordinary admissible writes, or failure of documented metadata recovery.

### 11.7 Must release prove automatic recovery from multi-way partitions?

**Why:** A majority/minority split does not cover several isolated cells or swarms
changing data independently.

**Recommendation:** Yes. Test at least five network components split several ways.
Control mutations proceed only with their authority quorum, while authorised
availability-first branches continue locally. Reconnection must retain and
automatically converge every admissible acknowledged version.

### 11.8 Is automatic metadata-Raft splitting required for `0.1.0`?

**Why:** The system must preserve this scale boundary, but automatic group creation
adds substantial complexity.

**Recommendation:** No. `0.1.0` proves permanent root and delegated-authority
boundaries plus manually constructed delegated groups without dual writers.
Automatic load-triggered split, merge and rebalancing remains a future
optimisation, while scale tests prove current interfaces do not prevent it.
