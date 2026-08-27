# Stage 0 decision review

Status: recommendations for review; no implementation is authorised by this
document.

This packet converts the remaining broad questions into seven decisions that can
be accepted, amended or deferred to a named roadmap gate. Defaults minimise the
operator surface; advanced options do not create alternate product paths.

## Decision summary

| ID | Recommendation | Needed before |
| --- | --- | --- |
| O-001 | Build a small MeshSpan-owned consensus core around mechanically proved flexible quorum plans; use established systems as references and differential oracles | Stage 3 |
| O-002 | Offer plain failure presets; keep arbitrary simultaneous fault scenarios in Advanced | Stage 6 UI, Stage 8 enforcement |
| O-003 | Implement a bounded SMB 3.1.1/3.0.2 profile over TCP 445; never SMB1 | Stage 7 |
| O-004 | Use fixed CoW logical extents with benchmark-selected size/layout profiles; no content-defined chunking initially | Stage 8 |
| O-005 | Use envelope encryption, offline recovery/root material and rotatable online intermediates | Stage 3 identity skeleton; Stage 10 full recovery |
| O-006 | Adopt the measurable MUP gates below on low-power and server reference classes | Stage 1 harness; Stage 11 release |
| O-007 | Ship native Linux/macOS and multi-architecture OCI artefacts for x86-64 and ARM64 | Stage 10 |

## O-001 — consensus implementation

### Recommendation

Implement a deliberately small MeshSpan-owned, leader-based replicated-log core
behind the versioned consensus interface. Its quorum plan has independent
election, consensus-write and linearizable-read predicates and supports nested
topology thresholds. Compile every plan to minimal quorum sets and mechanically
prove the required intersections before it can be committed.

This replaces the earlier OpenRaft recommendation. Stock OpenRaft currently
implements majority-of-each-set joint membership while listing flexible quorum
and separate read/write quorums as unfinished roadmap work. `raft-rs` exposes a
smaller core but has the same conventional quorum assumption, so MeshSpan would
still own invasive election, commitment, read and reconfiguration changes.

Use both as references rather than dependencies: OpenRaft for extended
membership, storage rules, simulation and known failures; `raft-rs` for a small
deterministic core/driver split. Flexible Paxos, FlexiRaft and ZooKeeper provide
the quorum constructions. [`consensus.md`](consensus.md) defines the complete
responsibility and safety boundary.

### Acceptance gate

Before Stage 3 depends on it, the consensus core must pass:

- executable formal-model invariants for election uniqueness, leader
  completeness, state-machine safety and linearizable read barriers;
- exhaustive compilation and intersection proof for all active and transitional
  plans through nine voters;
- deterministic simulations for every voter count from one through nine,
  including every multi-way split;
- crash/power-loss injection at vote, append, flush, truncate, purge, apply,
  snapshot build/install and membership transitions;
- learner catch-up and quorum-plan changes without admitting a lagging voter
  into the active quorum;
- stale leader, wrong-node-at-address and node-ID-reuse rejection over Quinn;
- linearizable, exact-revision and explicitly stale read vectors;
- differential majority-plan traces against established Raft implementations;
  and
- an on-disk migration fixture for every consensus format change.

Failure blocks the consensus core from becoming authoritative; it does not
weaken the gates or cause live topology to redefine a quorum.

Primary references:

- [OpenRaft production checklist](https://github.com/databendlabs/openraft/blob/main/openraft/src/docs/getting_started/getting-started.md)
- [OpenRaft roadmap](https://github.com/databendlabs/openraft)
- [`raft-rs` design boundary](https://github.com/tikv/raft-rs)
- [Flexible Paxos](https://doi.org/10.4230/LIPIcs.OPODIS.2016.25)
- [FlexiRaft](https://www.vldb.org/cidrdb/papers/2023/p83-yadav.pdf)
- [ZooKeeper hierarchical quorums](https://zookeeper.apache.org/doc/current/zookeeperHierarchicalQuorums.html)

## O-002 — failure-policy user experience

Protection and acknowledgement remain two separate questions.

### Ordinary protection choices

```text
Storage machines that may fail:  [0 | 1 | 2 | Custom]
Backing devices that may fail:   [0 | 1 | 2 | 3 | Custom]

Current result:
  Survive any 2 storage-machine failures OR any 3 backing-device failures
```

The recommendation reflects current independent hosts and storage devices. A
one-node mesh selects honest zero values and recommends adding another box; it
does not display an impossible promise. The ordinary two counters are separate
alternative scenarios. Requiring machine and device failures simultaneously is
an explicit Advanced scenario because it can need substantially more recovery
slices.

Advanced protection edits named scenarios such as:

```text
any 2 machines
any 3 backing devices
any 1 room plus any 1 power supply
any 2 machines plus any 3 additional backing devices
```

The UI previews whether the current topology can prove each scenario and the
approximate capacity cost. Users never choose `k`, `m` or shard locations.

### Ordinary save choices

```text
Keep working during outages (recommended)
Wait for protected storage
Wait for selected places
```

“Wait for selected places” displays named zones with a simple Required toggle.
Only selected zones hold the strong barrier. Locality for every other zone is
either eventual or absent according to its separate locality policy. Raw
predicates and advanced `excluded` placement remain under Advanced/API.

## O-003 — first SMB profile

### Dialects and transport

- Offer SMB 3.1.1 and SMB 3.0.2 over direct TCP on port 445.
- Prefer 3.1.1 and implement its mandatory pre-authentication integrity.
- Never offer SMB1, NetBIOS transport, SMB 2.0.2 or SMB 2.1.
- SMB over QUIC, RDMA/Direct and multichannel are later measured extensions, not
  hidden MUP dependencies.

### Security

- Signing is required by default for every session.
- Per-export encryption is supported; new exports default to required. Relaxing
  encryption is an explicit audited advanced setting with a clear network-risk
  warning.
- Initial self-contained authentication is SPNEGO/NTLMv2 using a separately
  revocable high-entropy SMB credential. Its required verifier is encrypted,
  never used for web/API login and rotatable from a strongly authenticated web
  session.
- Guest and anonymous access are absent.
- Kerberos/Active Directory integration is deferred behind the authentication
  contract, not emulated partially.

### Required command/semantic surface

- negotiate, session setup/logoff and tree connect/disconnect;
- create/open with dispositions, share modes and delete-on-close;
- read, write, flush, close, query/set file and filesystem information;
- directory enumeration, create, rename/move and delete;
- byte-range locks, leases/oplock breaks and durable-handle reconnect;
- change notifications needed by ordinary file browsers;
- bounded named streams and attributes through the common filesystem model;
- multi-credit bounded IO and compound requests where clients use them; and
- protocol-correct status mapping, cancellation and lost-response handling.

Continuously available shares/persistent handles, DFS, server-side copy,
compression, witness, POSIX extensions and clustering extensions are deferred
unless real-client tests prove one is required for the basic profile.

The gate is observable behaviour with real clients and Microsoft's published
protocol vectors, not the presence of packet parser code. Every command passes
hostile length/state fuzzing and the common filesystem conformance suite.

Primary references:

- [SMB dialect and capability negotiation](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-smb2/fac3655a-7eb5-4337-b0ab-244bbcd014e8)
- [SMB security and pre-authentication integrity](https://learn.microsoft.com/en-us/windows-server/storage/file-server/smb-security)

## O-004 — chunks and erasure profiles

Use fixed logical extents inside immutable file versions. CoW replaces only
affected extents; manifests may reference unchanged extents across versions.
Do not use content-defined chunking initially: it adds CPU, rolling-hash and
adversarial-boundary complexity without helping bounded random writes enough to
justify it.

The on-disk/wire format records explicit byte sizes and geometry; it never
hard-codes one global default. Stage 8 benchmarks these starting candidates:

| Workload candidate | Logical extent/stripe size | Purpose |
| --- | ---: | --- |
| Small/random | 1 MiB | bound read-modify-write amplification |
| General | 4 MiB | default balance for ordinary files |
| Large sequential | 16 MiB | reduce manifest and per-stripe overhead |

Candidate systematic Reed–Solomon geometries use `1 <= k <= 16`,
`0 <= m <= 8` and at most 24 slices per generation. These are implementation
review bounds, not user choices. A topology may use replication/`k=1` for small
meshes and data shapes where erasure coding is wasteful.

Before locking defaults, benchmark complete-file and random-write amplification,
memory per active stripe, encode/decode throughput, repair fan-in, small-file
packing, manifest depth and heterogeneous slow-target tails on both reference
hardware classes. The selected profile table becomes versioned metadata;
existing versions never change meaning when defaults improve.

## O-005 — mesh keys, backup and recovery

### Key hierarchy

At bootstrap:

1. The first node creates a mesh recovery wrapping key pair and an offline mesh
   root CA locally.
2. The public recovery key and root certificate become committed mesh identity.
3. The private recovery/root material is written only to an encrypted recovery
   bundle and removed from online state after verification.
4. A rotatable online intermediate CA and secret-wrapping generation are created
   for normal enrolment and encryption.
5. Every authorised node has separate signing and X25519 wrapping key pairs;
   private keys remain in its daemon state directory.

Each secret uses a random data-encryption key. Metadata stores the ciphertext and
separate key envelopes for exact eligible node public keys plus the recovery
public key. ACME certificate/private-key generations use this same envelope
mechanism, so every eligible gateway receives the same certificate without a
plaintext broadcast.

### Recovery bundle experience

Mesh creation requires one explicit “Save recovery bundle” step before adding
more nodes. The downloaded file is encrypted by a random high-entropy recovery
code displayed once; the interface asks the administrator to store the file and
code separately and verifies a short recovery challenge. There is no vendor
cloud escrow or back door.

Losing all online authority without this material is honestly unrecoverable.
Routine node replacement never needs it.

### Rotation and catastrophic restore

- Rotation creates a new generation, re-envelopes keys to current eligible
  nodes, waits for required installation acknowledgements and only then retires
  the old generation after retention.
- Metadata backups include ciphertext, public identity, envelopes and exact
  generation history, never unencrypted private material.
- Catastrophic restore requires the recovery bundle, its code, a verified
  committed metadata backup and target inventories.
- Restore creates a new authority epoch, new online intermediate and node
  envelopes; all old sessions, capabilities, join grants and node certificates
  are fenced.

Threshold cryptography and external HSM/KMS integration are later replaceable
key-provider implementations. They are not dependencies for a self-contained
MUP.

## O-006 — MUP performance and scale gates

Measure two documented reference classes:

- **Low-power:** Raspberry Pi 5 class, 8 GiB RAM, USB 3 SSD and 1 GbE.
- **Server:** 8 modern CPU cores, 32 GiB RAM, NVMe and 10 GbE.

Proposed release gates after warm-up and excluding an explicitly reported client
network limit:

| Behaviour | Low-power gate | Server gate |
| --- | ---: | ---: |
| Healthy large sequential HTTPS/SMB | >= 70% of measured direct-path ceiling and >= 80 MiB/s | >= 70% of direct-path ceiling and >= 700 MiB/s |
| One-node eventual metadata operation p95 | <= 25 ms | <= 10 ms |
| Three-voter LAN metadata operation p95 | <= 100 ms | <= 50 ms |
| Control-leader loss to new converged-control availability p95 | <= 5 s | <= 3 s |
| Foreground p95 under repair | <= 2x healthy p95 | <= 2x healthy p95 |
| Idle authenticated connections without swapping | >= 1,000 | >= 10,000 |

Additional gates:

- real-process tests at 1, 2, 3, 6 and 20 nodes;
- deterministic simulation through at least 100 nodes and five simultaneous
  network components;
- at least 1,000,000 namespace objects with bounded indexed request paths;
- repair uses at least 70% of deliberately available background bandwidth while
  honouring foreground latency and repair reserve;
- reconnect starts branch exchange within five seconds of stable reachability
  and makes monotonic progress without quadratic all-node broadcast;
- no unexplained memory, descriptor, task, branch-log or queue growth in the
  long-duration churn gate; and
- the local fast-suite/CI budgets in `verification.md` remain release gates.

These are minimum MUP proofs, not architectural ceilings. Every result records
hardware, filesystem, topology, protection geometry, encryption and exact
client so regressions cannot hide behind incomparable runs.

## O-007 — first release platforms

Mandatory release artefacts:

| Platform | Artefact |
| --- | --- |
| Linux x86-64 | self-contained archive and service definition |
| Linux ARM64 | self-contained archive and service definition, including Raspberry Pi class |
| macOS Apple Silicon | signed/notarised installer package and archive |
| macOS Intel | signed/notarised installer package and archive |
| OCI Linux amd64/arm64 | one multi-architecture image and immutable digest |

Native packages install the same daemon and embedded web assets. They may
configure a system service and permission to bind HTTPS/SMB ports, but do not
install a proxy, Samba, FUSE, database server or language runtime.

The container documents explicit state/storage mounts, UDP private transport and
HTTPS/SMB port mappings. It must run the same end-to-end acceptance cycle; it is
not a separate reduced product. Images run without a writable root filesystem
outside declared state/storage and without broad host-device access.

Native Windows remains deferred; WSL/container usage is documented without
being labelled native support. Release signing/notarisation credentials remain
CI secrets and never enter repository or mesh metadata.

## Review outcome

For each item, record one of:

```text
accepted as written
accepted with named amendment
deferred to the stated gate with no dependent implementation
rejected; replace with named direction
```

Accepted text moves into `decisions.md`. Rejected/deferred items remain visible;
they are not silently replaced by an implementation convenience.
