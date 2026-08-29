# MeshSpan requirements

Status: **draft for review**.

## Product contract

- **SYS-001** MeshSpan MUST combine registered storage folders across one or more nodes into one
  shared filesystem namespace.
- **SYS-002** The same implementation and record model MUST operate from one node to many nodes.
- **SYS-003** MeshSpan MUST automate ordinary placement, reconstruction, healing, rebalancing,
  certificate handling and membership work.
- **SYS-004** MeshSpan MUST NOT fabricate durability, authority or success. Availability-first file
  writes MAY commit to a local CoW branch with explicitly recorded local durability while wider
  authority or protection is unavailable.
- **SYS-005** Routine use MUST NOT require administrators to select erasure geometry, shard
  locations, metadata leaders or conflicting internal versions.
- **SYS-006** All externally supplied data MUST be treated as hostile and validated before use.
- **SYS-007** The normal deployment MUST be one self-contained daemon plus its compiled web assets;
  it MUST NOT require Kubernetes, an external database, proxy, message queue, Samba or FUSE.
- **SYS-008** The daemon, including storage, HTTPS and SMB gateway capabilities, MUST run natively on
  supported Linux and macOS hosts and in the supported container image; nodes in one mesh MAY mix
  supported operating systems and architectures.
- **SYS-009** In healthy operation MeshSpan MUST behave as a storage appliance: users interact with
  files and folders, while placement, coding, consensus, reconciliation and healing remain
  automatic implementation details.
- **SYS-010** Every message and record MUST be treated as hostile input regardless of whether it
  came from an authenticated client, enrolled node, voter, local database, provider folder or the
  same process. Authentication proves an identity, not truth, freshness, authority or safety.

## Appliance simplicity

- **SIM-001** Normal deployment MUST use one self-contained daemon per node; users MUST NOT install
  or coordinate separate storage, metadata, voter, repair, web or SMB processes.
- **SIM-002** First useful operation MUST require only creating or joining a mesh, registering one or
  more folders and creating the intended users/exports. It MUST NOT require storage pools,
  placement groups, shard maps, coding profiles or manual service placement.
- **SIM-003** Role eligibility, voter tiers, placement, coding, repair priority, rebalance and
  reconciliation MUST have safe automatic defaults and MUST NOT require routine operator choices.
- **SIM-004** Advanced diagnostics MAY expose internal evidence, but normal setup/status MUST lead
  with files, people, safety, places, current impact and automatic action.
- **SIM-005** A new user-visible distributed-system concept MUST be introduced only when MeshSpan
  cannot safely derive the decision and no existing intent-level control can express it.
- **SIM-006** Web, public API, CLI flags and headless flows MUST invoke the same domain operations;
  none may create a second configuration or recovery authority.
- **SIM-007** Ordinary churn MUST NOT require recovery commands. Any manual action request MUST name
  a missing physical resource, user intent or security decision with a stable diagnostic reason.
- **SIM-008** Ordinary federation setup MUST present resource sharing as selecting a volume, folder
  or file, selecting another swarm and choosing `view`, `edit` or `manage`; storage sharing MUST
  ask only for capacity and whether it may serve ordinary reads. Detailed rights and placement
  controls MUST remain optional advanced settings.
- **SIM-009** Federation internals including trust chains, delegation leases, remote branches,
  cryptographic keys, receipts and reconciliation MUST be automatic and MUST NOT become routine
  user or administrator choices.

## Hosts, nodes and membership

- **CLU-001** A host MUST represent a physical machine failure domain independently of daemon
  process identity.
- **CLU-002** A node MUST represent one enrolled daemon identity and MAY share a host with other
  nodes without manufacturing an additional host failure domain.
- **CLU-003** A one-node mesh MUST be useful and MUST report that it lacks node redundancy.
- **CLU-004** A running mesh MUST support online enrolment and growth without conversion from a
  standalone format.
- **CLU-005** A joining node MUST generate its private identity keys locally; private identity keys
  MUST NOT leave that node.
- **CLU-006** Join grants MUST be administrator-issued, expiring, use-limited and bound to one mesh.
- **CLU-007** UI, API and headless enrolment MUST execute the same authoritative transaction.
- **CLU-008** A node MUST support headless startup with a daemon state directory, storage paths and
  join material.
- **CLU-009** Metadata voter membership MUST remain independent of unbounded storage membership.
- **CLU-010** For each metadata partition, only a leader elected under its committed quorum plan
  and still able to satisfy its consensus-write quorum may advance the converged
  authoritative head. A component without that authority MAY acknowledge a causally scoped local
  filesystem branch commit but MUST NOT present it as globally converged.
- **CLU-011** A stale node or process incarnation MUST be fenced from publishing state after
  replacement.
- **CLU-012** Eligible storage nodes SHOULD be promotable to replace unavailable voters through
  surviving authority after full learner catch-up and a safe quorum-plan transition.
- **CLU-013** Discovery MAY advertise non-sensitive enrolment endpoints over local IPv4 and IPv6,
  but manual endpoint entry MUST remain available and identity MUST NOT depend on an IP address.
- **CLU-014** Possession of a valid administrator-issued join grant MUST be sufficient to perform
  its bounded pre-authorised enrolment without a second interactive approval step.
- **CLU-015** Node availability profiles and role restrictions MUST prevent unsuitable intermittent
  nodes from being selected as voters while allowing deliberately registered storage to leave and
  return safely.
- **CLU-016** Repeated cable unplug/replug, link flapping, address change, multi-way partition,
  process restart and host power loss MUST be treated as normal recoverable events rather than
  requiring manual membership repair.
- **CLU-017** While a valid partition authority, its required consensus-write quorum and the
  required verified shards remain reachable, public
  services MUST continue within the declared protection policy despite physical churn.
- **CLU-018** When authority or sufficient data is physically unavailable, surviving daemons MUST
  remain diagnosable, MUST NOT acknowledge unsafe work and MUST resume eligible service
  automatically after authority/data return and reconciliation.
- **CLU-019** Voter placement and count MUST grow automatically across independent eligible hosts.
  Plans MUST support every voter count from one through nine, normally prefer stable odd tiers and
  use even counts where a proved flexible plan improves the declared topology. Exact availability
  limitations MUST be reported.
- **CLU-020** Adding independent eligible nodes MUST NOT introduce a new mandatory single gateway,
  storage node or control endpoint. Authority, access and repair work SHOULD become more resilient
  and distributable as the mesh grows.
- **CLU-021** One mesh MUST support multiple metadata partitions and availability cells so loss of
  connectivity to one building, site or network region does not stop unrelated partitions that
  retain valid authority, their consensus-write quorum and required data.
- **CLU-022** Every authoritative record MUST belong to exactly one metadata partition at a time;
  only that partition's committed log may mutate it.
- **CLU-023** Every new swarm MUST begin with one root control metadata partition and one Raft
  group owning all authoritative scopes. That root group MUST remain the ultimate authority for
  swarm identity, node enrolment, federation trust and the partition-delegation directory after
  other groups are created.
- **CLU-024** Gateways MUST cache a signed, revisioned partition-routing table and contact the
  partition owning an operation directly; ordinary local-partition IO MUST NOT require a live
  campus-wide catalogue transaction.
- **CLU-025** A cell-local leader with valid authority and its consensus-write quorum MAY advance
  the converged head for its owned scope while disconnected from the wider mesh. Any cell/node
  with valid isolation authorisation and storage MAY advance an independent local branch, and
  reconnection MUST reconcile every branch without allowing one to overwrite acknowledged history.
- **CLU-026** Campus-wide identity/configuration authority MAY become temporarily unavailable during
  a partition while cell-owned filesystem work continues from an explicitly bounded committed
  identity/configuration revision.
- **CLU-027** Moving a scope between metadata partitions MUST be an explicit fenced copy-on-write
  handoff that gives mutation authority to at most one partition throughout the transition.
- **CLU-028** Every metadata partition MUST have separately defined election, consensus-write and
  linearizable-read quorum families; a majority quorum is one valid plan rather than a fixed rule.
- **CLU-029** Quorum predicates MUST support nested topology thresholds and weights sufficient to
  express hierarchical quorums over stable voter identities.
- **CLU-030** Every election quorum MUST intersect every other election quorum and every
  consensus-write quorum. Every linearizable-read quorum MUST intersect every election quorum.
- **CLU-031** A quorum-plan compiler MUST enumerate or otherwise exactly prove all required
  intersections, minimal cut sets and declared failure-survival properties before activation.
- **CLU-032** Active quorum meaning MUST be immutable within a committed membership epoch and MUST
  NOT be recomputed from current reachability, latency, free space or a failure detector.
- **CLU-033** A voter or quorum-plan change MUST use a committed safe transition that proves the
  necessary old/new cross-intersections and admits no unsynchronised voter.
- **CLU-034** Ordinary administration MUST express desired failure survival and locality rather
  than election, read or write quorum arithmetic; MeshSpan MUST compile and explain the plan.
- **CLU-035** The root control partition MUST be able to delegate an exact operation family and
  scope/key range to another Raft group through a revisioned, epoch-fenced ownership transition.
  After activation, ordinary operations in that scope MUST route directly to the delegated group
  and MUST NOT append through the root group.
- **CLU-036** A delegated Raft group MAY own identity, authentication, namespace, configuration,
  audit or other metadata families and MAY later be subdivided without changing public identities.
  No split may activate unless enough eligible swarm members and resources exist for its proved
  quorum plan; insufficient membership or load MUST leave the scope on its current safe group.

## Federation between autonomous swarms

- **FED-001** Independently administered swarms MUST be able to federate without joining voter
  sets, metadata partitions, user databases, encryption roots or consensus authorities.
- **FED-002** Federation MUST support horizontal peer relationships, hierarchical governance and
  deployments combining both forms.
- **FED-003** A subordinate swarm MUST have at most one immediate governing parent. Governance
  relationships MAY have multiple levels but MUST be acyclic. Horizontal data and storage
  relationships MAY be bidirectional or cyclic.
- **FED-004** A governing swarm MAY impose mandatory limits and policy ceilings. A subordinate
  MUST be able to commit ordinary decisions locally without upstream confirmation when they remain
  inside its durable delegation, but MUST NOT expand delegated authority.
- **FED-005** Every side of a federation relationship MAY impose restrictions. Effective authority,
  capacity and operation limits MUST be the intersection of the owning swarm's grant, every
  governing ceiling, the consuming swarm's local policy and the acting principal's active rights.
- **FED-006** Connecting swarms MUST require explicit administrator approval on both sides using
  short-lived, bounded connection material and verified swarm identities.
- **FED-007** Every swarm and remote principal MUST have a globally qualified identity. A remote
  user MUST authenticate with its home swarm; raw credentials, factors and sessions MUST NOT be
  copied into another swarm.
- **FED-008** Federation grants MUST target a volume, folder subtree, individual file or bounded
  storage capacity and MUST express explicit view, edit, manage and manage-sharing rights over the
  applicable resource kind.
- **FED-009** The ordinary UI MUST lead with the `view`, `edit` and `manage` presets. Resharing MUST
  require an explicit manage-sharing right, and advanced rights MUST NOT silently broaden a preset.
- **FED-010** Every shared volume, folder or file MUST retain exactly one owning swarm responsible
  for its ACL policy and canonical converged history, independently of data placement and the swarm
  that accepted an offline edit.
- **FED-011** An edit grant MUST allow authorised users from another swarm to create and modify data.
  A disconnected swarm with a valid signed offline delegation MUST be able to commit a durable
  local branch without synchronous confirmation from the owner or a governing swarm.
- **FED-012** Federated multi-writer reconciliation MUST authenticate provenance, validate the exact
  identity and delegation history, exchange bounded missing causal pages and referenced immutable
  records, and deterministically preserve every admissible acknowledged version.
- **FED-013** Federated write outcomes MUST distinguish durability on the accepting swarm,
  acceptance into the owning swarm's canonical history and satisfaction of the requested federated
  protection/availability policy.
- **FED-014** Federation grants MUST have an explicit offline-validity policy. Connected swarms
  SHOULD renew automatically; ordinary setup MUST supply a safe default while advanced controls
  MAY choose shorter, longer or indefinite offline access.
- **FED-015** Known revocation MUST stop access immediately. Work accepted while disconnected under
  an apparently valid grant but proven inadmissible after reconciliation MUST remain absent from
  the shared namespace and MUST be retained as bounded, audited quarantine until authorised
  recovery or expiry; it MUST NOT be silently published or destroyed.
- **FED-016** Remote capacity MUST be selectable by placement policy as one or more independent
  swarm locations. Placement MUST choose eligible partners automatically and MAY spread a required
  count across a larger partner set.
- **FED-017** Each remote-storage relationship MUST state whether its verified shards count towards
  protection and whether it may serve ordinary reads. Protection-only capacity MUST NOT be reported
  as immediate availability.
- **FED-018** Storage-only swarms MUST receive only encrypted shards, integrity metadata and bounded
  lifecycle capabilities. They MUST NOT receive volume decryption keys, filenames or user metadata.
- **FED-019** Readable federation sharing MAY deliver scoped, revocable decryption material only to
  authorised gateways. Storage donation MUST remain independent of readable data sharing.
- **FED-020** Every remote shard put, get, scrub, repair, retirement and reclamation MUST use an
  exact bounded capability and signed replay-safe receipt. Location, a relationship or mTLS identity
  alone MUST NOT authorise data access or deletion.
- **FED-021** Bilateral capacity and policy restrictions MUST be enforced at admission and placement.
  If one side offers 100 GB and the other permits 50 GB, no operation may rely on more than 50 GB.
- **FED-022** Loss of contact MUST NOT authorise ownership takeover. Recovery of a permanently lost
  owning swarm MUST require either its offline recovery material or an explicitly pre-authorised
  successor and MUST create a signed, audited transition that fences the former authority.
- **FED-023** Moving shared data outside its granted scope MUST require authority over both source
  and destination scopes and MUST NOT implicitly expand federation access.
- **FED-024** Relationship removal MUST revoke known access but MUST NOT claim remote bytes erased.
  Encrypted replicas MUST follow the agreed retention and receipt-backed cleanup lifecycle.
- **FED-025** Federation records, messages, signatures, delegation chains and remote data MUST be
  treated as hostile at every boundary and independently checked for identity, authority, scope,
  epoch, time, bounds, integrity and exact replay.
- **FED-026** Federation MUST be an intentional scale-out boundary: ordinary operations in one
  swarm MUST NOT require consensus, voter contact or a synchronous catalogue transaction in any
  other swarm. Large deployments MUST be able to distribute ownership by volume or explicit
  subtree across swarms while retaining the same sharing semantics.

## Storage targets and fault groups

- **TOP-001** One daemon MUST accept multiple registered storage-folder paths.
- **TOP-002** Registration MUST use existing folders without formatting, partitioning or mounting
  devices.
- **TOP-003** Folder size and filesystem type MUST NOT be assumed uniform.
- **TOP-004** A storage target MUST have a stable identity independent of its path spelling.
- **TOP-005** Machine, daemon, target, backing device and filesystem identities MUST remain distinct.
- **TOP-006** Hosts and storage targets MAY belong to multiple overlapping fault groups.
- **TOP-007** Fault-group classes and instances MUST be administrator-definable; machine and backing
  device groups MUST be created automatically where they can be proved.
- **TOP-008** Placement MUST evaluate the union of resources affected by simultaneous group failures.
- **TOP-009** Uncertain or contradictory failure-domain identity MUST reduce placement eligibility;
  it MUST NOT manufacture independence.
- **TOP-010** A topology change MUST expose any resulting loss of protection and queue safe movement
  when capacity permits.
- **TOP-011** Provider folders MUST contain only private provider records and shards; they MUST NOT
  mirror the user-visible namespace or become an alternate access path.
- **TOP-012** Folder-provider storage layout, indexing, packing and compaction MUST remain behind a
  provider interface and MUST avoid requiring one operating-system file per small shard.
- **TOP-013** Removing a mounted device, unmounting a filesystem or losing a folder during any IO
  operation MUST make that target unavailable without crashing the daemon or making sibling targets
  unavailable.
- **TOP-014** A returning target MUST be identified by its durable marker and generation rather than
  device name, mount point or discovery order; path reuse and replaced media MUST fail closed.
- **TOP-015** Target disappearance MUST NOT authorise retirement, cleanup or replacement of its
  identity. Repair urgency MUST consider protection risk and flap history without permitting an
  endless reconnect cycle to postpone critical repair.

## Protection and data lifecycle

- **DAT-001** Users MUST express required failures to survive; ordinary users MUST NOT select Reed–
  Solomon geometry.
- **DAT-002** A volume MAY contain immutable data encoded with different layouts while retaining one
  user-visible protection promise.
- **DAT-003** One-node data MUST use an explicitly unprotected layout rather than fake redundancy.
- **DAT-004** A write MUST NOT become visible until every shard required by the receipt's declared
  durability scope is durable and verified and its CoW branch version is committed. Wider
  convergence and protection MUST be reported separately.
- **DAT-005** Stored shard identities and contents MUST be immutable after publication.
- **DAT-006** Logical content and stored shards MUST carry cryptographic integrity digests.
- **DAT-007** Reads MUST verify content and SHOULD reconstruct from surviving shards without waiting
  for background repair.
- **DAT-008** Periodic scrub MUST detect missing and corrupt shards independently of client reads.
- **DAT-009** Reduced protection MUST create durable, bounded repair work and SHOULD heal without
  administrator intervention when eligible capacity exists.
- **DAT-010** A shard MUST NOT be deleted using location as authority.
- **DAT-011** Deletion MUST require an exact irreversible cleanup decision, current validation and a
  durable local tombstone before bytes become unreachable.
- **DAT-012** Interrupted, replayed, partial, out-of-space and indeterminate writes MUST recover
  without exposing partial files or leaking unbounded storage.
- **DAT-013** Storage and repair reservations MUST prevent concurrent work from double-spending
  capacity and MUST preserve configured repair reserve.
- **DAT-014** Folder and host drain MUST move authoritative data and prove safety before reporting
  that removal is safe.
- **DAT-015** The placement engine MUST support heterogeneous capacity and performance weights while
  treating failure independence as a hard constraint rather than a weight.
- **DAT-016** Logical chunks, shards, manifests, snapshots and provider records MUST use a reviewed
  cryptographic integrity algorithm with deterministic cross-implementation test vectors.
- **DAT-017** Capacity admission MUST preserve configurable repair and temporary-work reserve; it
  MUST block unsafe new writes before consuming space needed to honour existing promises.
- **DAT-018** Volumes MUST be thin-provisioned with an optional logical quota and MUST report both
  logical and actual protected physical consumption.
- **DAT-019** Placement MUST distribute stripes and repair options across the available independent
  failure domains so a larger mesh does not concentrate most availability on a small accidental
  subset.
- **DAT-020** Every consumer of stored or transferred data MUST independently verify the identity,
  length, cryptographic integrity, revision/generation, authority, freshness and semantic bounds
  required for that operation. A successful read, authenticated sender, catalogue entry, receipt,
  prior scrub or matching path MUST NOT make bytes inherently trusted.

## Erasure coding

- **EC-001** A protected stripe MUST use a recorded systematic Reed–Solomon `k+m` layout containing
  `k` data slices and `m` recovery slices.
- **EC-002** Any `k` independently verified slices from the `k+m` set MUST reconstruct the exact
  logical stripe; loss or corruption of any combination of at most `m` slices MUST be recoverable.
- **EC-003** Checksums MUST distinguish corrupt from valid slices before reconstruction; an invalid
  slice counts as unavailable and MUST NOT be used merely because it is present.
- **EC-004** A user failure policy MUST be translated into both coding geometry and placement proof.
  `m` alone MUST NOT claim machine, drive or custom fault-group survival.
- **EC-005** Separate failure scenarios are alternative promises. A simultaneous mixed scenario
  such as two machines plus three additional drives MUST be represented explicitly and proven
  against the union of all affected targets.
- **EC-006** The system MUST select `k` and `m` automatically within reviewed bounds, record the
  layout per stripe and permit different valid layouts within one volume.
- **EC-007** Encoding, decoding and reconstruction MUST stream in bounded slices and MUST NOT require
  an entire wide stripe or file in memory.
- **EC-008** Layout replacement and recoding MUST be copy-on-write: the new complete verified
  generation becomes authoritative atomically and the old generation is reclaimed later.

## Regional and local availability

- **LOC-001** Administrators and authorised owners MUST be able to attach a locality policy to a
  volume, folder or file and choose whether descendants inherit or override it.
- **LOC-002** A `complete_local` requirement for a cell/region MUST ensure every selected committed
  file version has enough verified slices entirely inside that cell to reconstruct every byte
  without external connectivity.
- **LOC-003** Local data availability MUST be paired with a reachable local branch service, valid
  identity/authorisation material and an access gateway before the system reports the scope locally
  usable for writes.
- **LOC-004** A locality policy MAY require several cells simultaneously and MAY specify an
  independent local fault-survival policy inside each cell.
- **LOC-005** Eventual writes MUST remain availability-first: the writing cell commits locally and
  reports other desired cells as lagging until automatic catch-up. Only an explicitly selected
  strong acknowledgement policy may wait for named required cells.
- **LOC-006** “Complete local copy” means 100% of selected committed logical bytes are locally
  decodable; it MUST NOT be presented as an absolute uptime guarantee when the cell itself loses
  power, gateways, valid authorisation or more storage than its local protection policy permits.
- **LOC-007** Locality, durability and failure-survival are separate constraints. Extra local copies
  count toward a protection promise only when their target/fault-group placement proves it.
- **LOC-008** The planner MAY satisfy locality using systematic data slices, recovery-coded sets or
  full replicas, but the representation MUST remain hidden behind the recorded layout and storage
  provider contracts.
- **LOC-009** Changing or inheriting a locality policy MUST create durable copy/repair work and
  expose `pending`, `complete`, `lagging`, `at_risk` or `unavailable` per required cell.
- **LOC-010** Snapshot locality MUST be explicit: a snapshot inherits the captured scope policy by
  default and MAY be assigned a separate retention/locality policy without rewriting its logical
  namespace root.
- **LOC-011** Cell and region names MUST be administrator-defined and composable with overlapping
  fault groups; the core MUST NOT hard-code buildings, stores, racks or geography.

## Filesystem namespace

- **FS-001** Files and folders MUST have stable identities that survive rename and move.
- **FS-002** Directory names MUST be unique under their parent after canonicalisation.
- **FS-003** Published file versions MUST be immutable; a file object MUST identify its current
  published version atomically.
- **FS-004** The filesystem service MUST support atomic open semantics including desired access,
  sharing access and create disposition.
- **FS-005** It MUST support bounded random reads and writes, length changes, flush, close, rename,
  deletion, enumeration and metadata operations.
- **FS-006** Cross-gateway share modes, byte-range locks and delete-on-close state MUST be governed by
  the reachable branch authority. During disconnection, incompatible branch-local operations MAY
  proceed and MUST reconcile into preserved conflict versions rather than silent overwrite.
- **FS-007** A dirty flush MUST publish exactly one durable branch file version with a receipt naming
  its cell/node, achieved protection and convergence scope, or report an unknown outcome resolvable
  by operation ID.
- **FS-008** Access adapters MUST use the filesystem service and MUST NOT read provider folders or
  database records directly.
- **FS-009** Extended attributes and named streams MUST have bounded protocol-neutral representations.
- **FS-010** Each volume MUST have an explicit, immutable-at-creation name policy; the ordinary
  default SHOULD be case-preserving, case-insensitive and portable across supported access clients.
- **FS-011** Large manifests MUST be divided into immutable, bounded and independently verified
  blocks rather than embedded as unbounded consensus commands.
- **FS-012** Copy MUST have defined same-volume semantics and MUST preserve permissions, ownership,
  tags and content identity according to an explicit policy.
- **FS-013** Namespace partition ownership MUST be explicit at volume or subtree boundaries. Same-
  partition operations retain atomic semantics; cross-partition operations require a typed
  transaction/handoff and MUST fail rather than partially commit during loss of either authority.
- **FS-014** An all-or-nothing namespace mutation spanning metadata partitions MUST stage every
  participant, record one durable global commit/abort decision and recover to that decision after
  crash or partition without exposing a partially committed batch.
- **FS-015** A logical bulk mutation MAY contain an effectively unbounded number of items only by
  using a durable immutable manifest assembled from bounded, independently validated chunks.

## Copy-on-write and snapshots

- **COW-001** Published file content, manifests, stripe generations, namespace commits and component
  configuration revisions MUST be immutable. Change creates new records and atomically advances the
  applicable local branch, converged namespace or configuration head pointer.
- **COW-002** Namespace mutation MUST path-copy only affected immutable records/blocks and MUST NOT
  duplicate unchanged file content or the complete directory tree.
- **COW-003** A volume snapshot MUST pin one exact committed namespace root in constant metadata
  work independent of the volume's byte size.
- **COW-004** Initial snapshots MUST be read-only, nameable and listable and MUST support manual and
  scheduled creation plus count/age retention policies.
- **COW-005** Snapshot restore MUST create a new namespace commit derived from the selected snapshot;
  it MUST NOT move consensus backwards, mutate the snapshot or destroy intervening history.
- **COW-006** Snapshot deletion MUST remove only its root reference. Content becomes reclaimable
  only after authoritative reachability proves that no live head, snapshot, handle, version or
  other retained root references it.
- **COW-007** Snapshot access MUST combine the captured namespace/metadata view with current active
  principal, authentication and explicit snapshot-access authority so historical permissions cannot
  resurrect a disabled identity.
- **COW-008** Mutable coordination state such as leases, presence, throttles, work claims, counters
  and observations MAY update in place transactionally; it MUST NOT be confused with immutable
  published state or included as user-restorable snapshot content.
- **COW-009** Snapshot, backup and consensus snapshot are distinct concepts and MUST use distinct
  record types, APIs, status text and recovery procedures.
- **COW-010** Restoring a historical file version MUST create a new current version or a new copied
  object; it MUST NOT rewind or erase intervening version history.
- **COW-011** Ordinary file-version history MUST be enabled by default and configurable per volume.
  Retention MUST support minimum age, minimum count, immediate-after-age or storage-pressure
  reclamation, explicit pins/holds and a separate minimum for concurrent-conflict versions.
- **COW-012** Disabling ordinary version history MUST NOT permit reconciliation to discard an
  acknowledged concurrent alternative before its mandatory conflict-safety retention expires.

## Disconnected writes and reconciliation

- **CON-001** A valid eventual filesystem create/write MUST remain accepted whenever the serving
  process can authenticate from an allowed committed identity revision and durably store at least
  one local CoW branch record plus its data; loss of wider quorum or remote cells alone MUST NOT
  block it.
- **CON-002** Every write receipt MUST state its durability scope: `node_local`, `cell_replicated` or
  `globally_converged`, plus achieved protection and pending locality/protection debt.
- **CON-003** HTTPS and SMB acknowledgement mappings MUST treat a successful flush as satisfying the
  scope's configured eventual or strong policy. UI/API status MUST NOT mislabel a local success as
  globally converged/protected or an unmet strong barrier as success.
- **CON-004** Each cell/node offline branch MUST be an immutable causally ordered operation/commit
  log with stable operation IDs, base commit(s), author, identity revision and content roots.
- **CON-005** Reconnection MUST automatically exchange missing branch heads and operations, validate
  identity revisions and content, compute deterministic merge commits and enqueue protection and
  locality repair without administrator action.
- **CON-006** Causally independent changes to different names or objects MUST merge without conflict;
  replayed identical operations MUST deduplicate.
- **CON-007** Concurrent incompatible edits MUST never discard an acknowledged version. Automated
  reconciliation MUST choose one deterministic visible result and preserve every alternative as
  immutable version history and, where needed, a deterministic conflict sibling.
- **CON-008** Concurrent same-name create, rename/rename, edit/delete and permission-sensitive
  operations MUST have explicit deterministic rules and canonical cross-implementation fixtures.
- **CON-009** Reconciliation MUST not require an administrator to repair consensus, choose shards or
  unblock the mesh. Content conflicts MAY be shown to affected users but MUST NOT prevent
  convergence or unrelated work.
- **CON-010** Security-critical mesh administration, voter membership, identity, role, ownership,
  permission, secret and executable-component changes MUST NOT use unrestricted offline merge;
  they require their owning authority or a separately designed constrained delegation.
- **CON-011** When an existing file's required base bytes are not locally available, MeshSpan MUST
  accept new independent files but MUST NOT fabricate a correct random modification of unavailable
  content. Locality policy SHOULD prevent this for scopes intended to work offline.
- **CON-012** Eventual local writes can stop only for a concrete physical or policy boundary such as no
  writable durable medium, exhausted authorised quota/reserve, unavailable required base bytes or
  invalid authentication—not merely because a remote link or global quorum is down.
- **CON-013** Protection/locality debt created during isolation MUST be durable, prioritised and
  repaired as soon as peers or capacity return; repeated churn MUST not lose or duplicate that debt.
- **CON-014** Offline authorisation MUST use a signed committed identity/ACL revision and bounded
  node/cell isolation delegation covering exact scopes, operation classes, targets, byte budget,
  validity interval and epoch; loss of connectivity MUST NOT create new authority.
- **CON-015** Offline capacity allocations MUST be disjoint and consumed durably per node/target so
  disconnected components cannot independently overspend one shared quota. Remote shard writes
  MUST carry an exact operation/shard/target capability derived from the delegation.
- **CON-016** Reconciliation of delete/edit races MUST follow causal order. For a genuinely
  concurrent race, a content write/truncate or rename survives, while descriptive, permission or
  ownership metadata alone MUST NOT resurrect a deleted object.
- **CON-017** Initial reconciliation MUST NOT perform content-aware merges. It MUST select one
  visible version deterministically and retain every acknowledged alternative in immutable version
  history for restore or restore-as-copy.

## Consistency and acknowledgement policy

- **ACK-001** Every volume, folder or file MUST resolve one inheritable acknowledgement policy with
  either `eventual` or `strong` consistency class and explicit durable-placement predicates.
- **ACK-002** Eventual acknowledgement MUST publish one immutable local or cell branch only after
  its configured minimum durable targets, distinct nodes and local protection predicates are
  verified; wider merge and placement MUST proceed automatically.
- **ACK-003** Strong acknowledgement MUST require every configured node, zone, locality and
  protection predicate to have verified durable receipts before one ACID metadata transaction
  publishes the manifest and advances the globally converged namespace head.
- **ACK-004** Each zone in an acknowledgement policy MUST be classified as
  `required_before_commit`, `eventual` or `excluded`, with optional per-zone minimum targets, nodes
  and protection scenarios. Only `required_before_commit` zones may hold the barrier.
- **ACK-005** Counts MUST use proved target, node, zone and fault-group identities and MUST NOT
  manufacture independence from several paths or targets on one host.
- **ACK-006** If a strong barrier cannot currently be met, MeshSpan MUST retain any durable local
  branch work and report the exact operation as pending or failed by deadline; it MUST NOT report
  strong success or silently fall back unless the policy explicitly permits fallback.
- **ACK-007** A successful SMB flush and HTTPS strong-write response MUST mean the configured
  acknowledgement policy was met. Structured APIs MUST expose achieved receipt scope, predicate
  evidence and remaining eventual-zone/protection debt.
- **ACK-008** Historical acknowledgement evidence MUST remain immutable. Later loss MAY degrade
  current health and trigger repair but MUST NOT rewrite what was proved when the version committed.
- **ACK-009** Reads MUST support latest authorised local branch, exact commit and linearizable latest
  converged modes; an isolated branch MUST NOT be presented as a successful strong read.
- **ACK-010** Normal UI setup MUST use a small set of plain-language, topology-aware presets and
  default to availability-first eventual convergence. Raw predicates and `excluded` zones MUST be
  advanced controls; users MUST NOT select shards or erasure geometry.

## Principals, groups, ownership and tags

- **IAM-001** Users and groups MUST share one principal identity namespace.
- **IAM-002** A user MAY belong directly to multiple groups.
- **IAM-003** A group MAY contain users and other groups.
- **IAM-004** Group membership MUST NOT contain direct or transitive cycles.
- **IAM-005** Nested-group membership MUST be evaluated consistently across all gateways.
- **IAM-006** A file or folder MUST have one or more owner principals.
- **IAM-007** An owner principal MAY be a user or group, and one object MAY have multiple owners.
- **IAM-008** Direct and transitive members of an owning group MUST receive effective ownership.
- **IAM-009** Ownership MUST survive content updates, rename and move.
- **IAM-010** Removing or disabling the last active owner MUST require an atomic ownership transfer.
- **IAM-011** Ownership and permission changes MUST be audited.
- **IAM-012** Files, folders, users and groups MAY carry multiple tags.
- **IAM-013** Tagging MUST NOT implicitly grant authority or file access.
- **IAM-014** Tags MUST attach to logical objects rather than immutable content versions.

## Permissions

- **ACL-001** A permission grant MUST target a user or group principal.
- **ACL-002** Grants MUST support volume, file and folder scope with explicit inheritance behaviour.
- **ACL-003** Grants MUST support optional activation and expiry instants.
- **ACL-004** A cached decision MUST NOT outlive its session, source grants, identity revision,
  gateway fence or authority validity.
- **ACL-005** Permission evaluation MUST include direct membership, transitive group membership,
  object ownership and inherited folder grants.
- **ACL-006** The internal rights model MUST distinguish traversal, listing, data read/write,
  creation, rename, deletion, attributes, permissions and ownership changes.
- **ACL-007** The ordinary UI SHOULD present understandable permission presets while advanced
  interfaces MAY expose individual rights.
- **ACL-008** Permission evaluation MUST be deterministic and independent of the serving gateway.
- **ACL-009** Permissions MUST be allow-only with explicit inheritance control; absence of an
  applicable right denies access and tags MUST NOT create authority.
- **ACL-010** A group or individual grant MAY require activation and MUST contribute no rights for a
  user without that user's current activation for the exact group or grant.
- **ACL-011** Activation MUST be self-service within pre-authorised bounds, record a bounded reason
  and duration, support a recent-step-up requirement, remain mesh-wide/revocable/audited, and never
  outlive its source, schedule, session or policy maximum.
- **ACL-012** Authorised system administrators MUST be able to create explicit inherited global
  read, write, manage and recovery grants, including for themselves, without receiving implicit
  data rights merely from the administrator role.

## Authentication and sessions

- **AUTH-001** A user MUST be able to enrol multiple independently revocable authentication methods.
- **AUTH-002** The model MUST support password, WebAuthn/passkey, TOTP, recovery-code, API-token,
  client-certificate and SMB-scoped credential records without combining their secret formats.
- **AUTH-003** Raw passwords, session tokens, API tokens and recovery codes MUST NOT be persisted.
- **AUTH-004** Authentication policies MUST support factor count, factor class, service scope,
  session lifetime and recent step-up requirements.
- **AUTH-005** Administrative operations SHOULD require recent strong authentication.
- **AUTH-006** Sessions MUST be usable consistently across authorised gateways and revocable across
  the mesh.
- **AUTH-007** Authentication throttling and security events MUST be mesh-wide so changing gateways
  cannot bypass them.
- **AUTH-008** Credential and secret material at rest MUST be hashed or encrypted according to its
  verification needs.
- **AUTH-009** Authentication failure MUST NOT reveal whether a user or individual factor exists.

## Access services

- **ACC-001** MeshSpan MUST provide built-in HTTPS and standards-compliant SMB services.
- **ACC-002** The SMB service MUST be implemented inside the Rust daemon without Samba or FUSE.
- **ACC-003** Multiple gateways MAY expose the same authoritative namespace concurrently.
- **ACC-004** The same user identity and permissions MUST apply through HTTPS and SMB.
- **ACC-005** HTTPS MUST provide authenticated administration, file browsing, upload and download.
- **ACC-006** SMB MUST support the filesystem operations and acknowledgement semantics required by
  the selected SMB compatibility profile.
- **ACC-007** Public services MUST remain usable on supported Linux and macOS hosts and in the
  supported container environment.
- **ACC-008** HTTPS uploads MUST be resumable, bounded and recoverable after client disconnect;
  downloads MUST stream, support ranges and stable version-derived validators without whole-file
  gateway staging.
- **ACC-009** Each eligible gateway MAY expose HTTPS and SMB concurrently; gateway selection MUST
  NOT create a single active namespace or credential owner.

## Certificates and secrets

- **PKI-001** Every enrolled node MUST have a mesh-bound identity certificate.
- **PKI-002** Node and user-facing certificate private keys MUST be protected at rest and in transit.
- **PKI-003** ACME MUST support HTTP-01 and DNS-01 challenges.
- **PKI-004** Only one fenced worker MAY act on a certificate order at a time.
- **PKI-005** An issued certificate and private key MUST be delivered as node-specific encrypted
  envelopes to authorised gateways.
- **PKI-006** Renewal, failed-order retry and worker replacement SHOULD be automatic.
- **PKI-007** Secret rotation MUST identify generation, recipients and installation acknowledgements.
- **PKI-008** Local installations MUST support a clearly identified mesh-local certificate, and
  administrators MAY install their own certificate without weakening private node identity.

## Administration and status

- **OPS-001** MeshSpan MUST provide user and administrator interfaces plus equivalent headless APIs.
- **OPS-002** Normal setup MUST not require editing generated protocol, consensus or certificate
  configuration files.
- **OPS-003** Status MUST report metadata authority, read availability, write availability,
  reachability and protection separately.
- **OPS-004** Slow placement, repair, scrub, drain and reconciliation work MUST be asynchronous,
  bounded and resumable.
- **OPS-005** Routine failure and return within policy SHOULD recover without administrator action.
- **OPS-006** Security- and durability-relevant administrative activity MUST be audit logged without
  secrets or file content.
- **OPS-007** The default dashboard MUST answer protection, availability, capacity, failures,
  background work and required action in plain language without consensus or erasure-code jargon.
- **OPS-008** The user interface MUST be keyboard accessible, screen-reader understandable,
  responsive on a phone, colour-independent and respectful of reduced-motion preferences.
- **OPS-009** User and administrator views MUST receive bounded incremental operation/event updates
  without requiring full-page reloads.
- **OPS-010** Optional email and generic-webhook notifications MUST be derived from durable,
  deduplicated events and MUST NOT contain secrets or file content.
- **OPS-011** A diagnostic bundle MUST contain versions, redacted configuration, recent bounded
  logs/events, topology, target health, quorum state and work status while excluding credentials,
  private keys, join secrets, tokens and user content.
- **OPS-012** Advanced metrics SHOULD be available in a documented scrapeable format without being
  required for ordinary administration.
- **OPS-013** Capacity and protection changes MUST show an honest feasibility, capacity and work
  estimate before commit, including uncertainty where prediction is weak.
- **OPS-014** Churn handling MUST be automatic and idempotent. The ordinary interface MAY explain
  current impact and action being taken but MUST NOT ask an administrator to choose internal
  histories, shards, leaders or returning-target conflicts.
- **OPS-015** As nodes, targets and links return, catch-up, inventory reconciliation, service
  activation and required healing MUST begin automatically and converge without waiting for an
  administrator to acknowledge the outage.
- **OPS-016** The ordinary user experience MUST use files, folders, people, safety and place
  vocabulary. Branches, shards, consensus terms and coding geometry MAY appear in advanced
  diagnostics but MUST NOT be required to use the appliance.

## Persistence, upgrade and recovery

- **PER-001** Authoritative metadata MUST use transactional SQLite-compatible relational schemas.
- **PER-002** Database schema, protocol and persisted record versions MUST be explicit.
- **PER-003** Migrations MUST be transactional, restartable or fail closed before service admission.
- **PER-004** Backup and restore MUST bind an exact committed metadata position and mesh identity.
- **PER-005** Restore MUST validate integrity, membership and secret availability before admission.
- **PER-006** Upgrade and supported rollback paths MUST be tested against real published artefacts.
- **PER-007** A voter database MUST remain local to that voter and MUST NOT be shared over a network
  filesystem.
- **PER-008** Protocol, command, schema, manifest, provider, capability and export formats MUST be
  independently versioned and reject unknown incompatible versions clearly.
- **PER-009** Rolling upgrade planning MUST preserve a valid election path, consensus-write quorum
  and working gateways, negotiate mixed-version features explicitly and block operations
  unsupported by any required participant.
- **PER-010** Recoverable metadata snapshots SHOULD be copied to protected storage targets without
  allowing those copies to participate in consensus.
- **PER-011** Catastrophic metadata recovery MUST use an administrator-held recovery bundle plus a
  verified committed snapshot and target inventories; it MUST never infer a new namespace solely
  from untrusted filenames or locations.
- **PER-012** One `partition.sqlite3` MUST contain a partition's consensus and applied replicated
  state, while one daemon-wide `local.sqlite3` contains node-local and disconnected-branch state.
  No invariant MAY depend on atomic commit across those files; every cross-authority transition
  MUST be idempotent, digest-bound and retain its source until a durable result is known.

## Scale, performance and resource safety

- **SCL-001** Protocol identifiers, paging and membership records MUST NOT impose a small fixed
  storage-node limit.
- **SCL-002** Request-path work MUST NOT scan all nodes, files, shards or users.
- **SCL-003** Enumeration, inventory and work queues MUST be revision-bound and cursor-paged.
- **SCL-004** Connection, stream, memory, file-descriptor and background-work limits MUST be
  resource-aware and configurable rather than arbitrary product ceilings.
- **SCL-005** Bulk data traffic MUST NOT starve consensus, authentication or control traffic.
- **SCL-006** Unreachable peers MUST be handled concurrently with bounded timeouts, cancellation and
  backoff.
- **SCL-007** Local development tests MUST remain partitioned, concurrent and fast enough to run
  before every push; early development MUST NOT depend on GitHub-hosted CI.
- **SCL-008** Runtime scheduling MUST use explicit priority classes so metadata, health and
  interactive IO are not starved by repair, rebalance, recoding, scrub or compaction.
- **SCL-009** Ordinary connection capacity MUST derive from available workers, memory, descriptors
  and configured budgets rather than a small hard-coded product ceiling.
- **SCL-010** Request routing and metadata storage MUST support adding partitions without changing
  public filesystem semantics or requiring a scan of all metadata partitions.
- **SCL-011** MeshSpan MUST support both scale-up within one swarm and scale-out through federation;
  it MUST NOT impose an arbitrary node-count threshold that forces conversion to federation.
- **SCL-012** Federated sharing MUST keep consensus work local to each swarm. Canonical merge and ACL
  authority for a shared scope MAY load its owning swarm, so large deployments MUST be able to
  distribute owned volumes or explicit subtree scopes without changing user-visible access.
- **SCL-013** The metadata model MUST scale online from one all-purpose root Raft group to many
  delegated groups without a format conversion. Adding nodes MUST NOT add every node as a root
  voter, make delegated operations append through the root, or require broadcasts to discover the
  owning group.
- **SCL-014** Partition routing and delegation MUST support bounded hierarchical lookup and cached
  signed routes so growth from tens to thousands of nodes increases independent groups and workers
  rather than the synchronous fan-out of an ordinary operation.

## Verification and release

- **TST-001** Semantic state transitions MUST have deterministic normal, replay, conflict and hostile
  input vectors independent of database and transport implementations.
- **TST-002** Storage tests MUST inject process death, power-loss semantics, partial writes,
  corruption, read-only state and out-of-space failures.
- **TST-003** Multi-node tests MUST exercise leader loss, majority/minority and multi-way partitions,
  return, catch-up and stale-process fencing.
- **TST-004** Real HTTPS and SMB clients MUST perform create, write, flush, read, rename and delete
  cycles against the same files and users.
- **TST-005** Protection tests MUST remove every configured combination of machine, device and custom
  fault groups and verify exact reconstructed bytes.
- **TST-006** Repair, scrub and drains MUST be tested while client activity continues.
- **TST-007** Backup, restore, migration, upgrade and rollback MUST have end-to-end acceptance tests.
- **TST-008** Long-duration churn, certificate renewal and heterogeneous-capacity tests MUST precede
  a stable release claim.
- **TST-009** Native Linux and macOS daemon/gateway acceptance plus the supported container path MUST
  exercise mixed-host meshes; SMB client interoperability MAY use any standards-compliant clients
  and MUST NOT turn a client product into a service requirement.
- **TST-010** A continuous physical-churn gate MUST repeatedly unplug and reconnect network links,
  hosts and storage devices during reads, writes, flushes, repair, scrub, drain, configuration
  rollout and certificate rotation, asserting exact acknowledged bytes and automatic convergence.
- **REL-001** Commits and tags MUST be signed, and releases MUST publish checksums and provenance.
- **REL-002** Development branches MUST be short-lived, merged promptly and deleted after merge.
- **REL-003** The project MUST publish a container image and the accepted native platform artefacts.
- **REL-004** Root licence text, every authored source header, Cargo/npm package metadata, generated
  OpenAPI, OCI labels, release manifests and SBOMs MUST identify the project as exactly
  `GPL-2.0-only` and MUST NOT offer a later-version alternative.

## Development system

- **DEV-001** Rust builds MUST track the latest stable toolchain that passes the complete required
  suite; toolchain updates MUST be tested before merge.
- **DEV-002** The web workspace MUST target Node.js 26 and TypeScript 6.0.3; TypeScript 7 MUST
  remain the next toolchain upgrade target once the selected generator and typed ESLint stack
  officially support it.
- **DEV-003** Web date/time domain logic MUST use Temporal rather than introducing new JavaScript
  `Date` arithmetic.
- **DEV-004** Every Rust workspace crate and web package MUST participate in language-standard
  format, lint, type/build and test gates with warnings treated as failures.
- **DEV-005** Dependency and toolchain update pull requests MAY merge automatically only after all
  required gates pass and the update policy has not classified the change for manual review. This
  automation remains deferred while GitHub Actions are disabled.
- **DEV-006** Fast checks MUST be runnable locally in independently parallelisable lanes; ordinary
  feature work MUST NOT depend on a remote workflow before its own relevant tests run.
- **DEV-007** The web application MUST use Solid 2.0, remain a compiled static client served by the
  Rust daemon and introduce no production Node.js server.
- **DEV-008** Rust public API schemas SHOULD generate TypeScript representations so the web client
  does not manually duplicate protocol-facing types.
- **DEV-009** GitHub Actions MUST remain absent during early implementation. Enabling remote CI
  requires an explicit decision, measured local-suite timings and a plan that preserves local-first
  feedback.
- **DEV-010** Unit, property, conformance, simulation, web and process-integration tests MUST run
  concurrently by default using isolated state, dynamic ports and bounded worker pools. A serial
  test MUST document the genuinely exclusive resource that prevents isolation.
- **DEV-011** Web linting MUST enable type-aware correctness, promise-safety, exhaustiveness,
  accessibility, Solid-specific, complexity, nesting and source-size rules with warnings treated
  as failures. Formatting alone is not linting.
- **DEV-012** A complexity or size violation MUST trigger review of responsibility, data flow and
  module boundaries. Moving an arbitrary suffix into a helper solely to satisfy a numerical limit
  is not an acceptable refactor.
- **DEV-013** Handwritten TypeScript MUST contain no `any` and MUST enable typed rules that reject
  unsafe `any` assignment, arguments, calls, member access, returns, assertions and operations.
  Untrusted inputs MUST enter as `unknown` and be validated or narrowed before use.

## Public API

- **API-001** The HTTPS API MUST provide a rolling `/api/latest` contract and, once published,
  immutable exact `/api/vM.m` contracts plus compatible-major `/api/vM.x` pins, with typed
  resources for setup, authentication, mesh, nodes, targets, fault groups, volumes, exports,
  principals, groups, permissions, files, uploads, work, repair, certificates, events and
  diagnostics.
- **API-002** Long-running operations MUST return an operation ID and expose durable state, bounded
  progress, cancellation support where safe and the terminal committed outcome.
- **API-003** Errors MUST contain a stable code, plain message, request ID, retry classification and
  bounded field/remediation details while excluding sensitive data.
- **API-004** Potentially large list APIs MUST use stable opaque cursors within indexed server-side
  filters and ordering. Every non-terminal page MUST return a ready-to-follow relative
  `next_page_url`; reverse links and exact total counts are optional where efficient.
- **API-005** API authentication and authorisation MUST use the same principals, sessions, roles,
  grants and audit rules as the user and administrator interfaces.
- **API-006** Rust boundary types and their structural constraints MUST be the source for generated
  OpenAPI, web types, request/response validators and the typed Fetch client. The server MUST NOT
  depend on a caller using generated code.
- **API-007** Every available API path MUST expose its exact OpenAPI document and return the
  resolved API contract label plus schema digest as informational response headers.
- **API-008** Before product 1.0 only `/api/latest` exists. An exact fixed point becomes immutable
  only when a signed release manifest publishes its API version, OpenAPI digest and generated-client
  fixture digest; support lifetime remains a separately published policy.
- **API-009** Exact minor fixed points within one major SHOULD be backward-compatible. A security or
  integrity emergency MAY reject unsafe behaviour only with an explicit stable error, affected-
  version notice and replacement/remediation guidance.
- **API-010** Path, query, header, cookie, JSON request and JSON response structures MUST be
  validated against the same generated structural contract at their consuming boundary; stateful
  domain rules remain authoritative Rust validation.
- **API-011** Requests MUST reject unknown fields by default. Responses MAY ignore and discard
  additive unknown fields only where forward compatibility is declared. Unknown control/security
  variants and ambiguous unions MUST fail closed.
- **API-012** Missing and nullable fields MUST remain distinct: omission means not supplied, while
  `null` means explicitly blank/clear only where declared. The API MUST NOT perform implicit scalar
  coercion or undeclared normalisation.
- **API-013** If the server cannot validate its own outgoing response, it MUST suppress that
  response, return a bounded internal-contract failure where possible and record a safe diagnostic
  event rather than exposing malformed internal state.
- **API-014** Route generation MUST default-deny missing access metadata and require an explicit
  anonymous, authenticated, recent-step-up or internal-node access profile. Authentication and
  coarse authorisation MUST precede expensive allocation/work where protocol framing permits.
- **API-015** Browser sessions MUST initially use secure HTTP-only cookies plus CSRF defence;
  headless clients MUST support scoped bearer tokens or client certificates. Credentials MUST NOT
  appear in URLs, and authentication methods remain replaceable.
- **API-016** Every mutation MUST carry a client-generated operation ID. Replay with the same
  canonical digest returns the durable outcome; reuse with different input is rejected.
- **API-017** A long-running mutation MUST support one durable operation with an asynchronous status
  URL and, where useful, bounded wait-for-terminal-outcome behaviour.
- **API-018** Pagination MUST apply current permissions at every page without forcing clients to
  replay earlier pages after a permission change. The server MUST use bounded indexed filtering so
  inaccessible records do not create a client request storm.
- **API-019** Resumable Server-Sent Events MAY optimise browser updates but MUST NOT be required for
  correctness or third-party clients. Pollable endpoints and conditional HTTP requests remain
  complete alternatives.
- **API-020** Authenticated `ETag` validators MUST include the resource revision and caller-visible
  authorisation projection so revocation cannot incorrectly produce `304 Not Modified`.
- **API-021** File streams MUST validate bounded control records, declared length/ranges and final
  content integrity incrementally. Invalid, truncated, excessive or mismatched streams MUST NOT
  publish a file version.
- **API-022** Resumable transfer state MUST bind operation ID, content identity and independently
  verified received ranges; a client-claimed offset alone is not authority.
- **API-023** Generated OpenAPI, web types, Fetch client and runtime validators MUST be committed,
  deterministic and non-editable by hand. Local regeneration MUST fail on drift and prove strict
  compilation, absence of `any`, and exact valid/invalid fixtures.
- **API-024** OpenAPI generation MUST reject incomplete contracts by default, including missing or
  duplicate operation IDs, access policy, outcomes, discriminators, bounds or mutation replay
  semantics. Contextual exceptions MUST be explicit and tested.

## Replaceability and configuration

- **EXT-001** Major subsystems MUST depend on stable capability-oriented contracts rather than a
  particular implementation. This includes storage providers, access connectors, administration
  clients, metadata repositories, consensus engines, coding schemes, placement policies,
  authentication methods, certificate challenge handlers, notification sinks and observability
  exporters.
- **EXT-002** Each replaceable implementation MUST have a stable implementation ID, contract
  version, configuration schema version and declared capabilities and limits.
- **EXT-003** A component replacement MUST support an explicit validate, stage, activate, observe
  and retire lifecycle; it MUST NOT require rewriting unrelated domain state.
- **EXT-004** Old and new implementations MAY coexist during a bounded migration when their
  contract versions are compatible. Existing data and configuration MUST identify the exact
  implementation/version needed to read or manage them.
- **EXT-005** Replaceability MUST NOT allow a component to bypass domain authority, permissions,
  lifecycle safety, audit, resource bounds or protocol validation.
- **EXT-006** The shipped administration panel MUST be a replaceable client of the same versioned
  API available to other authorised administration clients; it MUST NOT use a privileged private
  database or daemon interface.
- **EXT-007** Replicated metadata stores component selection and configuration, not executable
  plugin code. Installing or updating executable code remains an authenticated software deployment
  operation with normal artefact verification.
- **EXT-008** The owned consensus implementation MUST remain a composable Rust library boundary:
  its deterministic election, replication, quorum and membership pieces MUST accept explicit
  inputs and emit explicit effects, while MeshSpan-specific authorisation, metadata commands, SQL,
  transport and process lifecycle remain adapters outside the core. Separate publication and
  compatibility guarantees are deferred, but application coupling MUST NOT accumulate in the core.
- **CFG-001** Every mesh-wide desired setting MUST be an authoritative, schema-versioned,
  revisioned metadata record committed through consensus.
- **CFG-002** Configuration changes MUST be validated, authorised and audited and MUST produce a
  durable operation outcome. Partial node application MUST be visible as observed state, not
  mistaken for committed desired state.
- **CFG-003** Secret configuration MUST be represented in metadata by encrypted generations or
  secret references and per-node envelopes; plaintext secrets MUST NOT appear in ordinary
  configuration records, API responses or events.
- **CFG-004** Node-local state MAY contain only inherently local bindings and recovery material,
  including folder paths, daemon state paths, locally generated private keys, decrypted secret
  cache, socket bindings and measured resource observations.
- **CFG-005** A node-local binding MUST reference the authoritative component instance and revision
  it implements. Local configuration MUST NOT override mesh authority or manufacture a different
  volume, permission, connector or protection policy.
- **CFG-006** Bootstrap flags and environment values MUST converge into the same validated domain
  operations as the UI/API. After enrolment, replicated desired configuration is authoritative.
- **CFG-007** Returning and newly enrolled nodes MUST reconcile desired configuration by revision,
  apply only compatible instances and report exact unsupported, pending, active or failed observed
  states.
- **CFG-008** Configuration rollback MUST create a new committed revision selecting a compatible
  prior value; history MUST remain auditable rather than mutating or deleting the old revision.

## Deferred capabilities

- **DEF-001** NFS, WebDAV, SFTP, S3 and other access adapters are deferred but MUST use the same
  filesystem service when implemented.
- **DEF-002** Native direct-shard clients and peer-assisted verified caches are deferred; caches MUST
  never count toward durability.
- **DEF-004** Whole-device management and native Windows hosting are not part of the initial MUP.
- **DEF-005** Automatically deciding when and how to create, split, merge and rebalance delegated
  metadata Raft groups is a future optimisation. The root/delegation model and safe manual/test
  transition are foundational, but production heuristics MUST wait for measured load, measured
  per-group resource capacity, eligible membership, fault-domain placement and migration-cost
  evidence. They MUST NOT use node count or a fixed operation rate as a hardware-independent split
  trigger.
