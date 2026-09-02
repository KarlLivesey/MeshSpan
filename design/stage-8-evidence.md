# Stage 8 implementation evidence

Status: complete on 2026-09-02.

Stage 8 delivers fault-aware protection policies, streaming erasure coding and
degraded reads through the native HTTPS and embedded SMB boundaries. This is
implementation evidence, not a release declaration; release creation remains
disabled pending the dependency review.

## Delivered surfaces

| Surface                      | Executable evidence                                                                                                                                                                                                     |
| ---------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Fault model                  | Administrators can describe overlapping machine, device and availability-cell relationships. Placement evaluates the requested failure scenarios rather than counting nominal replicas.                                 |
| Automatic layout             | The placement oracle chooses a sufficient layout from eligible capacity, keeps independent failures independent and reports machine protection separately from device-only protection.                                  |
| Erasure coding               | Bounded streaming Reed-Solomon encoding and decoding produce authenticated immutable shards behind the coding interface. A volume may retain mixed historical layouts while new versions adopt the current policy.      |
| Degraded reads               | The filesystem verifies shards, rejects corrupt candidates and reconstructs exact bytes from any sufficient surviving set.                                                                                              |
| Locality and acknowledgement | Inherited policies distinguish complete local decodability, zones required before strong acknowledgement and zones that may catch up eventually.                                                                        |
| Online growth                | One-node operation grows to five metadata voters plus a learner. Newly admitted learners start catch-up at the committed membership boundary and receive later metadata without replaying an unbounded genesis history. |
| Common gateways              | One protected namespace is written and read through native HTTPS and the embedded SMB 3.1.1 service. No gateway-specific copy or credential store is involved.                                                          |

## Real six-process proof

The ignored Stage 8 process test starts six real MeshSpan daemons with separate
SQLite state and two independently registered storage folders per daemon. It
enrols five metadata voters and one learner, commits the topology and protection,
locality and acknowledgement policies through HTTPS, publishes the volume, and
uses a pinned real `smbclient` container against the embedded SMB service.

The proof writes exact bytes through HTTPS and SMB, reads them back through both
interfaces, then stops the two daemons in the same declared availability cell.
The remaining gateways still return the exact acknowledged version. Fixture
identities are mapped back to authoritative topology hosts before failure
injection, so the test removes the intended machines rather than relying on
discovery order.

Two clean consecutive runs passed in 41.14 and 42.52 seconds.

## Failure-model proof

The direct real-folder acceptance test uses six machines with two folders each.
It removes two whole machines, three additional storage devices and an isolated
availability cell, then verifies exact reconstruction. Exhaustive small-topology
tests compare the production placement search with a simple minimum-layout
oracle. Separate cases prove heterogeneous capacity cannot manufacture fault
independence and that a single machine reports device protection without falsely
claiming machine, power or location survival.

## Local verification

The final focused gate ran locally with GitHub Actions disabled:

```text
PASS affected Rust library suites (668 passed)
PASS meshspan-consensus unit tests (23 passed)
PASS meshspan-cluster unit tests, including real Quinn re-election (60 passed)
PASS real six-process HTTPS/SMB Stage 8 proof (2 consecutive runs)
PASS cargo fmt --check
PASS cargo clippy for all affected packages and targets (-D warnings)
PASS git diff --check
PASS Rust dependency licence policy
PASS JavaScript dependency licence policy under NVM Node v26.8.1
```
