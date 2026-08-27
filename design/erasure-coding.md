# Erasure coding and failure proof

Status: draft for review.

## The exact `k+m` guarantee

A systematic Reed–Solomon stripe contains:

```text
k data slices + m recovery slices = k+m total slices
```

The data slices contain the original striped bytes. Recovery slices contain
coding information. Any `k` valid slices reconstruct the original stripe, so any
combination of up to `m` missing or corrupt slices is recoverable.

Example:

```text
8 data + 2 recovery = 10 slices
```

Any eight verified slices recover the stripe. Any two may be unavailable. The
third loss may make that stripe unrecoverable.

Integrity and erasure coding solve different problems: the digest says whether a
slice is valid; Reed–Solomon reconstructs when invalid/missing count is within
`m`. MeshSpan never feeds a known-corrupt slice to the decoder as valid input.

## Slices are not failure domains

`m=2` does not by itself prove survival of two machines. Placement supplies that
proof. For a policy of any two machine failures, no selected two machine groups
may contain more than `m` slices of a stripe. The ordinary rule therefore places
at most one slice per host when enough independent hosts exist.

The same applies to backing devices and custom groups. If a target belongs to
`building-a`, `room-2`, `circuit-7`, `host-12` and `device-x`, its one slice is
removed when any selected failed group contains that target.

## Alternative and simultaneous scenarios

These are separate alternative promises:

```text
Scenario A: any 2 machine groups
Scenario B: any 3 backing-device groups
```

The layout must pass A and pass B, but it does not assume A and B occur at the
same time.

This is stronger and explicit:

```text
Scenario C: any 2 machine groups plus any 3 additional backing-device groups
```

For C, placement removes the union of all selected groups. If five distinct
slices can be removed, geometry needs at least five recovery slices. Overlap may
reduce the actual union, but MeshSpan proves every permitted combination instead
of assuming overlap.

## Automatic geometry

Users select failure promises, not `k` and `m`. The planner chooses a bounded
layout using:

- every required failure scenario;
- eligible independent targets;
- logical stripe length and final partial stripe;
- capacity efficiency and repair fan-in;
- encoder memory/CPU and target/network performance;
- reserve and current protection risk.

It first finds safe `m` and placement, then chooses `k` for useful efficiency and
bounded width. A strong publication waits or fails when no reachable layout
proves its required promise. An eventual write may commit the best currently
durable layout with explicit protection debt; it never labels missing parity as
present and repairs/re-encodes automatically when resources return.

One volume may contain `2+2`, `4+2`, `8+2` or other reviewed layouts. Every stripe
records its exact coding scheme/version, `k`, `m`, slice length, logical length,
digests and generation.

## Streaming

The encoder processes a stripe in small bounded byte windows across all `k+m`
slices. Backpressure from a slow target stops production of further windows
without retaining the full stripe in RAM. The decoder similarly reconstructs
only required ranges where the integrity construction permits it.

The implementation is replaceable behind the coding contract, but a candidate
must pass canonical encode/reconstruct vectors on all supported architectures.

## Copy-on-write recoding

Changing geometry or repairing a generation writes a complete new immutable
generation. After every required new slice is durable and verified, one metadata
compare-and-swap makes it authoritative. Old slices remain readable until that
commit and are removed later through guarded cleanup.

Snapshots reference logical file versions/manifests rather than assuming one
current coding geometry. Recoding therefore preserves snapshot bytes and does
not duplicate logical content.

## Required proof

For each allowed `k+m`, tests remove every subset of zero through `m` slices and
assert exact bytes, then remove `m+1` and assert honest unavailability unless an
extra valid location exists. Placement tests separately enumerate every required
machine, device and overlapping custom-group scenario and compare against a
simple exhaustive oracle.
