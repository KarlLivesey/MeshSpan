<!-- SPDX-License-Identifier: GPL-2.0-only -->

# meshspan-protobuf

`meshspan-protobuf` is a bounded Protocol Buffers runtime and Rust source
generator written for hostile-input services. It is `GPL-2.0-only`, uses only
the Rust standard library, and does not depend on MeshSpan.

The crate lives in its own directory so it can become an independently
maintained repository without changing its public API. MeshSpan is its first
consumer, not its owner at runtime.

## Contract

- Decode limits are explicit and checked before allocation.
- Length arithmetic and output reservation are fallible.
- Unknown fields are skipped according to the Protocol Buffers wire format.
- Malformed, truncated and out-of-range boundary values fail closed; emitted
  messages use one deterministic canonical encoding.
- Generated records use ordinary Rust values rather than exposing a generator's
  internal representation.
- The optional `codegen` feature compiles supported `.proto` schemas without
  invoking an external executable.

The first integration target is the MeshSpan private `proto3` schema surface:
messages, enums, oneofs, scalar presence, repeated packed scalars and imported
types. The runtime deliberately rejects unsupported wire constructs rather than
guessing.
