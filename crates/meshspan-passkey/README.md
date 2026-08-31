<!-- SPDX-License-Identifier: GPL-2.0-only -->

# meshspan-passkey

`meshspan-passkey` is an independently extractable WebAuthn relying-party
library for hostile-input services. It is licensed `GPL-2.0-only` and does not
depend on MeshSpan application crates.

The library owns bounded parsing, ceremony validation and policy decisions. It
uses current RustCrypto primitives under their MIT option for cryptographic
operations; it does not implement elliptic-curve arithmetic itself and does not
call an external service or executable.

Its first supported profile is the mandatory WebAuthn ES256 assertion path.
Unsupported algorithms fail explicitly. Registration and additional current
algorithms are added behind the same stable boundary, with standards vectors,
before MeshSpan advertises them.
