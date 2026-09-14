-- SPDX-License-Identifier: GPL-2.0-only

-- Local preimages only. The authoritative node activation digest remains the permission to use one.
CREATE TABLE local_node_capability_presentations (
    node_id BLOB NOT NULL CHECK(length(node_id) = 16 AND node_id != zeroblob(16)),
    incarnation INTEGER NOT NULL CHECK(incarnation > 0),
    certificate_fingerprint BLOB NOT NULL CHECK(length(certificate_fingerprint) = 32 AND certificate_fingerprint != zeroblob(32)),
    capability_digest BLOB NOT NULL CHECK(length(capability_digest) = 32 AND capability_digest != zeroblob(32)),
    canonical_hello BLOB NOT NULL CHECK(length(canonical_hello) BETWEEN 1 AND 65540),
    recorded_order INTEGER NOT NULL CHECK(recorded_order > 0),
    PRIMARY KEY(node_id, incarnation, capability_digest)
) STRICT;
