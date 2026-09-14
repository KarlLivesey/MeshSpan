-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE node_capability_presentations (
    node_id BLOB PRIMARY KEY REFERENCES nodes(node_id) CHECK(length(node_id) = 16),
    incarnation INTEGER NOT NULL CHECK(incarnation > 0),
    certificate_generation INTEGER NOT NULL CHECK(certificate_generation > 0),
    certificate_fingerprint BLOB NOT NULL CHECK(length(certificate_fingerprint) = 32),
    capability_digest BLOB NOT NULL CHECK(length(capability_digest) = 32),
    revision INTEGER NOT NULL CHECK(revision > 0)
) STRICT;
