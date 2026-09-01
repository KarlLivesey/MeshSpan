// SPDX-License-Identifier: GPL-2.0-only

//! Canonical digest of one validated node capability presentation.

use sha2::{Digest, Sha256};

use crate::v1::NodeHello;

const DOMAIN: &[u8] = b"meshspan.private.node-capabilities.v1\0";

/// Digests every negotiated role, component, feature and resource bound in `NodeHello`.
///
/// Callers must first pass the hello through the normal wire validator. Ordering remains part of
/// the presentation so a changed retry cannot silently normalise duplicates or reordered values.
#[must_use]
pub fn node_capability_digest(value: &NodeHello) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(DOMAIN);
    append_u64(&mut digest, value.versions.len());
    for version in &value.versions {
        digest.update(version.major.to_be_bytes());
        digest.update(version.minor.to_be_bytes());
    }
    append_u64(&mut digest, value.roles.len());
    for role in &value.roles {
        digest.update(role.to_be_bytes());
    }
    append_u64(&mut digest, value.components.len());
    for component in &value.components {
        digest.update(component.contract_kind.to_be_bytes());
        append_bytes(&mut digest, component.implementation_id.as_bytes());
        append_u64(&mut digest, component.versions.len());
        for version in &component.versions {
            digest.update(version.major.to_be_bytes());
            digest.update(version.minor.to_be_bytes());
        }
        digest.update(component.maximum_control_bytes.to_be_bytes());
        digest.update(component.maximum_items.to_be_bytes());
        digest.update(component.maximum_concurrency.to_be_bytes());
    }
    append_u64(&mut digest, value.feature_bits.len());
    for feature in &value.feature_bits {
        digest.update(feature.to_be_bytes());
    }
    digest.update(value.maximum_control_bytes.to_be_bytes());
    digest.update(value.maximum_data_frame_bytes.to_be_bytes());
    digest.update(value.maximum_streams.to_be_bytes());
    digest.finalize().into()
}

fn append_bytes(digest: &mut Sha256, value: &[u8]) {
    append_u64(digest, value.len());
    digest.update(value);
}

fn append_u64(digest: &mut Sha256, value: usize) {
    digest.update(u64::try_from(value).unwrap_or(u64::MAX).to_be_bytes());
}
