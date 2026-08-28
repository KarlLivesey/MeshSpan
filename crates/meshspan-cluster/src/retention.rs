// SPDX-License-Identifier: GPL-2.0-only

//! Exact replicated-policy to local retention-selection boundary.

use meshspan_filesystem::{
    VersionReclaimMode, VersionRetentionError, VersionRetentionSelectionPolicy,
};
use meshspan_metadata::{RetentionReclaimMode, VersionRetentionPolicy};

/// Converts one independently validated replicated policy without weakening any bound.
///
/// # Errors
///
/// Rejects policy values that cannot be represented by the local SQLite selection contract.
pub fn version_retention_selection_policy(
    policy: VersionRetentionPolicy,
) -> Result<VersionRetentionSelectionPolicy, VersionRetentionError> {
    VersionRetentionSelectionPolicy::new(
        policy.sequence,
        policy.minimum_age,
        policy.maximum_age,
        policy.minimum_versions,
        match policy.reclaim_mode {
            RetentionReclaimMode::UnderPressure => VersionReclaimMode::UnderPressure,
            RetentionReclaimMode::AfterMaximumAge => VersionReclaimMode::AfterMaximumAge,
            RetentionReclaimMode::EagerAfterMinimumAge => VersionReclaimMode::EagerAfterMinimumAge,
        },
        policy.soft_minimum_breakable,
        policy.conflict_minimum_age,
    )
}

#[cfg(test)]
mod tests {
    use meshspan_domain::{DurationMicros, Revision, UnixMicros, VolumeId};

    use super::*;

    #[test]
    fn replicated_selection_fields_map_exactly() -> Result<(), Box<dyn std::error::Error>> {
        let source = VersionRetentionPolicy {
            volume_id: VolumeId::from_bytes([1; 16])?,
            sequence: 7,
            history_enabled: false,
            minimum_age: DurationMicros::new(10),
            maximum_age: Some(DurationMicros::new(20)),
            minimum_versions: Some(3),
            reclaim_mode: RetentionReclaimMode::AfterMaximumAge,
            soft_minimum_breakable: true,
            conflict_minimum_age: DurationMicros::new(30),
            configured_at: UnixMicros::new(40),
            revision: Revision::new(50),
        };
        let expected = VersionRetentionSelectionPolicy::new(
            7,
            DurationMicros::new(10),
            Some(DurationMicros::new(20)),
            Some(3),
            VersionReclaimMode::AfterMaximumAge,
            true,
            DurationMicros::new(30),
        )?;
        assert_eq!(version_retention_selection_policy(source)?, expected);
        Ok(())
    }
}
