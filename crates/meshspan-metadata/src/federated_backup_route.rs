// SPDX-License-Identifier: GPL-2.0-only

//! Consumer-owned routing intent, distinct from provider-confirmed backup copies.

use meshspan_contracts::{BackupObjectIdentity, FederatedBackupScope};
use meshspan_domain::Revision;

/// Fixes the remote namespace before sending any bytes for one backup copy.
///
/// The provider still authenticates every operation against its current authority.
/// This local consensus record cannot grant remote access or prove storage/durability.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BindFederatedBackupRoute {
    /// Exact immutable encrypted object and consumer destination generation.
    pub object: BackupObjectIdentity,
    /// Signed-discovery scope originally selected for this copy.
    pub scope: FederatedBackupScope,
    /// Current local schedule worker; required before admitting a new route.
    pub claim: crate::MetadataBackupRunClaim,
    /// Exact active destination revision authorising this selection.
    pub expected_destination_revision: Revision,
}

/// Immutable route retained through worker replacement, failed IO and later copy retirement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederatedBackupRouteRecord {
    /// Original routing intent. Its foreign revisions are observations, not enduring authority.
    pub binding: BindFederatedBackupRoute,
    /// First authoritative binding revision; not a provider storage receipt.
    pub revision: Revision,
}
