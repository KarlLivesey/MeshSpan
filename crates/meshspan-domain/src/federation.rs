// SPDX-License-Identifier: GPL-2.0-only

//! Federation-qualified principals, resource scopes and bilateral policy intersection.

use thiserror::Error;

use crate::{DurationMicros, MeshId, ObjectId, PrincipalId, Rights, VolumeId};

const THIRTY_DAYS_MICROS: u64 = 30 * 24 * 60 * 60 * 1_000_000;

/// Ordinary default for how long a disconnected peer may use a renewed grant.
pub const DEFAULT_FEDERATION_OFFLINE_DURATION: DurationMicros =
    DurationMicros::new(THIRTY_DAYS_MICROS);

/// A principal identity qualified by the autonomous swarm which authenticates it.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct FederatedPrincipal {
    home_mesh_id: MeshId,
    principal_id: PrincipalId,
}

impl FederatedPrincipal {
    /// Constructs one globally qualified principal identity.
    #[must_use]
    pub const fn new(home_mesh_id: MeshId, principal_id: PrincipalId) -> Self {
        Self {
            home_mesh_id,
            principal_id,
        }
    }

    /// Returns the swarm responsible for authenticating this principal.
    #[must_use]
    pub const fn home_mesh_id(self) -> MeshId {
        self.home_mesh_id
    }

    /// Returns the stable principal identity inside the home swarm.
    #[must_use]
    pub const fn principal_id(self) -> PrincipalId {
        self.principal_id
    }
}

/// Exact owner-qualified resource selected by one federation grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederationResourceScope {
    /// Every object in one volume.
    Volume {
        /// Swarm which owns the volume's ACL and canonical history.
        owner_mesh_id: MeshId,
        /// Shared volume.
        volume_id: VolumeId,
    },
    /// One folder and its descendants.
    Subtree {
        /// Swarm which owns the subtree's ACL and canonical history.
        owner_mesh_id: MeshId,
        /// Volume containing the folder.
        volume_id: VolumeId,
        /// Stable root folder identity.
        root_object_id: ObjectId,
    },
    /// One individual file.
    File {
        /// Swarm which owns the file's ACL and canonical history.
        owner_mesh_id: MeshId,
        /// Volume containing the file.
        volume_id: VolumeId,
        /// Stable file identity.
        object_id: ObjectId,
    },
    /// Bounded storage supplied by a provider swarm without namespace authority.
    StorageCapacity {
        /// Swarm whose storage targets provide the capacity.
        provider_mesh_id: MeshId,
    },
}

impl FederationResourceScope {
    /// Returns the swarm which owns or provides this exact resource.
    #[must_use]
    pub const fn authority_mesh_id(self) -> MeshId {
        match self {
            Self::Volume { owner_mesh_id, .. }
            | Self::Subtree { owner_mesh_id, .. }
            | Self::File { owner_mesh_id, .. } => owner_mesh_id,
            Self::StorageCapacity { provider_mesh_id } => provider_mesh_id,
        }
    }
}

/// Simple appliance presets expanded into exact rights before persistence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederationPreset {
    /// Discover, list and read the selected resource.
    View,
    /// View plus create, modify, rename and delete content.
    Edit,
    /// Every filesystem right plus permission and resharing administration.
    Manage,
}

/// Exact namespace and resharing authority after preset expansion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationAccess {
    rights: Rights,
    manage_sharing: bool,
}

impl FederationAccess {
    /// Expands one ordinary preset into its complete stored authority.
    #[must_use]
    pub const fn from_preset(preset: FederationPreset) -> Self {
        match preset {
            FederationPreset::View => Self {
                rights: Rights::TRAVERSE
                    .union(Rights::LIST)
                    .union(Rights::READ_DATA)
                    .union(Rights::READ_ATTRIBUTES),
                manage_sharing: false,
            },
            FederationPreset::Edit => Self {
                rights: Rights::TRAVERSE
                    .union(Rights::LIST)
                    .union(Rights::READ_DATA)
                    .union(Rights::CREATE_CHILD)
                    .union(Rights::WRITE_DATA)
                    .union(Rights::APPEND_DATA)
                    .union(Rights::RENAME)
                    .union(Rights::DELETE)
                    .union(Rights::READ_ATTRIBUTES)
                    .union(Rights::WRITE_ATTRIBUTES),
                manage_sharing: false,
            },
            FederationPreset::Manage => Self {
                rights: Rights::ALL,
                manage_sharing: true,
            },
        }
    }

    /// Constructs an advanced exact authority without storing a preset label.
    #[must_use]
    pub const fn new(rights: Rights, manage_sharing: bool) -> Self {
        Self {
            rights,
            manage_sharing,
        }
    }

    /// Returns protocol-neutral filesystem rights.
    #[must_use]
    pub const fn rights(self) -> Rights {
        self.rights
    }

    /// Reports whether this authority may grant the resource to another swarm.
    #[must_use]
    pub const fn may_manage_sharing(self) -> bool {
        self.manage_sharing
    }

    /// Applies two independent restrictions without allowing either to broaden the other.
    #[must_use]
    pub const fn intersection(self, other: Self) -> Self {
        Self {
            rights: self.rights.intersection(other.rights),
            manage_sharing: self.manage_sharing && other.manage_sharing,
        }
    }
}

/// Whether remote shards contribute to protection and may serve ordinary reads.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct StorageParticipation {
    counts_towards_protection: bool,
    serves_reads: bool,
}

impl StorageParticipation {
    /// Constructs independent protection and serving classifications.
    #[must_use]
    pub const fn new(counts_towards_protection: bool, serves_reads: bool) -> Self {
        Self {
            counts_towards_protection,
            serves_reads,
        }
    }

    /// Reports whether verified remote shards count towards protection placement.
    #[must_use]
    pub const fn counts_towards_protection(self) -> bool {
        self.counts_towards_protection
    }

    /// Reports whether ordinary reads may query this remote storage.
    #[must_use]
    pub const fn serves_reads(self) -> bool {
        self.serves_reads
    }

    const fn intersection(self, other: Self) -> Self {
        Self {
            counts_towards_protection: self.counts_towards_protection
                && other.counts_towards_protection,
            serves_reads: self.serves_reads && other.serves_reads,
        }
    }
}

/// Exact namespace restrictions imposed by one side of a federation relationship.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NamespaceFederationPolicy {
    access: FederationAccess,
    maximum_offline_duration: Option<DurationMicros>,
}

impl NamespaceFederationPolicy {
    /// Constructs namespace authority independently of remote-storage participation.
    #[must_use]
    pub const fn new(
        access: FederationAccess,
        maximum_offline_duration: Option<DurationMicros>,
    ) -> Self {
        Self {
            access,
            maximum_offline_duration,
        }
    }

    /// Returns the exact effective namespace and sharing authority.
    #[must_use]
    pub const fn access(self) -> FederationAccess {
        self.access
    }

    /// Returns the maximum disconnected duration, or `None` for explicit indefinite access.
    #[must_use]
    pub const fn maximum_offline_duration(self) -> Option<DurationMicros> {
        self.maximum_offline_duration
    }

    const fn intersection(self, other: Self) -> Self {
        Self {
            access: self.access.intersection(other.access),
            maximum_offline_duration: earliest_duration(
                self.maximum_offline_duration,
                other.maximum_offline_duration,
            ),
        }
    }
}

/// Exact remote-storage restrictions imposed by one side of a federation relationship.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageFederationPolicy {
    maximum_storage_bytes: u64,
    participation: StorageParticipation,
    maximum_offline_duration: Option<DurationMicros>,
}

impl StorageFederationPolicy {
    /// Constructs remote-storage authority independently of namespace access.
    ///
    /// # Errors
    ///
    /// Rejects zero usable capacity.
    pub const fn new(
        maximum_storage_bytes: u64,
        participation: StorageParticipation,
        maximum_offline_duration: Option<DurationMicros>,
    ) -> Result<Self, FederationPolicyError> {
        if maximum_storage_bytes == 0 {
            return Err(FederationPolicyError::InvalidStorage);
        }
        Ok(Self {
            maximum_storage_bytes,
            participation,
            maximum_offline_duration,
        })
    }

    /// Returns the maximum remote capacity permitted by every side.
    #[must_use]
    pub const fn maximum_storage_bytes(self) -> u64 {
        self.maximum_storage_bytes
    }

    /// Returns the effective protection and ordinary-read classifications.
    #[must_use]
    pub const fn participation(self) -> StorageParticipation {
        self.participation
    }

    /// Returns the maximum disconnected duration, or `None` for explicit indefinite access.
    #[must_use]
    pub const fn maximum_offline_duration(self) -> Option<DurationMicros> {
        self.maximum_offline_duration
    }

    const fn intersection(self, other: Self) -> Self {
        let maximum_storage_bytes = if self.maximum_storage_bytes <= other.maximum_storage_bytes {
            self.maximum_storage_bytes
        } else {
            other.maximum_storage_bytes
        };
        Self {
            maximum_storage_bytes,
            participation: self.participation.intersection(other.participation),
            maximum_offline_duration: earliest_duration(
                self.maximum_offline_duration,
                other.maximum_offline_duration,
            ),
        }
    }
}

/// One side's typed upper bound on a namespace share or remote-storage grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FederationPolicy {
    /// Permissions over a volume, subtree or file.
    Namespace(NamespaceFederationPolicy),
    /// Capacity supplied without namespace authority.
    Storage(StorageFederationPolicy),
}

impl FederationPolicy {
    /// Intersects owner, governing, consuming and principal restrictions.
    ///
    /// # Errors
    ///
    /// Rejects an absent chain or a mix of namespace and storage policy kinds.
    pub fn intersect(policies: &[Self]) -> Result<Self, FederationPolicyError> {
        let Some((first, remaining)) = policies.split_first() else {
            return Err(FederationPolicyError::MissingRestriction);
        };
        remaining
            .iter()
            .try_fold(*first, |effective, next| match (effective, *next) {
                (Self::Namespace(left), Self::Namespace(right)) => {
                    Ok(Self::Namespace(left.intersection(right)))
                }
                (Self::Storage(left), Self::Storage(right)) => {
                    Ok(Self::Storage(left.intersection(right)))
                }
                _ => Err(FederationPolicyError::IncompatibleKinds),
            })
    }

    /// Returns the maximum disconnected duration for either policy kind.
    #[must_use]
    pub const fn maximum_offline_duration(self) -> Option<DurationMicros> {
        match self {
            Self::Namespace(policy) => policy.maximum_offline_duration(),
            Self::Storage(policy) => policy.maximum_offline_duration(),
        }
    }
}

/// Invalid federation policy construction or intersection.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FederationPolicyError {
    /// At least one policy is required so absence cannot manufacture authority.
    #[error("federation policy requires at least one restriction")]
    MissingRestriction,
    /// Namespace and storage restrictions cannot be intersected into invented authority.
    #[error("federation policy kinds are incompatible")]
    IncompatibleKinds,
    /// Remote storage authority requires non-zero usable capacity.
    #[error("federation storage capacity must be non-zero")]
    InvalidStorage,
}

const fn earliest_duration(
    left: Option<DurationMicros>,
    right: Option<DurationMicros>,
) -> Option<DurationMicros> {
    match (left, right) {
        (Some(left), Some(right)) => {
            if left.get() <= right.get() {
                Some(left)
            } else {
                Some(right)
            }
        }
        (Some(duration), None) | (None, Some(duration)) => Some(duration),
        (None, None) => None,
    }
}

#[cfg(test)]
#[path = "federation_tests.rs"]
mod tests;
