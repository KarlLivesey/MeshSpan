// SPDX-License-Identifier: GPL-2.0-only

//! Fresh local admission facts from the existing authority owner, without reopening its store.

use meshspan_domain::{MeshId, NodeId, PartitionId};
use meshspan_metadata::{
    ActiveNodeCertificate, JoinRoles, NodeCertificateRotation, StorageTargetRegistrationContext,
};
use tokio::sync::oneshot;

use super::{
    AuthorityEvent, MetadataAuthorityHandle, MetadataAuthorityRequestError,
    MetadataAuthorityRuntime,
};

/// Selects the bounded evidence required by one private control operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MetadataPeerAdmissionPurpose {
    /// Identity admission around a separately established quorum read fence.
    ReadFence,
    /// Ordinary typed metadata command forwarding.
    Command,
    /// Attestation that this node installed its own staged certificate.
    CertificateInstallation,
}

/// Locally applied identity evidence; the caller must still validate its authenticated binding.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetadataPeerAdmissionState {
    /// Owning swarm, absent before bootstrap.
    pub mesh_id: Option<MeshId>,
    /// Partition served by this authority owner.
    pub partition_id: PartitionId,
    /// Current active certificate, absent for a retired or unknown node.
    pub certificate: Option<ActiveNodeCertificate>,
    /// Evidence restricted to the requested operation family.
    pub details: MetadataPeerAdmissionDetails,
}

/// Operation-specific facts; none substitutes for current transport or command validation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MetadataPeerAdmissionDetails {
    /// No forwarding authority is requested.
    ReadFence,
    /// The current active plan and, when necessary, storage registration authority.
    Command {
        /// Whether the node belongs to the persisted active voting plan.
        is_voter: bool,
        /// Current registration authority for a storage-only sender.
        registration: Option<StorageTargetRegistrationContext>,
    },
    /// Current installation consent for the node's exact staged generation.
    CertificateInstallation {
        /// Active node and administrator authorising the installation.
        registration: Option<StorageTargetRegistrationContext>,
        /// Current staged or installed rotation record.
        rotation: Option<NodeCertificateRotation>,
    },
}

pub(super) struct PeerAdmissionRequest {
    pub node_id: NodeId,
    pub purpose: MetadataPeerAdmissionPurpose,
    pub respond: oneshot::Sender<Result<MetadataPeerAdmissionState, MetadataAuthorityRequestError>>,
}

impl MetadataAuthorityHandle {
    /// Reads fresh local admission facts through the existing bounded authority queue.
    ///
    /// This does not establish a quorum fence or cache authorization. The caller rechecks
    /// its current deadline and authenticated binding after receiving the result. Cancellation
    /// drops only a read response; queued cancelled reads perform no database work.
    ///
    /// # Errors
    /// Returns unavailable when ingress is full, the owner stops, a read fails or one second elapses.
    pub async fn peer_admission(
        &self,
        node_id: NodeId,
        purpose: MetadataPeerAdmissionPurpose,
    ) -> Result<MetadataPeerAdmissionState, MetadataAuthorityRequestError> {
        let (respond, response) = oneshot::channel();
        self.events
            .try_send(AuthorityEvent::PeerAdmission(PeerAdmissionRequest {
                node_id,
                purpose,
                respond,
            }))
            .map_err(|_| MetadataAuthorityRequestError::Unavailable)?;
        tokio::time::timeout(std::time::Duration::from_secs(1), response)
            .await
            .map_err(|_| MetadataAuthorityRequestError::Unavailable)?
            .map_err(|_| MetadataAuthorityRequestError::Unavailable)?
    }
}

impl MetadataAuthorityRuntime {
    pub(super) fn peer_admission(
        &self,
        node_id: NodeId,
        purpose: MetadataPeerAdmissionPurpose,
    ) -> Result<MetadataPeerAdmissionState, MetadataAuthorityRequestError> {
        let repository = self.driver.persistence();
        let unavailable = |_| MetadataAuthorityRequestError::Unavailable;
        let certificate = repository
            .active_node_certificate(node_id)
            .map_err(unavailable)?;
        let mesh_id = repository.local_mesh_id().map_err(unavailable)?;
        let details = match purpose {
            MetadataPeerAdmissionPurpose::ReadFence => MetadataPeerAdmissionDetails::ReadFence,
            MetadataPeerAdmissionPurpose::Command => {
                let plan = repository
                    .load_active_consensus_quorum_plan()
                    .map_err(|_| MetadataAuthorityRequestError::Unavailable)?
                    .ok_or(MetadataAuthorityRequestError::Unavailable)?;
                let is_voter = plan.voters().contains(&node_id);
                let registration = if certificate.as_ref().is_some_and(|certificate| {
                    !is_voter
                        && certificate.roles.bits() & JoinRoles::GATEWAY == 0
                        && certificate.roles.bits() & JoinRoles::STORAGE != 0
                }) {
                    repository
                        .storage_target_registration_context(node_id, super::now())
                        .map_err(unavailable)?
                } else {
                    None
                };
                MetadataPeerAdmissionDetails::Command {
                    is_voter,
                    registration,
                }
            }
            MetadataPeerAdmissionPurpose::CertificateInstallation => {
                MetadataPeerAdmissionDetails::CertificateInstallation {
                    registration: repository
                        .storage_target_registration_context(node_id, super::now())
                        .map_err(unavailable)?,
                    rotation: repository
                        .node_certificate_rotation(node_id)
                        .map_err(unavailable)?,
                }
            }
        };
        Ok(MetadataPeerAdmissionState {
            mesh_id,
            partition_id: repository.partition_id(),
            certificate,
            details,
        })
    }
}
