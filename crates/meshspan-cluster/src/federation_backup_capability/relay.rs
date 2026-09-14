// SPDX-License-Identifier: GPL-2.0-only

//! Owner-side authority for an independently authenticated relayed consumer operation.

use super::{AuthorisedFederatedBackup, FederationBackupCapabilityError, current_backup_authority};
use meshspan_contracts::ContractError;
use meshspan_data_plane::decode_federated_backup_permit;
use meshspan_domain::{NodeId, UnixMicros};
use meshspan_metadata::AuthoritativeRepository;
use meshspan_protocol::v1::federation_envelope::Message;
use meshspan_transport::AuthenticatedFederationBackupRelay;

/// Rechecks an authenticated relay at its exact storage owner without sharing gateway keys.
///
/// `routing_epoch` is the owner's currently active private-network route epoch, not a value
/// trusted from the request. The gateway checks its own permit MAC; this owner instead requires
/// the original consumer signature, current enrolled relay and independent bilateral authority.
/// This function reserves no bytes. Physical-folder and allocation admission must still precede
/// readiness, and callers must repeat this check at transfer and completion boundaries.
///
/// # Errors
/// Rejects wrong owner/partition/epoch, stale relay certificate/incarnation, expired request,
/// changed remote identity and revoked allocation/grant. All metadata checks share a short
/// read view; a subsequent transfer boundary opens a new view rather than retaining permission.
pub fn authorise_forwarded_backup(
    repository: &AuthoritativeRepository,
    owner: NodeId,
    routing_epoch: u64,
    relay: &AuthenticatedFederationBackupRelay,
    now: UnixMicros,
) -> Result<AuthorisedFederatedBackup, FederationBackupCapabilityError> {
    repository
        .with_read_view(|view| authorise_relay_in_view(view, owner, routing_epoch, relay, now))
        .map_err(|_| ContractError::Unavailable)?
}

fn authorise_relay_in_view(
    repository: &AuthoritativeRepository,
    owner: NodeId,
    routing_epoch: u64,
    relay: &AuthenticatedFederationBackupRelay,
    now: UnixMicros,
) -> Result<AuthorisedFederatedBackup, FederationBackupCapabilityError> {
    let header = relay
        .forwarded()
        .header
        .as_ref()
        .ok_or(ContractError::InvalidInput)?;
    let peer = relay.peer();
    let certificate = repository
        .active_node_certificate(peer.node_id())
        .map_err(|_| ContractError::Unavailable)?
        .ok_or(ContractError::Unauthorized)?;
    let mesh = repository
        .local_mesh_id()
        .map_err(|_| ContractError::Unavailable)?
        .ok_or(ContractError::Unauthorized)?;
    if header.mesh_id.as_slice() != mesh.as_bytes()
        || header.partition_id.as_slice() != repository.partition_id().as_bytes()
        || routing_epoch == 0
        || header.routing_epoch != routing_epoch
        || relay.forwarded().provider_node_id.as_slice() != owner.as_bytes()
        || certificate.incarnation != peer.incarnation()
        || certificate.certificate_fingerprint != peer.certificate_fingerprint()
        || certificate.valid_until <= now
    {
        return Err(ContractError::Unauthorized.into());
    }
    if header.deadline_unix_micros <= now.get() {
        return Err(ContractError::DeadlineExceeded.into());
    }
    let authenticated = relay.consumer();
    let Message::ExecuteBackup(execute) = authenticated.message() else {
        return Err(ContractError::InvalidInput.into());
    };
    let permit = decode_federated_backup_permit(
        execute.permit.as_ref().ok_or(ContractError::InvalidInput)?,
        now,
    )?;
    if permit.scope.provider_node_id != owner || permit.scope.provider_mesh_id != mesh {
        return Err(ContractError::Unauthorized.into());
    }
    let (authority, _) = current_backup_authority(
        repository,
        authenticated,
        permit.scope,
        &permit.request,
        now,
    )?;
    if permit.expires_at > authority.valid_until() {
        return Err(ContractError::Stale.into());
    }
    Ok(AuthorisedFederatedBackup { permit, authority })
}
