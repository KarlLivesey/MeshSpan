// SPDX-License-Identifier: GPL-2.0-only

//! Deterministic connector-neutral namespace access evaluation.

mod authority;
mod grants;
pub(super) mod subjects;

use std::collections::{BTreeMap, BTreeSet};

use meshspan_domain::{
    ApiKeyId, AssuranceLevel, AuthenticationService, GrantId, NodeId, ObjectId, PrincipalId,
    Revision, Rights, SessionId, UnixMicros, VolumeId,
};
use sha2::{Digest, Sha256};

use super::RepositoryError;
use crate::PartitionDatabase;

pub(super) const DEFINED_RIGHTS: usize = 13;

/// Authenticated, gateway-bound request for one exact namespace object.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessRequest {
    /// Connector family against which the credential must be validated.
    pub authentication_service: AuthenticationService,
    /// Digest of the presented session or API-key secret; raw bytes remain outside metadata.
    pub credential_digest: [u8; 32],
    /// Minimum assurance required by this operation class.
    pub required_assurance: AssuranceLevel,
    /// Gateway executing the authorised operation.
    pub gateway_node_id: NodeId,
    /// Exact live process incarnation presented by that gateway.
    pub gateway_incarnation: u64,
    /// Exact containing volume.
    pub volume_id: VolumeId,
    /// Exact target object.
    pub object_id: ObjectId,
    /// Non-empty protocol-neutral rights required atomically.
    pub requested_rights: Rights,
    /// Authoritative mesh time used for every window decision.
    pub now: UnixMicros,
}

/// Stable internal denial classes; connectors map them to non-disclosing protocol errors.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessDenial {
    /// No current committed authentication matches the supplied service and digest.
    AuthenticationUnavailable,
    /// The session does not prove the operation's required assurance.
    InsufficientAssurance,
    /// The named gateway incarnation is not currently active.
    GatewayUnavailable,
    /// The target is absent, retired or belongs to another volume.
    ObjectUnavailable,
    /// Applicable owner and allow-grant sources do not contain every requested right.
    MissingRights,
}

/// Public identity of the exact committed authentication used by an access decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessAuthentication {
    /// Replicated interactive session.
    Session(SessionId),
    /// Direct scoped API key, revalidated at operation time.
    ApiKey(ApiKeyId),
}

/// One bounded capability input, tied to every mutable authority used by the decision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AccessCapability {
    /// Exact authentication authority used for this decision.
    pub authentication: AccessAuthentication,
    /// Connector family against which that authority was validated.
    pub authentication_service: AuthenticationService,
    /// User receiving authority.
    pub principal_id: PrincipalId,
    /// Gateway to which this decision is fenced.
    pub gateway_node_id: NodeId,
    /// Exact live process incarnation of the gateway.
    pub gateway_incarnation: u64,
    /// Target volume.
    pub volume_id: VolumeId,
    /// Target object.
    pub object_id: ObjectId,
    /// Rights required by the operation.
    pub requested_rights: Rights,
    /// Complete rights available at evaluation time.
    pub effective_rights: Rights,
    /// Current identity, group and ACL revision.
    pub identity_revision: Revision,
    /// Current namespace authority revision.
    pub namespace_revision: Revision,
    /// Exact target object revision.
    pub object_revision: Revision,
    /// Exact gateway record revision.
    pub gateway_revision: Revision,
    /// Exclusive expiry, never later than the session or a required source.
    pub expires_at: UnixMicros,
    /// Canonical digest over every field above.
    pub capability_digest: [u8; 32],
}

/// Complete outcome of one access evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessDecision {
    /// Every requested right is present and bound into a capability input.
    Granted(AccessCapability),
    /// The request is not authorised at the committed projection.
    Denied(AccessDenial),
}

#[derive(Clone, Copy)]
pub(super) struct AuthenticatedPrincipal {
    authentication: AccessAuthentication,
    principal_id: PrincipalId,
    factor_state: super::session::SessionFactorState,
    identity_revision: Revision,
    expires_at: UnixMicros,
}

#[derive(Clone, Copy)]
pub(super) struct Target {
    object_revision: Revision,
    owner_set_id: [u8; 16],
    is_root: bool,
    inherits_volume_grants: bool,
}

#[derive(Clone, Copy)]
pub(super) struct AuthorityRevisions {
    identity: Revision,
    namespace: Revision,
    gateway: Revision,
}

#[derive(Clone, Copy)]
pub(super) struct GrantEvaluation<'a> {
    request: AccessRequest,
    principal_id: PrincipalId,
    target_is_root: bool,
    inherits_volume_grants: bool,
    ancestors: &'a BTreeSet<ObjectId>,
    subjects: &'a BTreeMap<PrincipalId, Option<UnixMicros>>,
    activations: &'a BTreeMap<GrantId, UnixMicros>,
}

#[derive(Clone, Copy, Default)]
pub(super) struct RightLifetime {
    present: bool,
    expires_at: Option<UnixMicros>,
}

pub(super) fn evaluate(
    database: &PartitionDatabase,
    request: AccessRequest,
) -> Result<AccessDecision, RepositoryError> {
    if request.requested_rights == Rights::default() || request.gateway_incarnation == 0 {
        return Ok(AccessDecision::Denied(AccessDenial::MissingRights));
    }
    let revisions = authority::load_authority_revisions(database, request)?;
    let Some(authentication) =
        authority::load_authentication(database, request, revisions.identity)?
    else {
        return Ok(AccessDecision::Denied(
            AccessDenial::AuthenticationUnavailable,
        ));
    };
    if !super::session::meets_assurance(
        database.connection(),
        authentication.factor_state,
        request.required_assurance,
        request.now,
    )? {
        return Ok(AccessDecision::Denied(AccessDenial::InsufficientAssurance));
    }
    if revisions.gateway == Revision::ZERO {
        return Ok(AccessDecision::Denied(AccessDenial::GatewayUnavailable));
    }
    let Some((target, ancestors)) = authority::load_target_and_ancestors(database, request)? else {
        return Ok(AccessDecision::Denied(AccessDenial::ObjectUnavailable));
    };
    let group_activations =
        subjects::load_group_activations(database, authentication, request.now)?;
    let effective_subjects = subjects::load_effective_subjects(
        database,
        authentication,
        request.now,
        &group_activations,
    )?;
    let grant_activations = grants::load_grant_activations(database, authentication, request.now)?;
    let mut rights = [RightLifetime::default(); DEFINED_RIGHTS];
    grants::apply_ownership(
        database,
        target.owner_set_id,
        &effective_subjects,
        &mut rights,
    )?;
    grants::apply_grants(
        database,
        GrantEvaluation {
            request,
            principal_id: authentication.principal_id,
            target_is_root: target.is_root,
            inherits_volume_grants: target.inherits_volume_grants,
            ancestors: &ancestors,
            subjects: &effective_subjects,
            activations: &grant_activations,
        },
        &mut rights,
    )?;
    build_decision(request, authentication, target, revisions, &rights)
}

fn build_decision(
    request: AccessRequest,
    authentication: AuthenticatedPrincipal,
    target: Target,
    revisions: AuthorityRevisions,
    rights: &[RightLifetime; DEFINED_RIGHTS],
) -> Result<AccessDecision, RepositoryError> {
    let mut effective_bits = 0_u32;
    let mut expires_at = authentication.expires_at;
    for (index, lifetime) in rights.iter().enumerate() {
        let bit = 1_u32 << index;
        if lifetime.present {
            effective_bits |= bit;
        }
        if request.requested_rights.bits() & bit != 0 {
            if !lifetime.present {
                return Ok(AccessDecision::Denied(AccessDenial::MissingRights));
            }
            if let Some(source_expiry) = lifetime.expires_at {
                expires_at = expires_at.min(source_expiry);
            }
        }
    }
    if expires_at <= request.now {
        return Ok(AccessDecision::Denied(AccessDenial::MissingRights));
    }
    let effective_rights =
        Rights::from_bits(effective_bits).map_err(|_| RepositoryError::CorruptState)?;
    let mut capability = AccessCapability {
        authentication: authentication.authentication,
        authentication_service: request.authentication_service,
        principal_id: authentication.principal_id,
        gateway_node_id: request.gateway_node_id,
        gateway_incarnation: request.gateway_incarnation,
        volume_id: request.volume_id,
        object_id: request.object_id,
        requested_rights: request.requested_rights,
        effective_rights,
        identity_revision: revisions.identity,
        namespace_revision: revisions.namespace,
        object_revision: target.object_revision,
        gateway_revision: revisions.gateway,
        expires_at,
        capability_digest: [0; 32],
    };
    capability.capability_digest = capability_digest(capability);
    Ok(AccessDecision::Granted(capability))
}

pub(super) fn contribute(
    lifetimes: &mut [RightLifetime; DEFINED_RIGHTS],
    rights: Rights,
    expires_at: Option<UnixMicros>,
) {
    for (index, lifetime) in lifetimes.iter_mut().enumerate() {
        if rights.bits() & (1_u32 << index) == 0 {
            continue;
        }
        if !lifetime.present || extends_expiry(lifetime.expires_at, expires_at) {
            *lifetime = RightLifetime {
                present: true,
                expires_at,
            };
        }
    }
}

fn extends_expiry(current: Option<UnixMicros>, candidate: Option<UnixMicros>) -> bool {
    match (current, candidate) {
        (Some(old), Some(new)) => new > old,
        (Some(_), None) => true,
        _ => false,
    }
}

fn capability_digest(capability: AccessCapability) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.access-capability.v2");
    match capability.authentication {
        AccessAuthentication::Session(session_id) => {
            digest.update([1]);
            digest.update(session_id.as_bytes());
        }
        AccessAuthentication::ApiKey(key_id) => {
            digest.update([2]);
            digest.update(key_id.as_bytes());
        }
    }
    digest.update([capability.authentication_service.scope_bit()]);
    digest.update(capability.principal_id.as_bytes());
    digest.update(capability.gateway_node_id.as_bytes());
    digest.update(capability.gateway_incarnation.to_be_bytes());
    digest.update(capability.volume_id.as_bytes());
    digest.update(capability.object_id.as_bytes());
    digest.update(capability.requested_rights.bits().to_be_bytes());
    digest.update(capability.effective_rights.bits().to_be_bytes());
    digest.update(capability.identity_revision.get().to_be_bytes());
    digest.update(capability.namespace_revision.get().to_be_bytes());
    digest.update(capability.object_revision.get().to_be_bytes());
    digest.update(capability.gateway_revision.get().to_be_bytes());
    digest.update(capability.expires_at.get().to_be_bytes());
    digest.finalize().into()
}
