// SPDX-License-Identifier: GPL-2.0-only

//! Manager-authorised logical-volume creation over replicated metadata.

use axum::http::HeaderMap;
use axum::http::header::{AUTHORIZATION, COOKIE};
use meshspan_api_contract::{CreateVolumeRequest, CreateVolumeResponse};
use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    AuditEventId, ObjectId, OperationId, OwnerSetId, PrincipalId, RandomSource, UnixMicros,
    VolumeId, uuid_v8,
};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CommitSecretGeneration, CreateVolume, RecordName,
    VOLUME_CONTENT_KEY_SECRET_KIND, VolumeInventoryRecord,
};
use meshspan_secret_envelope::{SecretContext, WrappingPublicKey, encrypt_secret};
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroizing;

use crate::create_mesh_setup::parse_uuid;
use crate::{
    BrowserRequestProtection, BrowserSessionAuthenticator, BrowserSessionAuthority,
    FileApiAuthenticationError, GatewaySessionIdentity, IdentityAdministrator,
    NativeApiKeyAuthenticator, NativeApiKeyAuthority,
};

const VOLUME_ID_DOMAIN: &[u8] = b"meshspan.volume-administration.volume-id.v1\0";
const ROOT_ID_DOMAIN: &[u8] = b"meshspan.volume-administration.root-id.v1\0";
const OWNER_SET_ID_DOMAIN: &[u8] = b"meshspan.volume-administration.owner-set-id.v1\0";
const AUDIT_ID_DOMAIN: &[u8] = b"meshspan.volume-administration.audit-id.v1\0";
const INITIAL_KEY_GENERATION: u64 = 1;
const VOLUME_CONTENT_KEY_BYTES: usize = 32;

/// Exact durable evidence returned for one volume creation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VolumeAdministrationCommit {
    /// Canonical request digest accepted by consensus.
    pub request_digest: [u8; 32],
    /// Non-zero durable result digest.
    pub result_digest: [u8; 32],
    /// Created logical volume.
    pub record: VolumeInventoryRecord,
    /// Exact canonical initial owner set retained with the created root object.
    pub owners: Vec<PrincipalId>,
}

/// Replicated reads and consensus mutation needed by volume administration.
pub trait VolumeAdministrationAuthority: BrowserSessionAuthority + NativeApiKeyAuthority {
    /// Reports current system-manager authority.
    ///
    /// # Errors
    ///
    /// Fails closed when the current role projection cannot be trusted.
    fn is_system_manager(
        &self,
        principal_id: PrincipalId,
        now: UnixMicros,
    ) -> Result<bool, VolumeAdministrationAuthorityError>;

    /// Resolves one prior volume-creation operation.
    ///
    /// # Errors
    ///
    /// Rejects another command family or malformed retained evidence.
    fn resolve_volume_creation(
        &self,
        operation_id: OperationId,
    ) -> Result<Option<VolumeAdministrationCommit>, VolumeAdministrationAuthorityError>;

    /// Returns current gateway wrapping keys plus the verified offline recovery key.
    ///
    /// # Errors
    ///
    /// Fails closed when the complete recoverable recipient set cannot be trusted.
    fn volume_key_recipients(
        &self,
    ) -> Result<Vec<WrappingPublicKey>, VolumeAdministrationAuthorityError>;

    /// Commits or exactly resolves one volume creation through consensus.
    ///
    /// # Errors
    ///
    /// Rejects changed operation reuse and never invents success from transport outcome.
    fn commit_or_resolve_volume_creation(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<VolumeAdministrationCommit, VolumeAdministrationAuthorityError>;
}

/// Synchronous manager-only volume controller.
pub trait VolumeAdministrationController: Send + 'static {
    /// Authenticates before the HTTP boundary consumes a request body.
    ///
    /// # Errors
    ///
    /// Rejects missing, ambiguous, stale or insufficient credentials and unavailable authority.
    fn authenticate(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, VolumeAdministrationError>;

    /// Creates or exactly replays one logical volume.
    ///
    /// # Errors
    ///
    /// Rejects invalid names/owners, conflicting reuse and untrustworthy committed evidence.
    fn create_volume(
        &mut self,
        administrator: IdentityAdministrator,
        request: CreateVolumeRequest,
    ) -> Result<CreateVolumeResponse, VolumeAdministrationError>;
}

/// Complete volume-administration application service.
pub struct VolumeAdministrationService<A, R> {
    authority: A,
    gateway: GatewaySessionIdentity,
    random: R,
}

impl<A, R> VolumeAdministrationService<A, R> {
    /// Binds manager authentication and replicated volume authority to one gateway.
    #[must_use]
    pub const fn new(authority: A, gateway: GatewaySessionIdentity, random: R) -> Self {
        Self {
            authority,
            gateway,
            random,
        }
    }
}

impl<A, R> VolumeAdministrationController for VolumeAdministrationService<A, R>
where
    A: VolumeAdministrationAuthority + Send + 'static,
    R: RandomSource + Send + 'static,
{
    fn authenticate(
        &self,
        headers: &HeaderMap,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, VolumeAdministrationError> {
        let has_authorization = headers.contains_key(AUTHORIZATION);
        if has_authorization && headers.contains_key(COOKIE) {
            return Err(VolumeAdministrationError::Unauthenticated);
        }
        let principal_id = if has_authorization {
            NativeApiKeyAuthenticator::new(&self.authority, self.gateway)
                .authenticate_principal(headers, now)
                .map_err(map_file_authentication_error)?
        } else {
            BrowserSessionAuthenticator::new(&self.authority, self.gateway)
                .authenticate(
                    headers,
                    BrowserRequestProtection::Mutation,
                    meshspan_domain::AssuranceLevel::SingleFactor,
                    now,
                )
                .map_err(|error| match error {
                    crate::BrowserAuthenticationError::Rejected => {
                        VolumeAdministrationError::Unauthenticated
                    }
                    crate::BrowserAuthenticationError::Authority(
                        crate::BrowserSessionAuthorityError::Unavailable,
                    ) => VolumeAdministrationError::Unavailable,
                    crate::BrowserAuthenticationError::InvalidGateway
                    | crate::BrowserAuthenticationError::Authority(
                        crate::BrowserSessionAuthorityError::Failed,
                    ) => VolumeAdministrationError::Failed,
                })?
                .principal_id
        };
        if !self
            .authority
            .is_system_manager(principal_id, now)
            .map_err(map_authority_error)?
        {
            return Err(VolumeAdministrationError::Forbidden);
        }
        Ok(IdentityAdministrator { principal_id, now })
    }

    fn create_volume(
        &mut self,
        administrator: IdentityAdministrator,
        request: CreateVolumeRequest,
    ) -> Result<CreateVolumeResponse, VolumeAdministrationError> {
        let operation_id = domain_operation(&request.operation_id)?;
        let volume_id = derived_id::<VolumeId>(VOLUME_ID_DOMAIN, operation_id)?;
        let root_object_id = derived_id::<ObjectId>(ROOT_ID_DOMAIN, operation_id)?;
        let owner_set_id = derived_id::<OwnerSetId>(OWNER_SET_ID_DOMAIN, operation_id)?;
        let name = RecordName::new(request.name.as_str())
            .map_err(|_| VolumeAdministrationError::InvalidInput)?;
        let mut owners = request
            .owner_principal_ids
            .iter()
            .map(domain_principal)
            .collect::<Result<Vec<_>, _>>()?;
        owners.sort_unstable();
        if owners.is_empty() || owners.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(VolumeAdministrationError::InvalidInput);
        }
        let existing = self
            .authority
            .resolve_volume_creation(operation_id)
            .map_err(map_authority_error)?;
        if let Some(commit) = existing {
            validate_commit(&commit, volume_id, root_object_id, &name, &owners, None)?;
            return create_response(request.operation_id, commit);
        }
        let recipients = self
            .authority
            .volume_key_recipients()
            .map_err(map_authority_error)?;
        let key_generation = Box::new(initial_key_generation(
            volume_id,
            &recipients,
            &mut self.random,
        )?);
        let command = AuthoritativeCommand::CreateVolume(CreateVolume {
            volume_id,
            name,
            root_object_id,
            owner_set_id,
            owners: BoundedItems::new(owners.clone(), 1_024)
                .map_err(|_| VolumeAdministrationError::InvalidInput)?,
            key_generation,
        });
        let context = command_context(operation_id, administrator, administrator.now)?;
        let expected_digest = command.request_digest(context);
        let (commit, exact_request_digest) = match self
            .authority
            .commit_or_resolve_volume_creation(context, &command)
        {
            Ok(commit) => (commit, Some(expected_digest)),
            Err(commit_error) => {
                let resolved = self
                    .authority
                    .resolve_volume_creation(operation_id)
                    .map_err(map_authority_error)?;
                match resolved {
                    Some(commit) => (commit, None),
                    None => return Err(map_authority_error(commit_error)),
                }
            }
        };
        validate_commit(
            &commit,
            volume_id,
            root_object_id,
            match &command {
                AuthoritativeCommand::CreateVolume(value) => &value.name,
                _ => return Err(VolumeAdministrationError::Failed),
            },
            &owners,
            exact_request_digest,
        )?;
        create_response(request.operation_id, commit)
    }
}

fn initial_key_generation(
    volume_id: VolumeId,
    recipients: &[WrappingPublicKey],
    random: &mut impl RandomSource,
) -> Result<CommitSecretGeneration, VolumeAdministrationError> {
    let mut key = Zeroizing::new([0_u8; VOLUME_CONTENT_KEY_BYTES]);
    random
        .fill_bytes(key.as_mut())
        .map_err(|_| VolumeAdministrationError::Unavailable)?;
    let context = SecretContext::new(
        VOLUME_CONTENT_KEY_SECRET_KIND,
        volume_id.as_bytes(),
        INITIAL_KEY_GENERATION,
    )
    .map_err(|_| VolumeAdministrationError::Failed)?;
    let (secret, envelopes) = encrypt_secret(context, key.as_ref(), recipients, random)
        .map_err(|_| VolumeAdministrationError::Unavailable)?;
    Ok(CommitSecretGeneration {
        secret: secret.parts(),
        recipients: envelopes
            .into_iter()
            .map(|envelope| envelope.parts())
            .collect(),
    })
}

fn validate_commit(
    commit: &VolumeAdministrationCommit,
    volume_id: VolumeId,
    root_object_id: ObjectId,
    name: &RecordName,
    owners: &[PrincipalId],
    expected_digest: Option<[u8; 32]>,
) -> Result<(), VolumeAdministrationError> {
    if expected_digest.is_some_and(|digest| commit.request_digest != digest)
        || commit.request_digest == [0; 32]
        || commit.result_digest == [0; 32]
        || commit.record.volume_id != volume_id
        || commit.record.root_object_id != root_object_id
        || commit.record.display_name != name.display()
        || commit.record.canonical_name != name.canonical()
        || commit.owners != owners
    {
        Err(VolumeAdministrationError::Conflict)
    } else {
        Ok(())
    }
}

fn create_response(
    operation_id: meshspan_api_contract::OperationId,
    commit: VolumeAdministrationCommit,
) -> Result<CreateVolumeResponse, VolumeAdministrationError> {
    let owner_principal_ids = commit
        .owners
        .into_iter()
        .map(|owner| {
            meshspan_api_contract::PrincipalId::from_uuid_bytes(owner.as_bytes())
                .ok_or(VolumeAdministrationError::Failed)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(CreateVolumeResponse {
        operation_id,
        volume_id: meshspan_api_contract::VolumeId::from_uuid_bytes(
            commit.record.volume_id.as_bytes(),
        )
        .ok_or(VolumeAdministrationError::Failed)?,
        root_object_id: meshspan_api_contract::ObjectId::from_uuid_bytes(
            commit.record.root_object_id.as_bytes(),
        )
        .ok_or(VolumeAdministrationError::Failed)?,
        name: commit.record.display_name,
        owner_principal_ids,
        created_at_epoch_micros: commit.record.created_at.get(),
        revision: commit.record.revision.get(),
    })
}

trait DerivedIdentifier: Sized {
    fn from_derived_bytes(bytes: [u8; 16]) -> Result<Self, meshspan_domain::IdentifierError>;
}

impl DerivedIdentifier for VolumeId {
    fn from_derived_bytes(bytes: [u8; 16]) -> Result<Self, meshspan_domain::IdentifierError> {
        Self::from_bytes(bytes)
    }
}

impl DerivedIdentifier for ObjectId {
    fn from_derived_bytes(bytes: [u8; 16]) -> Result<Self, meshspan_domain::IdentifierError> {
        Self::from_bytes(bytes)
    }
}

impl DerivedIdentifier for OwnerSetId {
    fn from_derived_bytes(bytes: [u8; 16]) -> Result<Self, meshspan_domain::IdentifierError> {
        Self::from_bytes(bytes)
    }
}

fn derived_id<T: DerivedIdentifier>(
    domain: &[u8],
    operation_id: OperationId,
) -> Result<T, VolumeAdministrationError> {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(operation_id.as_bytes());
    let bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .map(uuid_v8)
        .map_err(|_| VolumeAdministrationError::Failed)?;
    T::from_derived_bytes(bytes).map_err(|_| VolumeAdministrationError::Failed)
}

fn domain_operation(
    value: &meshspan_api_contract::OperationId,
) -> Result<OperationId, VolumeAdministrationError> {
    OperationId::from_bytes(
        parse_uuid(value.as_str()).map_err(|_| VolumeAdministrationError::InvalidInput)?,
    )
    .map_err(|_| VolumeAdministrationError::InvalidInput)
}

fn domain_principal(
    value: &meshspan_api_contract::PrincipalId,
) -> Result<PrincipalId, VolumeAdministrationError> {
    PrincipalId::from_bytes(
        parse_uuid(value.as_str()).map_err(|_| VolumeAdministrationError::InvalidInput)?,
    )
    .map_err(|_| VolumeAdministrationError::InvalidInput)
}

fn command_context(
    operation_id: OperationId,
    administrator: IdentityAdministrator,
    occurred_at: UnixMicros,
) -> Result<CommandContext, VolumeAdministrationError> {
    let mut digest = Sha256::new();
    digest.update(AUDIT_ID_DOMAIN);
    digest.update(operation_id.as_bytes());
    digest.update(administrator.principal_id.as_bytes());
    let bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .map(uuid_v8)
        .map_err(|_| VolumeAdministrationError::Failed)?;
    Ok(CommandContext {
        operation_id,
        actor_principal_id: administrator.principal_id,
        audit_event_id: AuditEventId::from_bytes(bytes)
            .map_err(|_| VolumeAdministrationError::Failed)?,
        occurred_at,
        expected_revision: None,
    })
}

fn map_file_authentication_error(error: FileApiAuthenticationError) -> VolumeAdministrationError {
    match error {
        FileApiAuthenticationError::Rejected => VolumeAdministrationError::Unauthenticated,
        FileApiAuthenticationError::AuthorityUnavailable => VolumeAdministrationError::Unavailable,
        FileApiAuthenticationError::InvalidGateway
        | FileApiAuthenticationError::AuthorityFailed => VolumeAdministrationError::Failed,
    }
}

fn map_authority_error(error: VolumeAdministrationAuthorityError) -> VolumeAdministrationError {
    match error {
        VolumeAdministrationAuthorityError::Unavailable => VolumeAdministrationError::Unavailable,
        VolumeAdministrationAuthorityError::Conflict => VolumeAdministrationError::Conflict,
        VolumeAdministrationAuthorityError::Failed => VolumeAdministrationError::Failed,
    }
}

/// Closed replicated-authority failure safe for public classification.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum VolumeAdministrationAuthorityError {
    /// Current consensus projection or leader is unavailable.
    #[error("volume administration authority is unavailable")]
    Unavailable,
    /// Name, owner, operation or command conflicts with committed state.
    #[error("volume administration operation conflicts")]
    Conflict,
    /// Persisted evidence or an invariant failed closed.
    #[error("volume administration authority failed closed")]
    Failed,
}

/// Closed manager-only volume-administration outcome.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum VolumeAdministrationError {
    /// Public name, identity or owner set is invalid.
    #[error("volume administration input is invalid")]
    InvalidInput,
    /// No current credential was accepted.
    #[error("volume administration authentication was rejected")]
    Unauthenticated,
    /// The current principal lacks system-manager authority.
    #[error("volume administration authority was denied")]
    Forbidden,
    /// Name, owner or operation conflicts with committed state.
    #[error("volume administration operation conflicts")]
    Conflict,
    /// Current consensus authority is temporarily unavailable.
    #[error("volume administration authority is unavailable")]
    Unavailable,
    /// Persisted evidence or response construction failed closed.
    #[error("volume administration failed closed")]
    Failed,
}
