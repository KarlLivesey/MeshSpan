// SPDX-License-Identifier: GPL-2.0-only

//! Restartable first-mesh composition across local claim state and consensus authority.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use meshspan_api_contract::{
    CreateMeshSetupRequest, CreateMeshSetupResponse, OperationId as ApiOperationId,
};
use meshspan_domain::{
    ClaimBundle, ClaimBundleError, InitialBootstrapMaterial, InitialBootstrapMaterialError,
    OperationId, UnixMicros,
};
use meshspan_metadata::{
    AuthoritativeCommand, BootstrapAppliance, BootstrapMesh, CommandContext,
    CreateAuthenticationMethod, LocalDatabase, LocalSetupError, LocalSetupKind, LocalSetupState,
    NewAuthenticationCredential, NewLocalSetup, RecordName, RecordNameError,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{ClaimFile, ClaimFileError, SetupLifecycleError, SetupStateSnapshot};

const ALL_INITIAL_SERVICE_SCOPES: u8 = 1 | 2 | 4;
const LOGIN_SCOPE: u64 = 1;

/// Minimal committed result needed to bridge consensus into the local setup journal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootstrapCommit {
    /// Digest of the exact authoritative result receipt.
    pub result_digest: [u8; 32],
}

/// Authority boundary implemented by the live root-partition consensus runtime.
pub trait BootstrapAuthority {
    /// Commits or resolves the exact atomic bootstrap command by its operation identity.
    ///
    /// # Errors
    ///
    /// Fails without claiming success when quorum, persistence or exact replay resolution fails.
    fn commit_or_resolve(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<BootstrapCommit, BootstrapAuthorityError>;
}

/// Opaque authority failure categories safe to cross the public setup boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum BootstrapAuthorityError {
    /// The exact mutation cannot currently reach its required authority.
    #[error("bootstrap authority is unavailable")]
    Unavailable,
    /// The operation identity was already bound to different semantic input.
    #[error("bootstrap operation conflicts with an existing operation")]
    Conflict,
    /// Authority persistence or result verification failed closed.
    #[error("bootstrap authority failed")]
    Failed,
}

/// Owns the two-database first-mesh transition and protected claim-file cleanup.
pub struct CreateMeshSetupService<A> {
    local_database: LocalDatabase,
    authority: A,
    claim_output_path: PathBuf,
    setup_state: Arc<SetupStateSnapshot>,
}

impl<A> CreateMeshSetupService<A>
where
    A: BootstrapAuthority,
{
    /// Creates a service around already identity-bound durable stores.
    #[must_use]
    pub fn new(
        local_database: LocalDatabase,
        authority: A,
        claim_output_path: PathBuf,
        setup_state: Arc<SetupStateSnapshot>,
    ) -> Self {
        Self {
            local_database,
            authority,
            claim_output_path,
            setup_state,
        }
    }

    /// Creates or exactly resumes one first mesh, then consumes and removes its claim.
    ///
    /// # Errors
    ///
    /// Rejects malformed domain values, changed retries, invalid claims, authority failure,
    /// inconsistent durable state or unsafe claim-file cleanup without exposing secret material.
    pub fn create(
        &mut self,
        request: &CreateMeshSetupRequest,
        now: UnixMicros,
    ) -> Result<CreateMeshSetupResponse, CreateMeshSetupError> {
        let input = ValidatedSetupInput::new(request)?;
        let claim = ClaimBundle::parse(request.claim.expose_for_verification())?;
        let material = InitialBootstrapMaterial::derive(
            &claim,
            input.operation_id,
            self.local_database.node_id(),
        )?;
        let request_digest = input.request_digest(claim.claim_id().as_bytes());
        self.local_database.prepare_local_setup(NewLocalSetup {
            operation_id: input.operation_id,
            claim_id: claim.claim_id(),
            claim_secret_digest: claim.secret_digest(),
            kind: LocalSetupKind::CreateMesh,
            request_digest,
            created_at: now,
        })?;
        let setup = self
            .local_database
            .local_setup()?
            .ok_or(CreateMeshSetupError::Inconsistent)?;
        self.setup_state.reconcile(&self.local_database)?;

        if setup.state == LocalSetupState::Prepared {
            let context = CommandContext {
                operation_id: input.operation_id,
                actor_principal_id: material.administrator_id,
                audit_event_id: material.audit_event_id,
                occurred_at: setup.created_at,
                expected_revision: Some(meshspan_domain::Revision::ZERO),
            };
            let command = input.command(&material, setup.created_at);
            let committed = self.authority.commit_or_resolve(context, &command)?;
            self.local_database.record_local_setup_authority_commit(
                input.operation_id,
                committed.result_digest,
                std::cmp::max(now, setup.created_at),
            )?;
        }
        let setup = self
            .local_database
            .local_setup()?
            .ok_or(CreateMeshSetupError::Inconsistent)?;
        let completion_at = setup
            .authority_committed_at
            .map_or(now, |committed_at| std::cmp::max(now, committed_at));
        self.local_database.complete_local_setup(
            input.operation_id,
            claim.claim_id(),
            claim.secret_digest(),
            completion_at,
        )?;
        ClaimFile::remove_if_matches(
            &self.claim_output_path,
            claim.claim_id(),
            claim.secret_digest(),
        )?;
        self.setup_state.reconcile(&self.local_database)?;
        Ok(input.response(&material))
    }

    /// Returns the protected claim-output path owned by this service.
    #[must_use]
    pub fn claim_output_path(&self) -> &Path {
        &self.claim_output_path
    }
}

struct ValidatedSetupInput {
    api_operation_id: ApiOperationId,
    operation_id: OperationId,
    mesh_name: RecordName,
    administrator_name: RecordName,
    host_name: RecordName,
    node_name: RecordName,
    partition_name: RecordName,
}

impl ValidatedSetupInput {
    fn new(request: &CreateMeshSetupRequest) -> Result<Self, CreateMeshSetupError> {
        Ok(Self {
            api_operation_id: request.operation_id.clone(),
            operation_id: OperationId::from_bytes(parse_uuid(request.operation_id.as_str())?)?,
            mesh_name: RecordName::new(request.mesh_name.as_str())?,
            administrator_name: RecordName::new(request.administrator_name.as_str())?,
            host_name: RecordName::new(request.host_name.as_str())?,
            node_name: RecordName::new(request.node_name.as_str())?,
            partition_name: RecordName::new("Root authority")?,
        })
    }

    fn command(
        &self,
        material: &InitialBootstrapMaterial,
        occurred_at: UnixMicros,
    ) -> AuthoritativeCommand {
        AuthoritativeCommand::BootstrapAppliance(BootstrapAppliance {
            mesh: BootstrapMesh {
                mesh_id: material.mesh_id,
                mesh_name: self.mesh_name.clone(),
                administrator_id: material.administrator_id,
                administrator_name: self.administrator_name.clone(),
                administrator_role_id: material.administrator_role_id,
                host_id: material.host_id,
                host_name: self.host_name.clone(),
                node_id: material.node_id,
                node_name: self.node_name.clone(),
                partition_name: self.partition_name.clone(),
            },
            authentication: CreateAuthenticationMethod {
                method_id: material.authentication_method_id,
                principal_id: material.administrator_id,
                label: "Initial API key".to_owned(),
                service_scope: ALL_INITIAL_SERVICE_SCOPES,
                expires_at: None,
                credential: NewAuthenticationCredential::ApiKey {
                    key_id: material.api_key.key_id(),
                    key_digest: material.api_key.secret_digest(),
                    scopes: LOGIN_SCOPE,
                    valid_from: occurred_at,
                },
            },
        })
    }

    fn request_digest(&self, claim_id: [u8; 16]) -> [u8; 32] {
        let mut digest = Sha256::new();
        digest.update(b"meshspan.setup.create-mesh-request.v1");
        digest.update(claim_id);
        append_name(&mut digest, &self.mesh_name);
        append_name(&mut digest, &self.administrator_name);
        append_name(&mut digest, &self.host_name);
        append_name(&mut digest, &self.node_name);
        digest.finalize().into()
    }

    fn response(&self, material: &InitialBootstrapMaterial) -> CreateMeshSetupResponse {
        CreateMeshSetupResponse {
            operation_id: self.api_operation_id.clone(),
            mesh_id: format_uuid(material.mesh_id.as_bytes()),
            node_id: format_uuid(material.node_id.as_bytes()),
            api_key: material.api_key.expose_encoded().to_string(),
        }
    }
}

fn append_name(digest: &mut Sha256, name: &RecordName) {
    for value in [name.display(), name.canonical()] {
        digest.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
        digest.update(value.as_bytes());
    }
}

pub(crate) fn parse_uuid(value: &str) -> Result<[u8; 16], CreateMeshSetupError> {
    if value.len() != 36 {
        return Err(CreateMeshSetupError::InvalidUuid);
    }
    let bytes = value.as_bytes();
    if [8, 13, 18, 23]
        .into_iter()
        .any(|index| bytes.get(index) != Some(&b'-'))
    {
        return Err(CreateMeshSetupError::InvalidUuid);
    }
    let mut decoded = [0_u8; 16];
    let mut source = bytes
        .iter()
        .enumerate()
        .filter_map(|(index, byte)| (![8, 13, 18, 23].contains(&index)).then_some(*byte));
    for destination in &mut decoded {
        let high = source
            .next()
            .and_then(decode_hex)
            .ok_or(CreateMeshSetupError::InvalidUuid)?;
        let low = source
            .next()
            .and_then(decode_hex)
            .ok_or(CreateMeshSetupError::InvalidUuid)?;
        *destination = (high << 4) | low;
    }
    if source.next().is_some() {
        return Err(CreateMeshSetupError::InvalidUuid);
    }
    Ok(decoded)
}

pub(crate) fn format_uuid(value: [u8; 16]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(36);
    for (index, byte) in value.into_iter().enumerate() {
        if [4, 6, 8, 10].contains(&index) {
            output.push('-');
        }
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

const fn decode_hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

/// Stable first-mesh setup failure with no request, claim or key material.
#[derive(Debug, Error)]
pub enum CreateMeshSetupError {
    /// A public UUID was not exact canonical lowercase text.
    #[error("setup UUID is invalid")]
    InvalidUuid,
    /// Public operation identity was not a canonical domain identifier.
    #[error("setup operation identifier is invalid")]
    Identifier(#[from] meshspan_domain::IdentifierError),
    /// A display name failed canonical domain validation.
    #[error("setup name is invalid")]
    Name(#[from] RecordNameError),
    /// The first-boot claim was malformed or substituted.
    #[error("first-boot claim was not accepted")]
    Claim(#[from] ClaimBundleError),
    /// Restart-stable bootstrap material could not be derived.
    #[error("bootstrap material could not be derived")]
    Material(#[from] InitialBootstrapMaterialError),
    /// Node-local setup state rejected the transition.
    #[error("local setup transition failed")]
    Local(#[from] LocalSetupError),
    /// Root-partition consensus did not commit or resolve the operation.
    #[error("bootstrap authority failed")]
    Authority(#[from] BootstrapAuthorityError),
    /// Protected claim output could not be removed safely.
    #[error("protected claim output cleanup failed")]
    ClaimFile(#[from] ClaimFileError),
    /// Durable local records disagree.
    #[error("durable setup state is inconsistent")]
    Lifecycle(#[from] SetupLifecycleError),
    /// Required durable setup evidence was absent.
    #[error("durable setup state is inconsistent")]
    Inconsistent,
}
