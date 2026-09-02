// SPDX-License-Identifier: GPL-2.0-only

//! Restartable first-mesh composition across local claim state and consensus authority.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use meshspan_api_contract::{
    CreateMeshSetupRequest, CreateMeshSetupResponse, OperationId as ApiOperationId,
};
use meshspan_certificates::{NodePublicIdentity, OnlineCertificateAuthority};
use meshspan_domain::{
    ClaimBundle, ClaimBundleError, InitialBootstrapMaterial, InitialBootstrapMaterialError,
    OperationId, RandomSource, UnixMicros,
};
use meshspan_metadata::{
    AUTHENTICATION_ROOT_KEY_SECRET_KIND, AuthoritativeCommand, BootstrapAppliance, BootstrapMesh,
    BootstrapNodeCertificate, BootstrapRecoveryIdentity, CommandContext, CommitSecretGeneration,
    CreateAuthenticationMethod, LocalDatabase, LocalSetupError, LocalSetupKind, LocalSetupState,
    NewAuthenticationCredential, NewLocalSetup, ONLINE_AUTHORITY_KEY_SECRET_KIND, RecordName,
    RecordNameError, RegisterNodeWrappingKey, STORAGE_PERMIT_KEY_SECRET_KIND,
};
use meshspan_recovery_bundle::{OfflineRecoveryIdentity, RecoveryBundleCode, RecoveryBundleError};
use meshspan_secret_envelope::{
    EncryptedSecret, RecipientKeyEnvelope, SecretContext, WrappingPublicKey, encrypt_secret,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{
    ClaimFile, ClaimFileError, PendingRecoveryBundle, PendingRecoveryBundleError,
    SetupLifecycleError, SetupStateSnapshot,
};

const ALL_INITIAL_SERVICE_SCOPES: u8 = 1 | 2 | 4;
const ALL_INITIAL_LOGIN_SCOPES: u64 = 1 | 2 | 4;
const NODE_CERTIFICATE_LIFETIME_MICROS: u64 = 30 * 24 * 60 * 60 * 1_000_000;

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
pub struct CreateMeshSetupService<A, R> {
    local_database: LocalDatabase,
    authority: A,
    claim_output_path: PathBuf,
    recovery_bundle_path: PathBuf,
    setup_state: Arc<SetupStateSnapshot>,
    wrapping_public_key: WrappingPublicKey,
    node_identity_public_key: Vec<u8>,
    random: R,
}

/// Immutable local paths and node identity required by first-mesh creation.
pub struct CreateMeshSetupConfiguration {
    claim_output_path: PathBuf,
    recovery_bundle_path: PathBuf,
    wrapping_public_key: WrappingPublicKey,
    node_identity_public_key: Vec<u8>,
}

impl CreateMeshSetupConfiguration {
    /// Binds mesh creation to the current node's protected paths and public identity.
    #[must_use]
    pub fn new(
        claim_output_path: PathBuf,
        recovery_bundle_path: PathBuf,
        wrapping_public_key: WrappingPublicKey,
        node_identity_public_key: Vec<u8>,
    ) -> Self {
        Self {
            claim_output_path,
            recovery_bundle_path,
            wrapping_public_key,
            node_identity_public_key,
        }
    }
}

impl<A, R> CreateMeshSetupService<A, R>
where
    A: BootstrapAuthority,
    R: RandomSource,
{
    /// Creates a service around already identity-bound durable stores.
    #[must_use]
    pub fn new(
        local_database: LocalDatabase,
        authority: A,
        setup_state: Arc<SetupStateSnapshot>,
        configuration: CreateMeshSetupConfiguration,
        random: R,
    ) -> Self {
        Self {
            local_database,
            authority,
            claim_output_path: configuration.claim_output_path,
            recovery_bundle_path: configuration.recovery_bundle_path,
            setup_state,
            wrapping_public_key: configuration.wrapping_public_key,
            node_identity_public_key: configuration.node_identity_public_key,
            random,
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
        let recovery_code =
            RecoveryBundleCode::from_high_entropy_seed(material.recovery_bundle_code_seed())?;
        let recovery_bundle = PendingRecoveryBundle::open_or_create(
            &self.recovery_bundle_path,
            material.mesh_id,
            &recovery_code,
            &mut self.random,
        )?;
        let recovery_identity = recovery_bundle.public_identity()?;
        let setup = self
            .local_database
            .local_setup()?
            .ok_or(CreateMeshSetupError::Inconsistent)?;
        self.setup_state.reconcile(&self.local_database)?;

        if setup.state == LocalSetupState::Prepared {
            let online_material = material.online_authority_material();
            let online_authority =
                recovery_bundle.online_authority(&recovery_code, *online_material.key_seed())?;
            let context = CommandContext {
                operation_id: input.operation_id,
                actor_principal_id: material.administrator_id,
                audit_event_id: material.audit_event_id,
                occurred_at: setup.created_at,
                expected_revision: Some(meshspan_domain::Revision::ZERO),
            };
            let command = input.command(
                &material,
                &BootstrapCommandInputs {
                    recovery: &recovery_identity,
                    save_challenge_commitment: recovery_bundle
                        .challenge(&recovery_code)
                        .commitment(),
                    occurred_at: setup.created_at,
                    wrapping_public_key: self.wrapping_public_key,
                    node_identity_public_key: &self.node_identity_public_key,
                    online_authority: &online_authority,
                },
            )?;
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
        input.response(&material, &recovery_bundle, &recovery_code)
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

struct BootstrapCommandInputs<'a> {
    recovery: &'a OfflineRecoveryIdentity,
    save_challenge_commitment: [u8; 32],
    occurred_at: UnixMicros,
    wrapping_public_key: WrappingPublicKey,
    node_identity_public_key: &'a [u8],
    online_authority: &'a OnlineCertificateAuthority,
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
        inputs: &BootstrapCommandInputs<'_>,
    ) -> Result<AuthoritativeCommand, CreateMeshSetupError> {
        let recovery_public_key = inputs.recovery.public_wrapping_key();
        let generations = initial_authority_generations(
            material,
            inputs.wrapping_public_key,
            recovery_public_key,
            inputs.online_authority,
        )?;
        let node_public_identity = NodePublicIdentity::from_sec1(inputs.node_identity_public_key)
            .map_err(|_| CreateMeshSetupError::Certificate)?;
        if InitialBootstrapMaterial::node_id(node_public_identity.public_key_fingerprint())?
            != material.node_id
        {
            return Err(CreateMeshSetupError::Certificate);
        }
        let node_certificate_der = inputs
            .online_authority
            .sign_node_public_identity(
                &node_public_identity,
                &private_node_certificate_name(material.node_id),
            )
            .map_err(|_| CreateMeshSetupError::Certificate)?;
        let certificate_valid_until = inputs
            .occurred_at
            .checked_add(meshspan_domain::DurationMicros::new(
                NODE_CERTIFICATE_LIFETIME_MICROS,
            ))
            .ok_or(CreateMeshSetupError::Certificate)?;
        Ok(AuthoritativeCommand::BootstrapAppliance(Box::new(
            BootstrapAppliance {
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
                        scopes: ALL_INITIAL_LOGIN_SCOPES,
                        valid_from: inputs.occurred_at,
                    },
                },
                recovery: Box::new(BootstrapRecoveryIdentity {
                    public_wrapping_key: recovery_public_key.as_bytes(),
                    key_fingerprint: recovery_public_key.fingerprint(),
                    root_certificate_digest: Sha256::digest(inputs.recovery.root_certificate_der())
                        .into(),
                    root_certificate_der: inputs.recovery.root_certificate_der().to_vec(),
                    online_authority_certificate_der: inputs
                        .online_authority
                        .certificate_der()
                        .to_vec(),
                    online_authority_certificate_digest: Sha256::digest(
                        inputs.online_authority.certificate_der(),
                    )
                    .into(),
                    bundle_digest: inputs.recovery.bundle_digest(),
                    save_challenge_commitment: inputs.save_challenge_commitment,
                }),
                node_wrapping_key: RegisterNodeWrappingKey {
                    node_id: material.node_id,
                    generation: 1,
                    public_key: inputs.wrapping_public_key.as_bytes(),
                    key_fingerprint: inputs.wrapping_public_key.fingerprint(),
                },
                node_certificate: BootstrapNodeCertificate {
                    certificate_fingerprint: Sha256::digest(&node_certificate_der).into(),
                    certificate_der: node_certificate_der,
                    certificate_valid_until,
                },
                storage_permit_key_generation: generations.storage_permit,
                authentication_root_key_generation: generations.authentication_root,
                online_authority_key_generation: generations.online_authority,
            },
        )))
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

    fn response(
        &self,
        material: &InitialBootstrapMaterial,
        recovery_bundle: &PendingRecoveryBundle,
        recovery_code: &RecoveryBundleCode,
    ) -> Result<CreateMeshSetupResponse, CreateMeshSetupError> {
        Ok(CreateMeshSetupResponse {
            operation_id: self.api_operation_id.clone(),
            mesh_id: format_uuid(material.mesh_id.as_bytes()),
            node_id: format_uuid(material.node_id.as_bytes()),
            api_key: material.api_key.expose_encoded().to_string(),
            recovery_bundle: recovery_bundle.download_text()?,
            recovery_code: recovery_code.expose_once(),
            recovery_challenge: recovery_bundle
                .challenge(recovery_code)
                .expose_for_verification(),
        })
    }
}

fn private_node_certificate_name(node_id: meshspan_domain::NodeId) -> String {
    let compact = node_id.to_string().replace('-', "");
    format!("node-{compact}.meshspan.internal")
}

struct InitialAuthorityGenerations {
    storage_permit: Box<CommitSecretGeneration>,
    authentication_root: Box<CommitSecretGeneration>,
    online_authority: Box<CommitSecretGeneration>,
}

fn initial_authority_generations(
    material: &InitialBootstrapMaterial,
    node: WrappingPublicKey,
    recovery: WrappingPublicKey,
    online_authority: &OnlineCertificateAuthority,
) -> Result<InitialAuthorityGenerations, CreateMeshSetupError> {
    let recipients = [node, recovery];
    let mut permit_material = material.storage_permit_material();
    let permit_key = permit_material.key();
    let permit = encrypt_secret(
        SecretContext::new(
            STORAGE_PERMIT_KEY_SECRET_KIND,
            material.mesh_id.as_bytes(),
            1,
        )?,
        permit_key.as_ref(),
        &recipients,
        &mut permit_material,
    )?;
    let mut authentication_material = material.authentication_root_material();
    let authentication_key = authentication_material.key();
    let authentication = encrypt_secret(
        SecretContext::new(
            AUTHENTICATION_ROOT_KEY_SECRET_KIND,
            material.mesh_id.as_bytes(),
            1,
        )?,
        authentication_key.as_ref(),
        &recipients,
        &mut authentication_material,
    )?;
    let mut online_material = material.online_authority_material();
    let online = encrypt_secret(
        SecretContext::new(
            ONLINE_AUTHORITY_KEY_SECRET_KIND,
            material.mesh_id.as_bytes(),
            1,
        )?,
        online_authority.private_key_pkcs8(),
        &recipients,
        &mut online_material,
    )?;
    Ok(InitialAuthorityGenerations {
        storage_permit: committed_generation(permit),
        authentication_root: committed_generation(authentication),
        online_authority: committed_generation(online),
    })
}

fn committed_generation(
    (secret, recipients): (EncryptedSecret, Vec<RecipientKeyEnvelope>),
) -> Box<CommitSecretGeneration> {
    Box::new(CommitSecretGeneration {
        secret: secret.parts(),
        recipients: recipients.iter().map(RecipientKeyEnvelope::parts).collect(),
    })
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
    /// Recovery-code derivation failed closed.
    #[error("recovery code could not be derived")]
    RecoveryCode(#[from] RecoveryBundleError),
    /// Protected offline recovery delivery could not be created or resumed.
    #[error("pending offline recovery bundle failed")]
    RecoveryBundle(#[from] PendingRecoveryBundleError),
    /// Initial protected mesh-secret encryption or recipient composition failed closed.
    #[error("initial protected mesh-secret envelope could not be created")]
    InitialSecretEnvelope(#[from] meshspan_secret_envelope::SecretEnvelopeError),
    /// Initial node public identity or mesh certificate construction failed closed.
    #[error("initial node certificate could not be created")]
    Certificate,
    /// The authenticated private network could not start after the durable mesh commit.
    #[error("private mesh network could not start")]
    PrivateNetwork,
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
