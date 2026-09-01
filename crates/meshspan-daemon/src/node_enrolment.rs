// SPDX-License-Identifier: GPL-2.0-only

//! Anonymous pre-authorised node admission and mesh-certificate issuance.

use std::collections::BTreeSet;

use meshspan_api_contract::{
    EnrolNodeRequest, EnrolNodeResponse, EnrolmentBootstrapPeer, NodeJoinHost, NodeJoinRole,
};
use meshspan_certificates::NodePublicIdentity;
use meshspan_domain::{
    AuditEventId, DurationMicros, HostId, InitialBootstrapMaterial, JoinGrantBundle, MeshId,
    NodeId, OperationId, UnixMicros, uuid_v8,
};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, ConsumeJoinGrant, JoinGrantRecord, JoinRoles,
    MeshRecoveryAuthority, NodeEnrolmentRecord, RecordName, RecoveryBundleState,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::create_mesh_setup::{format_uuid, parse_uuid};
use crate::{
    OnlineAuthorityLoadingAuthority, OnlineAuthorityLoadingError, OnlineAuthorityLoadingService,
    SecretGenerationDecryptor,
};

const AUDIT_ID_DOMAIN: &[u8] = b"meshspan.enrolment.consume-audit-id.v1\0";
const HOST_ID_DOMAIN: &[u8] = b"meshspan.enrolment.new-host-id.v1\0";
const TRANSCRIPT_DOMAIN: &[u8] = b"meshspan.enrolment.node-identity-proof.v1\0";
const NODE_CERTIFICATE_LIFETIME_MICROS: u64 = 30 * 24 * 60 * 60 * 1_000_000;

/// Exact durable evidence returned by one node admission.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct NodeEnrolmentCommit {
    /// Original semantic request digest.
    pub request_digest: [u8; 32],
    /// Durable result digest.
    pub result_digest: [u8; 32],
    /// Admitted node and certificate facts.
    pub record: NodeEnrolmentRecord,
}

/// Replicated reads and mutation required by anonymous node admission.
pub trait NodeEnrolmentAuthority {
    /// Returns one exact current join grant.
    ///
    /// # Errors
    ///
    /// Fails closed when grant state is unavailable or malformed.
    fn join_grant(
        &self,
        join_grant_id: meshspan_domain::JoinGrantId,
    ) -> Result<Option<JoinGrantRecord>, NodeEnrolmentAuthorityError>;

    /// Returns the mesh's offline public recovery/root authority.
    ///
    /// # Errors
    ///
    /// Fails closed when recovery authority is unavailable or malformed.
    fn mesh_recovery_authority(
        &self,
        mesh_id: MeshId,
    ) -> Result<Option<MeshRecoveryAuthority>, NodeEnrolmentAuthorityError>;

    /// Resolves one exact prior node admission.
    ///
    /// # Errors
    ///
    /// Rejects another command family or malformed durable evidence.
    fn resolve_node_enrolment(
        &self,
        operation_id: OperationId,
        node_id: NodeId,
    ) -> Result<Option<NodeEnrolmentCommit>, NodeEnrolmentAuthorityError>;

    /// Commits or exactly resolves one node admission through consensus.
    ///
    /// # Errors
    ///
    /// Rejects changed operation reuse and never reports success without durable evidence.
    fn commit_or_resolve_node_enrolment(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<NodeEnrolmentCommit, NodeEnrolmentAuthorityError>;
}

/// HTTP-facing anonymous node enrolment operation.
pub trait NodeEnrolmentController: Send + 'static {
    /// Consumes one pre-authorised grant and returns committed bootstrap trust.
    ///
    /// # Errors
    ///
    /// Rejects malformed proof, invalid/expired grant, changed retry or unavailable authority.
    fn enrol(
        &mut self,
        request: EnrolNodeRequest,
        now: UnixMicros,
    ) -> Result<EnrolNodeResponse, NodeEnrolmentError>;
}

/// Late-bound source of currently reachable, active bootstrap peers.
pub trait NodeEnrolmentBootstrapSource {
    /// Returns at least one current mesh-signed peer only after setup has completed.
    ///
    /// # Errors
    ///
    /// Fails closed when active certificate or endpoint state is unavailable or malformed.
    fn bootstrap_peers(&self) -> Result<Vec<EnrolmentBootstrapPeer>, NodeEnrolmentAuthorityError>;
}

/// Complete admission service over replaceable consensus and online-authority boundaries.
pub struct NodeEnrolmentService<A, R, D, B> {
    authority: A,
    online_authority: OnlineAuthorityLoadingService<R, D>,
    bootstrap_peers: B,
}

impl<A, R, D, B> NodeEnrolmentService<A, R, D, B> {
    /// Binds admission authority, protected certificate issuance and reachable bootstrap peers.
    #[must_use]
    pub fn new(authority: A, online_authority: R, decryptor: D, bootstrap_peers: B) -> Self {
        Self {
            authority,
            online_authority: OnlineAuthorityLoadingService::new(online_authority, decryptor),
            bootstrap_peers,
        }
    }
}

impl<A, R, D, B> NodeEnrolmentController for NodeEnrolmentService<A, R, D, B>
where
    A: NodeEnrolmentAuthority + Send + 'static,
    R: OnlineAuthorityLoadingAuthority + Send + 'static,
    D: SecretGenerationDecryptor + Send + 'static,
    B: NodeEnrolmentBootstrapSource + Send + 'static,
{
    fn enrol(
        &mut self,
        request: EnrolNodeRequest,
        now: UnixMicros,
    ) -> Result<EnrolNodeResponse, NodeEnrolmentError> {
        let input = ValidatedEnrolment::new(&request)?;
        let invitation =
            JoinGrantBundle::parse(&request.join_code).map_err(|_| NodeEnrolmentError::Rejected)?;
        let grant = self
            .authority
            .join_grant(invitation.join_grant_id())?
            .ok_or(NodeEnrolmentError::Rejected)?;
        let (mesh_id, online_authority) = self.online_authority.load_latest()?;
        if invitation.mesh_id() != mesh_id || grant.expires_at <= now {
            return Err(NodeEnrolmentError::Rejected);
        }
        input.verify_identity_proof(mesh_id, invitation.join_grant_id())?;
        let recovery = self
            .authority
            .mesh_recovery_authority(mesh_id)?
            .filter(|record| record.state == RecoveryBundleState::Verified)
            .ok_or(NodeEnrolmentError::Unavailable)?;
        let existing = self
            .authority
            .resolve_node_enrolment(input.operation_id, input.node_id)?;
        let occurred_at = existing
            .as_ref()
            .map_or(now, |commit| commit.record.admitted_at);
        let certificate_valid_until = occurred_at
            .checked_add(DurationMicros::new(NODE_CERTIFICATE_LIFETIME_MICROS))
            .ok_or(NodeEnrolmentError::InvalidInput)?;
        let certificate_der = online_authority
            .sign_node_public_identity(&input.public_identity, &input.certificate_dns_name())
            .map_err(|_| NodeEnrolmentError::Failed)?;
        let command = input.command(&invitation, certificate_der, certificate_valid_until);
        let context = command_context(
            input.operation_id,
            grant.issued_by,
            input.node_id,
            occurred_at,
        )?;
        let expected_digest = command.request_digest(context);
        let commit = match existing {
            Some(commit) => commit,
            None => self
                .authority
                .commit_or_resolve_node_enrolment(context, &command)?,
        };
        validate_commit(
            &commit,
            expected_digest,
            input.node_id,
            certificate_valid_until,
        )?;
        let bootstrap_peers = self.bootstrap_peers.bootstrap_peers()?;
        if bootstrap_peers.is_empty() {
            return Err(NodeEnrolmentError::Unavailable);
        }
        Ok(EnrolNodeResponse {
            operation_id: request.operation_id,
            mesh_id: format_uuid(mesh_id.as_bytes()),
            node_id: format_uuid(input.node_id.as_bytes()),
            node_certificate_der_hex: encode_hex(&commit.record.certificate_der),
            online_authority_certificate_der_hex: encode_hex(online_authority.certificate_der()),
            root_certificate_der_hex: encode_hex(&recovery.root_certificate_der),
            bootstrap_peers,
        })
    }
}

struct ValidatedEnrolment {
    operation_id: OperationId,
    host_id: HostId,
    new_host_name: Option<RecordName>,
    node_id: NodeId,
    node_name: RecordName,
    requested_roles: JoinRoles,
    wrapping_public_key: [u8; 32],
    private_endpoint: String,
    public_identity: NodePublicIdentity,
    proof_signature: Vec<u8>,
}

impl ValidatedEnrolment {
    fn new(request: &EnrolNodeRequest) -> Result<Self, NodeEnrolmentError> {
        let operation_id = operation_id(&request.operation_id)?;
        let public_key = decode_hex::<65>(&request.node_identity_public_key_hex)?;
        let public_identity = NodePublicIdentity::from_sec1(&public_key)
            .map_err(|_| NodeEnrolmentError::InvalidInput)?;
        let node_id = InitialBootstrapMaterial::node_id(public_identity.public_key_fingerprint())
            .map_err(|_| NodeEnrolmentError::InvalidInput)?;
        let node_name = RecordName::new(request.node_name.as_str())
            .map_err(|_| NodeEnrolmentError::InvalidInput)?;
        let (host_id, new_host_name) = host(request, operation_id, node_id)?;
        let requested_roles = roles(&request.requested_roles)?;
        let wrapping_public_key = decode_hex::<32>(&request.wrapping_public_key_hex)?;
        meshspan_secret_envelope::WrappingPublicKey::from_bytes(wrapping_public_key)
            .map_err(|_| NodeEnrolmentError::InvalidInput)?;
        let proof_signature = decode_variable_hex(&request.identity_proof_signature_hex, 72)?;
        Ok(Self {
            operation_id,
            host_id,
            new_host_name,
            node_id,
            node_name,
            requested_roles,
            wrapping_public_key,
            private_endpoint: request.private_endpoint.clone(),
            public_identity,
            proof_signature,
        })
    }

    fn verify_identity_proof(
        &self,
        mesh_id: MeshId,
        join_grant_id: meshspan_domain::JoinGrantId,
    ) -> Result<(), NodeEnrolmentError> {
        self.public_identity
            .verify_enrolment_transcript(
                &self.transcript(mesh_id, join_grant_id),
                &self.proof_signature,
            )
            .map_err(|_| NodeEnrolmentError::Rejected)
    }

    fn transcript(&self, mesh_id: MeshId, join_grant_id: meshspan_domain::JoinGrantId) -> Vec<u8> {
        let mut transcript = Vec::with_capacity(512);
        transcript.extend_from_slice(TRANSCRIPT_DOMAIN);
        transcript.extend_from_slice(&mesh_id.as_bytes());
        transcript.extend_from_slice(&join_grant_id.as_bytes());
        transcript.extend_from_slice(&self.operation_id.as_bytes());
        transcript.extend_from_slice(&self.host_id.as_bytes());
        append_optional_name(&mut transcript, self.new_host_name.as_ref());
        append_name(&mut transcript, &self.node_name);
        transcript.push(self.requested_roles.bits());
        transcript.extend_from_slice(&self.wrapping_public_key);
        append_bytes(&mut transcript, self.private_endpoint.as_bytes());
        transcript
    }

    fn certificate_dns_name(&self) -> String {
        format!(
            "node-{}.meshspan.internal",
            encode_hex(&self.node_id.as_bytes())
        )
    }

    fn command(
        &self,
        invitation: &JoinGrantBundle,
        certificate_der: Vec<u8>,
        certificate_valid_until: UnixMicros,
    ) -> AuthoritativeCommand {
        AuthoritativeCommand::ConsumeJoinGrant(ConsumeJoinGrant {
            join_grant_id: invitation.join_grant_id(),
            secret_digest: invitation.secret_digest(),
            host_id: self.host_id,
            new_host_name: self.new_host_name.clone(),
            node_id: self.node_id,
            node_name: self.node_name.clone(),
            incarnation: 1,
            requested_roles: self.requested_roles,
            wrapping_public_key: self.wrapping_public_key,
            private_endpoint: self.private_endpoint.clone(),
            certificate_fingerprint: Sha256::digest(&certificate_der).into(),
            certificate_der,
            certificate_valid_until,
        })
    }
}

fn operation_id(
    value: &meshspan_api_contract::OperationId,
) -> Result<OperationId, NodeEnrolmentError> {
    OperationId::from_bytes(
        parse_uuid(value.as_str()).map_err(|_| NodeEnrolmentError::InvalidInput)?,
    )
    .map_err(|_| NodeEnrolmentError::InvalidInput)
}

fn host(
    request: &EnrolNodeRequest,
    operation_id: OperationId,
    node_id: NodeId,
) -> Result<(HostId, Option<RecordName>), NodeEnrolmentError> {
    match &request.host {
        NodeJoinHost::Existing { host_id } => Ok((
            HostId::from_bytes(parse_uuid(host_id).map_err(|_| NodeEnrolmentError::InvalidInput)?)
                .map_err(|_| NodeEnrolmentError::InvalidInput)?,
            None,
        )),
        NodeJoinHost::New { name } => {
            let name =
                RecordName::new(name.as_str()).map_err(|_| NodeEnrolmentError::InvalidInput)?;
            let mut digest = Sha256::new();
            digest.update(HOST_ID_DOMAIN);
            digest.update(operation_id.as_bytes());
            digest.update(node_id.as_bytes());
            digest.update(name.canonical().as_bytes());
            let bytes: [u8; 16] = digest.finalize()[..16]
                .try_into()
                .map(uuid_v8)
                .map_err(|_| NodeEnrolmentError::Failed)?;
            Ok((
                HostId::from_bytes(bytes).map_err(|_| NodeEnrolmentError::Failed)?,
                Some(name),
            ))
        }
    }
}

fn roles(values: &[NodeJoinRole]) -> Result<JoinRoles, NodeEnrolmentError> {
    let values = values.iter().copied().collect::<BTreeSet<_>>();
    if values.is_empty() {
        return Err(NodeEnrolmentError::InvalidInput);
    }
    let bits = values.into_iter().fold(0_u8, |bits, role| {
        bits | match role {
            NodeJoinRole::Storage => JoinRoles::STORAGE,
            NodeJoinRole::Gateway => JoinRoles::GATEWAY,
            NodeJoinRole::MetadataEligible => JoinRoles::METADATA_ELIGIBLE,
        }
    });
    JoinRoles::new(bits).map_err(|_| NodeEnrolmentError::InvalidInput)
}

fn command_context(
    operation_id: OperationId,
    issuer: meshspan_domain::PrincipalId,
    node_id: NodeId,
    occurred_at: UnixMicros,
) -> Result<CommandContext, NodeEnrolmentError> {
    let mut digest = Sha256::new();
    digest.update(AUDIT_ID_DOMAIN);
    digest.update(operation_id.as_bytes());
    digest.update(node_id.as_bytes());
    let bytes: [u8; 16] = digest.finalize()[..16]
        .try_into()
        .map(uuid_v8)
        .map_err(|_| NodeEnrolmentError::Failed)?;
    Ok(CommandContext {
        operation_id,
        actor_principal_id: issuer,
        audit_event_id: AuditEventId::from_bytes(bytes).map_err(|_| NodeEnrolmentError::Failed)?,
        occurred_at,
        expected_revision: None,
    })
}

fn validate_commit(
    commit: &NodeEnrolmentCommit,
    expected_digest: [u8; 32],
    node_id: NodeId,
    certificate_valid_until: UnixMicros,
) -> Result<(), NodeEnrolmentError> {
    if commit.request_digest != expected_digest {
        return Err(NodeEnrolmentError::Conflict);
    }
    if commit.result_digest == [0; 32]
        || commit.record.node_id != node_id
        || commit.record.certificate_valid_until != certificate_valid_until
    {
        return Err(NodeEnrolmentError::Failed);
    }
    Ok(())
}

fn append_optional_name(destination: &mut Vec<u8>, value: Option<&RecordName>) {
    destination.push(u8::from(value.is_some()));
    if let Some(value) = value {
        append_name(destination, value);
    }
}

fn append_name(destination: &mut Vec<u8>, value: &RecordName) {
    append_bytes(destination, value.display().as_bytes());
    append_bytes(destination, value.canonical().as_bytes());
}

fn append_bytes(destination: &mut Vec<u8>, value: &[u8]) {
    destination.extend_from_slice(&u64::try_from(value.len()).unwrap_or(u64::MAX).to_be_bytes());
    destination.extend_from_slice(value);
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], NodeEnrolmentError> {
    decode_variable_hex(value, N)?
        .try_into()
        .map_err(|_| NodeEnrolmentError::InvalidInput)
}

fn decode_variable_hex(value: &str, maximum: usize) -> Result<Vec<u8>, NodeEnrolmentError> {
    if value.is_empty() || !value.len().is_multiple_of(2) || value.len() > maximum * 2 {
        return Err(NodeEnrolmentError::InvalidInput);
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high = hex_nibble(pair[0]).ok_or(NodeEnrolmentError::InvalidInput)?;
            let low = hex_nibble(pair[1]).ok_or(NodeEnrolmentError::InvalidInput)?;
            Ok((high << 4) | low)
        })
        .collect()
}

const fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

fn encode_hex(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut output = String::with_capacity(value.len() * 2);
    for byte in value {
        output.push(char::from(HEX[usize::from(byte >> 4)]));
        output.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    output
}

/// Closed replicated-authority failure for anonymous node admission.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum NodeEnrolmentAuthorityError {
    /// Current authority cannot be reached.
    #[error("node enrolment authority is unavailable")]
    Unavailable,
    /// Operation identity is bound to different input.
    #[error("node enrolment authority reports a conflict")]
    Conflict,
    /// Grant or node uniqueness rejected this admission.
    #[error("node enrolment authority rejected the admission")]
    Rejected,
    /// Durable state or evidence failed validation.
    #[error("node enrolment authority failed closed")]
    Failed,
}

/// Stable public node-enrolment failure containing no grant or key material.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum NodeEnrolmentError {
    /// Public identifiers, names, roles, keys or endpoints are invalid.
    #[error("node enrolment request is invalid")]
    InvalidInput,
    /// Join pre-authorisation or node identity possession was rejected.
    #[error("node enrolment was rejected")]
    Rejected,
    /// Operation identity is bound to different semantic input.
    #[error("node enrolment conflicts with committed state")]
    Conflict,
    /// Required replicated or certificate authority is temporarily unavailable.
    #[error("node enrolment authority is unavailable")]
    Unavailable,
    /// Certificate material, durable evidence or an invariant failed closed.
    #[error("node enrolment failed closed")]
    Failed,
}

impl From<NodeEnrolmentAuthorityError> for NodeEnrolmentError {
    fn from(error: NodeEnrolmentAuthorityError) -> Self {
        match error {
            NodeEnrolmentAuthorityError::Unavailable => Self::Unavailable,
            NodeEnrolmentAuthorityError::Conflict => Self::Conflict,
            NodeEnrolmentAuthorityError::Rejected => Self::Rejected,
            NodeEnrolmentAuthorityError::Failed => Self::Failed,
        }
    }
}

impl From<OnlineAuthorityLoadingError> for NodeEnrolmentError {
    fn from(error: OnlineAuthorityLoadingError) -> Self {
        match error {
            OnlineAuthorityLoadingError::NotFound
            | OnlineAuthorityLoadingError::NotRecipient
            | OnlineAuthorityLoadingError::Unavailable => Self::Unavailable,
            OnlineAuthorityLoadingError::Failed => Self::Failed,
        }
    }
}
