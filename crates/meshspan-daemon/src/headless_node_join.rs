// SPDX-License-Identifier: GPL-2.0-only

//! Restart-safe headless admission into an existing mesh.

use meshspan_api_contract::{
    EnrolNodeRequest, EnrolNodeResponse, MAX_ENROL_NODE_BYTES, NodeJoinHost, NodeJoinRole,
    OperationId as ApiOperationId, SetupName, decode_enrol_node_response,
    encode_enrol_node_request,
};
use meshspan_domain::{InitialBootstrapMaterial, OperationId, UnixMicros, uuid_v8};
use meshspan_metadata::{JoinRoles, LocalSetupKind, LocalSetupState, NewLocalSetup, RecordName};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::claim_file::{ClaimFile, ClaimFileError};
use crate::node_enrolment::{NodeEnrolmentTranscript, derived_new_host_id};
use crate::pinned_https_client::{PinnedHttpsClientError, post_pinned_json};
use crate::protected_file::{self, ProtectedFileError, PublishMode};
use crate::{DaemonLocalState, DaemonLocalStateError, HeadlessDaemonConfig};

const ENROLMENT_ROUTE: &str = "/api/latest/setup/enrolments";
const OPERATION_ID_DOMAIN: &[u8] = b"meshspan.headless-join.operation-id.v1\0";
const REQUEST_DIGEST_DOMAIN: &[u8] = b"meshspan.headless-join.request.v1\0";
const RESULT_DIGEST_DOMAIN: &[u8] = b"meshspan.headless-join.result.v1\0";

/// Admits an unconfigured daemon through the invitation-pinned HTTPS boundary.
///
/// The local first-boot claim remains active. It is consumed only after private activation and
/// metadata catch-up have completed, so an HTTPS response alone can never report configured.
pub(crate) async fn admit_headless_node(
    local_state: &mut DaemonLocalState,
    config: &HeadlessDaemonConfig,
    private_endpoint: &str,
    now: UnixMicros,
) -> Result<Option<EnrolNodeResponse>, HeadlessNodeJoinError> {
    let Some(invitation) = config.join_grant() else {
        return Ok(None);
    };
    let node_id = local_state.node_id();
    let operation_bytes =
        derived_operation_id(invitation.join_grant_id().as_bytes(), node_id.as_bytes());
    let operation_id = OperationId::from_bytes(operation_bytes)
        .map_err(|_| HeadlessNodeJoinError::InvalidLocalState)?;
    let api_operation_id = ApiOperationId::from_uuid_bytes(operation_bytes)
        .ok_or(HeadlessNodeJoinError::InvalidLocalState)?;
    let host_name = setup_name("host", node_id)?;
    let node_name = setup_name("node", node_id)?;
    let host_record_name = RecordName::new(host_name.as_str())
        .map_err(|_| HeadlessNodeJoinError::InvalidLocalState)?;
    let node_record_name = RecordName::new(node_name.as_str())
        .map_err(|_| HeadlessNodeJoinError::InvalidLocalState)?;
    let host_id = derived_new_host_id(operation_id, node_id, &host_record_name)
        .map_err(|_| HeadlessNodeJoinError::InvalidLocalState)?;
    let requested_roles = requested_roles();
    let join_roles =
        JoinRoles::new(JoinRoles::STORAGE | JoinRoles::GATEWAY | JoinRoles::METADATA_ELIGIBLE)
            .map_err(|_| HeadlessNodeJoinError::InvalidLocalState)?;
    let wrapping_public_key = local_state.wrapping_public_key().as_bytes();
    let transcript = NodeEnrolmentTranscript {
        mesh_id: invitation.mesh_id(),
        join_grant_id: invitation.join_grant_id(),
        operation_id,
        host_id,
        new_host_name: Some(&host_record_name),
        node_name: &node_record_name,
        requested_roles: join_roles,
        wrapping_public_key,
        private_endpoint,
    }
    .encode();
    let proof = local_state.sign_node_enrolment_transcript(&transcript)?;
    let request = EnrolNodeRequest {
        operation_id: api_operation_id,
        join_code: invitation.expose_encoded().to_string(),
        host: NodeJoinHost::New { name: host_name },
        node_name,
        requested_roles,
        node_identity_public_key_hex: encode_hex(local_state.node_identity_public_key()),
        identity_proof_signature_hex: encode_hex(&proof),
        wrapping_public_key_hex: encode_hex(&wrapping_public_key),
        private_endpoint: private_endpoint.to_owned(),
    };
    let request_bytes = encode_enrol_node_request(&request)
        .map_err(|_| HeadlessNodeJoinError::InvalidLocalState)?;
    let request_digest = digest(REQUEST_DIGEST_DOMAIN, &request_bytes);
    let claim = ClaimFile::read(local_state.claim_output_path())?;
    local_state
        .local_database_mut()
        .prepare_local_setup(NewLocalSetup {
            operation_id,
            claim_id: claim.claim_id(),
            claim_secret_digest: claim.secret_digest(),
            kind: LocalSetupKind::JoinMesh,
            request_digest,
            created_at: now,
        })?;

    let receipt_path = local_state.pending_node_enrolment_path();
    let response_bytes = match protected_file::read_bounded(&receipt_path, 2, MAX_ENROL_NODE_BYTES)
    {
        Ok(bytes) => bytes.to_vec(),
        Err(ProtectedFileError::Missing) => {
            let response = post_pinned_json(
                invitation.enrolment_endpoint(),
                ENROLMENT_ROUTE,
                invitation.gateway_certificate_fingerprint(),
                &request_bytes,
                MAX_ENROL_NODE_BYTES,
            )
            .await?;
            protected_file::publish(&receipt_path, &response, PublishMode::Create)?;
            response
        }
        Err(error) => return Err(error.into()),
    };
    let response = decode_enrol_node_response(&response_bytes)
        .map_err(|_| HeadlessNodeJoinError::InvalidAdmissionResponse)?;
    validate_response(&response, &request, invitation.mesh_id(), node_id)?;
    let result_digest = digest(RESULT_DIGEST_DOMAIN, &response_bytes);
    let setup = local_state
        .local_database()
        .local_setup()?
        .ok_or(HeadlessNodeJoinError::InvalidLocalState)?;
    if setup.state == LocalSetupState::Prepared {
        local_state
            .local_database_mut()
            .record_local_setup_authority_commit(operation_id, result_digest, now)?;
    } else if setup.authority_result_digest != Some(result_digest) {
        return Err(HeadlessNodeJoinError::InvalidLocalState);
    }
    Ok(Some(response))
}

fn derived_operation_id(join_grant_id: [u8; 16], node_id: [u8; 16]) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(OPERATION_ID_DOMAIN);
    digest.update(join_grant_id);
    digest.update(node_id);
    let mut value = [0_u8; 16];
    value.copy_from_slice(&digest.finalize()[..16]);
    uuid_v8(value)
}

fn setup_name(
    prefix: &str,
    node_id: meshspan_domain::NodeId,
) -> Result<SetupName, HeadlessNodeJoinError> {
    let suffix = node_id.to_string();
    SetupName::parse(&format!("{prefix}-{}", &suffix[..12]))
        .ok_or(HeadlessNodeJoinError::InvalidLocalState)
}

fn requested_roles() -> Vec<NodeJoinRole> {
    vec![
        NodeJoinRole::Storage,
        NodeJoinRole::Gateway,
        NodeJoinRole::MetadataEligible,
    ]
}

fn validate_response(
    response: &EnrolNodeResponse,
    request: &EnrolNodeRequest,
    mesh_id: meshspan_domain::MeshId,
    node_id: meshspan_domain::NodeId,
) -> Result<(), HeadlessNodeJoinError> {
    if response.operation_id != request.operation_id
        || response.mesh_id != crate::create_mesh_setup::format_uuid(mesh_id.as_bytes())
        || response.node_id != crate::create_mesh_setup::format_uuid(node_id.as_bytes())
        || response.routing_epoch == 0
        || response.bootstrap_peers.is_empty()
        || response
            .bootstrap_peers
            .iter()
            .any(|peer| peer.node_id == response.node_id)
    {
        return Err(HeadlessNodeJoinError::InvalidAdmissionResponse);
    }
    let public_identity = meshspan_certificates::NodePublicIdentity::from_sec1(&decode_hex::<65>(
        &request.node_identity_public_key_hex,
    )?)
    .map_err(|_| HeadlessNodeJoinError::InvalidAdmissionResponse)?;
    if InitialBootstrapMaterial::node_id(public_identity.public_key_fingerprint())
        .map_err(|_| HeadlessNodeJoinError::InvalidAdmissionResponse)?
        != node_id
    {
        return Err(HeadlessNodeJoinError::InvalidAdmissionResponse);
    }
    for value in [
        &response.node_certificate_der_hex,
        &response.online_authority_certificate_der_hex,
        &response.root_certificate_der_hex,
    ] {
        if value.is_empty() || value.len() % 2 != 0 {
            return Err(HeadlessNodeJoinError::InvalidAdmissionResponse);
        }
    }
    Ok(())
}

fn digest(domain: &[u8], value: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(value);
    digest.finalize().into()
}

fn encode_hex(value: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn decode_hex<const N: usize>(value: &str) -> Result<[u8; N], HeadlessNodeJoinError> {
    if value.len() != N * 2 {
        return Err(HeadlessNodeJoinError::InvalidAdmissionResponse);
    }
    let mut decoded = [0_u8; N];
    for (destination, pair) in decoded.iter_mut().zip(value.as_bytes().as_chunks::<2>().0) {
        let high = decode_nibble(pair[0]).ok_or(HeadlessNodeJoinError::InvalidAdmissionResponse)?;
        let low = decode_nibble(pair[1]).ok_or(HeadlessNodeJoinError::InvalidAdmissionResponse)?;
        *destination = (high << 4) | low;
    }
    Ok(decoded)
}

const fn decode_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        _ => None,
    }
}

#[derive(Debug, Error)]
pub(crate) enum HeadlessNodeJoinError {
    #[error("headless node join local state is invalid")]
    InvalidLocalState,
    #[error("headless node admission response is invalid")]
    InvalidAdmissionResponse,
    #[error("headless node claim failed")]
    Claim(#[from] ClaimFileError),
    #[error("headless node identity failed")]
    LocalState(#[from] DaemonLocalStateError),
    #[error("headless node setup journal failed")]
    Setup(#[from] meshspan_metadata::LocalSetupError),
    #[error("headless node protected receipt failed")]
    ProtectedReceipt(#[from] ProtectedFileError),
    #[error("headless node HTTPS admission failed")]
    Https(#[from] PinnedHttpsClientError),
}
