// SPDX-License-Identifier: GPL-2.0-only

//! Restart-safe headless admission into an existing mesh.

use std::net::SocketAddr;

use meshspan_api_contract::{
    EnrolNodeRequest, EnrolNodeResponse, MAX_ENROL_NODE_BYTES, NodeJoinHost, NodeJoinRole,
    OperationId as ApiOperationId, SetupName, decode_enrol_node_response,
    encode_enrol_node_request,
};
use meshspan_cluster::{
    ConsensusNetwork, ConsensusNetworkConfig, ConsensusPeerConfig, PeerConsensusMessage,
    PeerControlRequest, PeerDataStream,
};
use meshspan_consensus::ActiveQuorumPlan;
use meshspan_domain::{
    BackupId, InitialBootstrapMaterial, JoinGrantBundle, OperationId, PartitionId, Revision,
    SnapshotId, UnixMicros, uuid_v8,
};
use meshspan_metadata::{
    JoinRoles, LocalSetupKind, LocalSetupState, LogPosition as MetadataLogPosition, NewLocalSetup,
    PartitionBackupManifest, PartitionSnapshotManifest, PreservedVote, RecordName,
    restore_partition_snapshot,
};
use meshspan_protocol::v1::control_envelope::Message;
use meshspan_protocol::v1::{
    ControlEnvelope, NodeActivationRequest, NodeActivationResult, NodeRole, OperationOutcome,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::claim_file::{ClaimFile, ClaimFileError};
use crate::node_enrolment::{NodeEnrolmentTranscript, derived_new_host_id};
use crate::pinned_https_client::{PinnedHttpsClientError, post_pinned_json};
use crate::private_consensus_runtime::certificate_name;
use crate::protected_file::{self, ProtectedFileError, PublishMode};
use crate::{DaemonLocalState, DaemonLocalStateError, HeadlessDaemonConfig};

const ENROLMENT_ROUTE: &str = "/api/latest/setup/enrolments";
const OPERATION_ID_DOMAIN: &[u8] = b"meshspan.headless-join.operation-id.v1\0";
const REQUEST_DIGEST_DOMAIN: &[u8] = b"meshspan.headless-join.request.v1\0";
const RESULT_DIGEST_DOMAIN: &[u8] = b"meshspan.headless-join.result.v1\0";
const ACTIVATION_OPERATION_ID_DOMAIN: &[u8] = b"meshspan.headless-join.activation.v1\0";
const ROOT_AUTHORITY_DATABASE: &str = "root-authority.sqlite3";
const PRIVATE_OPERATION_TIMEOUT_MICROS: i64 = 30 * 1_000_000;

pub(crate) struct HeadlessJoinNetwork {
    pub network: ConsensusNetwork,
    pub peer_messages: tokio::sync::mpsc::Receiver<PeerConsensusMessage>,
    pub control_requests: tokio::sync::mpsc::Receiver<PeerControlRequest>,
}

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
    let host_name = setup_name("host", node_id)?;
    let node_name = setup_name("node", node_id)?;
    let operation_bytes =
        derived_operation_id(invitation.join_grant_id().as_bytes(), node_id.as_bytes());
    let operation_id = ApiOperationId::from_uuid_bytes(operation_bytes)
        .ok_or(HeadlessNodeJoinError::InvalidLocalState)?;
    admit_node(
        local_state,
        invitation,
        operation_id,
        host_name,
        node_name,
        private_endpoint,
        now,
    )
    .await
    .map(Some)
}

/// Admits one locally claimed daemon using names supplied by either headless configuration or UI.
///
/// This is the single enrolment implementation for every first-start presentation. The caller
/// controls only bounded display names and the advertised private endpoint; the invitation pins
/// the remote HTTPS origin, certificate and authoritative mesh identity.
pub(crate) async fn admit_node(
    local_state: &mut DaemonLocalState,
    invitation: &JoinGrantBundle,
    api_operation_id: ApiOperationId,
    host_name: SetupName,
    node_name: SetupName,
    private_endpoint: &str,
    now: UnixMicros,
) -> Result<EnrolNodeResponse, HeadlessNodeJoinError> {
    let node_id = local_state.node_id();
    let operation_id = OperationId::from_bytes(parse_uuid(api_operation_id.as_str())?)
        .map_err(|_| HeadlessNodeJoinError::InvalidLocalState)?;
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
    Ok(response)
}

/// Activates an admitted node, installs the authoritative snapshot and consumes its local claim.
///
/// The public setup UI and headless startup both enter through this exact implementation.
pub(crate) async fn activate_and_install_node(
    local_state: &mut DaemonLocalState,
    private_listen: SocketAddr,
    admission: &EnrolNodeResponse,
    data_streams: tokio::sync::mpsc::Sender<PeerDataStream>,
    now: UnixMicros,
) -> Result<HeadlessJoinNetwork, HeadlessNodeJoinError> {
    let local_node_id = local_state.node_id();
    let prepared = prepare_join_network(local_state, private_listen, admission).await?;
    let partition_id = prepared.partition_id;
    let mesh_id = prepared.config.mesh_id;
    let (peer_messages, received_peer_messages) = tokio::sync::mpsc::channel(256);
    let (control_requests, received_control_requests) = tokio::sync::mpsc::channel(64);
    let (snapshots, mut received_snapshots) = tokio::sync::mpsc::channel(1);
    let network = ConsensusNetwork::start_with_control_snapshots_and_data(
        prepared.config,
        peer_messages,
        control_requests,
        snapshots,
        data_streams,
    )?;
    activate_joined_node(&network, admission, local_node_id, now).await?;
    let received = tokio::time::timeout(
        std::time::Duration::from_micros(
            u64::try_from(PRIVATE_OPERATION_TIMEOUT_MICROS)
                .map_err(|_| HeadlessNodeJoinError::PrivateNetwork)?,
        ),
        received_snapshots.recv(),
    )
    .await
    .map_err(|_| HeadlessNodeJoinError::PrivateNetwork)?
    .ok_or(HeadlessNodeJoinError::PrivateNetwork)?;
    install_join_snapshot(local_state, mesh_id, partition_id, received, now)?;
    complete_join_setup(local_state, now)?;
    Ok(HeadlessJoinNetwork {
        network,
        peer_messages: received_peer_messages,
        control_requests: received_control_requests,
    })
}

struct PreparedJoinNetwork {
    config: ConsensusNetworkConfig,
    partition_id: PartitionId,
}

async fn prepare_join_network(
    local_state: &DaemonLocalState,
    private_listen: SocketAddr,
    admission: &EnrolNodeResponse,
) -> Result<PreparedJoinNetwork, HeadlessNodeJoinError> {
    let mesh_id = meshspan_domain::MeshId::from_bytes(parse_uuid(&admission.mesh_id)?)
        .map_err(|_| HeadlessNodeJoinError::InvalidAdmissionResponse)?;
    let partition_id = PartitionId::from_bytes(parse_uuid(&admission.root_partition_id)?)
        .map_err(|_| HeadlessNodeJoinError::InvalidAdmissionResponse)?;
    let mut peers = Vec::with_capacity(admission.bootstrap_peers.len());
    for peer in &admission.bootstrap_peers {
        let node_id = meshspan_domain::NodeId::from_bytes(parse_uuid(&peer.node_id)?)
            .map_err(|_| HeadlessNodeJoinError::InvalidAdmissionResponse)?;
        let address = tokio::net::lookup_host(&peer.private_endpoint)
            .await
            .map_err(|_| HeadlessNodeJoinError::PrivateNetwork)?
            .next()
            .ok_or(HeadlessNodeJoinError::PrivateNetwork)?;
        peers.push(ConsensusPeerConfig {
            node_id,
            incarnation: 1,
            address,
            certificate_der: decode_hex_vec(&peer.certificate_der_hex)?,
            certificate_name: certificate_name(node_id),
        });
    }
    let client_address = if private_listen.is_ipv4() {
        std::net::SocketAddr::from(([0, 0, 0, 0], 0))
    } else {
        std::net::SocketAddr::from(([0_u16; 8], 0))
    };
    Ok(PreparedJoinNetwork {
        config: ConsensusNetworkConfig {
            local_node_id: local_state.node_id(),
            local_incarnation: 1,
            mesh_id,
            partition_id,
            routing_epoch: admission.routing_epoch,
            roles: vec![
                NodeRole::Storage,
                NodeRole::Gateway,
                NodeRole::MetadataLearner,
            ],
            listen_address: private_listen,
            client_address,
            certificate_chain_der: vec![
                decode_hex_vec(&admission.node_certificate_der_hex)?,
                decode_hex_vec(&admission.online_authority_certificate_der_hex)?,
            ],
            private_key_pkcs8: zeroize::Zeroizing::new(
                local_state.node_identity_private_key_pkcs8().to_vec(),
            ),
            trust_anchors: vec![decode_hex_vec(&admission.root_certificate_der_hex)?],
            peers,
            snapshot_staging_path: Some(
                local_state.state_directory().join(ROOT_AUTHORITY_DATABASE),
            ),
        },
        partition_id,
    })
}

async fn activate_joined_node(
    network: &ConsensusNetwork,
    admission: &EnrolNodeResponse,
    local_node_id: meshspan_domain::NodeId,
    now: UnixMicros,
) -> Result<(), HeadlessNodeJoinError> {
    let activation_operation = activation_operation_id(local_node_id)?;
    let deadline = now
        .get()
        .checked_add(PRIVATE_OPERATION_TIMEOUT_MICROS)
        .ok_or(HeadlessNodeJoinError::PrivateNetwork)?;
    let request = ControlEnvelope {
        header: Some(network.control_header(activation_operation, deadline)?),
        message: Some(Message::NodeActivationRequest(NodeActivationRequest {
            roles: vec![
                NodeRole::Storage.into(),
                NodeRole::Gateway.into(),
                NodeRole::MetadataLearner.into(),
            ],
            capability_digest: network.local_capability_digest().to_vec(),
        })),
    };
    let target = admission
        .bootstrap_peers
        .first()
        .ok_or(HeadlessNodeJoinError::InvalidAdmissionResponse)?;
    let target_id = meshspan_domain::NodeId::from_bytes(parse_uuid(&target.node_id)?)
        .map_err(|_| HeadlessNodeJoinError::InvalidAdmissionResponse)?;
    let response = network.request_control(target_id, &request).await?;
    validate_activation_result(&response)
}

fn validate_activation_result(
    response: &meshspan_protocol::ValidatedControlEnvelope,
) -> Result<(), HeadlessNodeJoinError> {
    let Some(Message::NodeActivationResult(NodeActivationResult {
        result: Some(result),
        active_revision: Some(active_revision),
    })) = response.as_inner().message.as_ref()
    else {
        return Err(HeadlessNodeJoinError::InvalidActivationResponse);
    };
    if result.outcome != i32::from(OperationOutcome::Durable)
        || result.committed_revision != Some(*active_revision)
        || result.error.is_some()
        || result.result_digest.len() != 32
    {
        return Err(HeadlessNodeJoinError::InvalidActivationResponse);
    }
    Ok(())
}

fn install_join_snapshot(
    local_state: &DaemonLocalState,
    mesh_id: meshspan_domain::MeshId,
    partition_id: PartitionId,
    received: meshspan_cluster::ReceivedConsensusSnapshot,
    now: UnixMicros,
) -> Result<(), HeadlessNodeJoinError> {
    let active = ActiveQuorumPlan::decode(&received.snapshot.quorum_plan)
        .map_err(|_| HeadlessNodeJoinError::InvalidSnapshot)?;
    let ActiveQuorumPlan::Stable(plan) = active else {
        return Err(HeadlessNodeJoinError::InvalidSnapshot);
    };
    if !plan.spec().voters.contains(&received.from)
        || !plan.spec().learners.contains(&local_state.node_id())
        || plan.proof_digest() != received.snapshot.quorum_plan_digest
        || plan.spec().membership_epoch != received.snapshot.membership_epoch
    {
        return Err(HeadlessNodeJoinError::InvalidSnapshot);
    }
    let snapshot_id = SnapshotId::from_bytes(received.snapshot.snapshot_id)
        .map_err(|_| HeadlessNodeJoinError::InvalidSnapshot)?;
    let included = received.snapshot.included_position;
    let manifest = PartitionSnapshotManifest {
        snapshot_id,
        backup: PartitionBackupManifest {
            backup_id: BackupId::from_bytes(snapshot_id.as_bytes())
                .map_err(|_| HeadlessNodeJoinError::InvalidSnapshot)?,
            partition_id,
            mesh_id,
            applied_position: MetadataLogPosition {
                term: included.term,
                index: included.index,
            },
            state_revision: Revision::new(received.snapshot.state_revision),
            schema_version: received.snapshot.format_version,
            byte_length: received.snapshot.total_bytes,
            digest: received.snapshot.digest,
            created_at: now,
        },
        membership_epoch: received.snapshot.membership_epoch,
        quorum_plan_digest: received.snapshot.quorum_plan_digest,
    };
    let destination = local_state.state_directory().join(ROOT_AUTHORITY_DATABASE);
    let database = restore_partition_snapshot(
        &received.snapshot.staging_path,
        &destination,
        manifest,
        &plan,
        PreservedVote {
            current_term: 1,
            voted_for: None,
            membership_epoch: 0,
        },
        now,
    )?;
    let membership = meshspan_metadata::AuthoritativeRepository::new(database)
        .partition_membership()?
        .ok_or(HeadlessNodeJoinError::InvalidSnapshot)?;
    if membership.admitted_learners().get(&local_state.node_id()) != Some(&1) {
        return Err(HeadlessNodeJoinError::InvalidSnapshot);
    }
    received
        .installed
        .send(())
        .map_err(|()| HeadlessNodeJoinError::PrivateNetwork)
}

fn complete_join_setup(
    local_state: &mut DaemonLocalState,
    now: UnixMicros,
) -> Result<(), HeadlessNodeJoinError> {
    let setup = local_state
        .local_database()
        .local_setup()?
        .ok_or(HeadlessNodeJoinError::InvalidLocalState)?;
    let claim = ClaimFile::read(local_state.claim_output_path())?;
    local_state.local_database_mut().complete_local_setup(
        setup.operation_id,
        claim.claim_id(),
        claim.secret_digest(),
        now,
    )?;
    ClaimFile::remove_if_matches(
        local_state.claim_output_path(),
        claim.claim_id(),
        claim.secret_digest(),
    )?;
    Ok(())
}

fn activation_operation_id(
    node_id: meshspan_domain::NodeId,
) -> Result<OperationId, HeadlessNodeJoinError> {
    let bytes = digest(ACTIVATION_OPERATION_ID_DOMAIN, &node_id.as_bytes());
    let mut exact: [u8; 16] = bytes[..16]
        .try_into()
        .map_err(|_| HeadlessNodeJoinError::InvalidLocalState)?;
    exact = uuid_v8(exact);
    OperationId::from_bytes(exact).map_err(|_| HeadlessNodeJoinError::InvalidLocalState)
}

fn parse_uuid(value: &str) -> Result<[u8; 16], HeadlessNodeJoinError> {
    crate::create_mesh_setup::parse_uuid(value)
        .map_err(|_| HeadlessNodeJoinError::InvalidAdmissionResponse)
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

fn decode_hex_vec(value: &str) -> Result<Vec<u8>, HeadlessNodeJoinError> {
    if value.is_empty() || !value.len().is_multiple_of(2) {
        return Err(HeadlessNodeJoinError::InvalidAdmissionResponse);
    }
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let high =
                decode_nibble(pair[0]).ok_or(HeadlessNodeJoinError::InvalidAdmissionResponse)?;
            let low =
                decode_nibble(pair[1]).ok_or(HeadlessNodeJoinError::InvalidAdmissionResponse)?;
            Ok((high << 4) | low)
        })
        .collect()
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
    #[error("headless node activation response is invalid")]
    InvalidActivationResponse,
    #[error("headless node admission snapshot is invalid")]
    InvalidSnapshot,
    #[error("headless node private network failed")]
    PrivateNetwork,
    #[error("headless node private transport failed")]
    ConsensusNetwork(#[from] meshspan_cluster::ConsensusNetworkError),
    #[error("headless node metadata query failed")]
    Repository(#[from] meshspan_metadata::RepositoryError),
    #[error("headless node claim failed")]
    Claim(#[from] ClaimFileError),
    #[error("headless node identity failed")]
    LocalState(#[from] DaemonLocalStateError),
    #[error("headless node setup journal failed")]
    Setup(#[from] meshspan_metadata::LocalSetupError),
    #[error("headless node protected receipt failed")]
    ProtectedReceipt(#[from] ProtectedFileError),
    // The nested enum contains only closed, payload-free failure categories.
    #[error("headless node HTTPS admission failed: {0}")]
    Https(#[from] PinnedHttpsClientError),
}
