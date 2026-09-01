// SPDX-License-Identifier: GPL-2.0-only

//! Deterministic Stage 3 proof commands applied by every replicated metadata state machine.

use std::collections::BTreeMap;

use ed25519_dalek::{Signer, SigningKey};
use meshspan_consensus::LogEntry;
use meshspan_domain::{
    ApiKeyId, AuditEventId, AuthenticationMethodId, DelegatedMetadataScope, DelegationAdmission,
    EntropyError, GroupId, HandoffEvidence, HostId, JoinGrantId, MeshId, MetadataKeyRange,
    MetadataOperationFamily, NodeId, PartitionId, PrincipalId, RandomSource, Revision, RoleId,
    RootDelegatedRoute, ScopeId, UnixMicros,
};
use meshspan_metadata::{
    AUTHENTICATION_ROOT_KEY_SECRET_KIND, ActivateScopeHandoff, AuthoritativeCommand,
    BeginScopeHandoff, BootstrapAppliance, BootstrapMesh, BootstrapNodeCertificate,
    BootstrapRecoveryIdentity, CommandContext, CommitSecretGeneration, ConfirmRecoveryBundleSaved,
    ConsumeJoinGrant, CreateAuthenticationMethod, CreateGroup, CreateMetadataPartition,
    CreateScopeRoute, FreezeScopeHandoff, IssueJoinGrant, JoinRoles, NewAuthenticationCredential,
    ONLINE_AUTHORITY_KEY_SECRET_KIND, RecordName, RegisterNodeWrappingKey, RegisterRoutingSigner,
    RouteAttestation, STORAGE_PERMIT_KEY_SECRET_KIND,
};
use meshspan_secret_envelope::{
    SecretContext, WrappingPrivateKey, WrappingPublicKey, encrypt_secret,
};
use meshspan_transport::certificate_fingerprint;
use rustls::pki_types::CertificateDer;
use sha2::{Digest, Sha256};

use super::NodeRuntimeError;
use super::config::NodeConfig;

const BOOTSTRAP: u8 = 1;
const ISSUE_NODE_TWO: u8 = 2;
const ENROL_NODE_TWO: u8 = 3;
const ISSUE_NODE_THREE: u8 = 4;
const ENROL_NODE_THREE: u8 = 5;
const REGISTER_ROUTING_SIGNER: u8 = 6;
const CREATE_SECOND_PARTITION: u8 = 7;
const CREATE_SCOPE_ROUTE: u8 = 8;
const BEGIN_SCOPE_HANDOFF: u8 = 9;
const FREEZE_SCOPE_HANDOFF: u8 = 10;
const ACTIVATE_SCOPE_HANDOFF: u8 = 11;
const CONFIRM_RECOVERY: u8 = 12;
const FIRST_USER_COMMAND: u8 = 21;

pub(super) struct ProofMetadata {
    certificates: BTreeMap<NodeId, Vec<u8>>,
}

pub(super) struct DecodedCommand {
    pub context: CommandContext,
    pub command: AuthoritativeCommand,
}

impl ProofMetadata {
    pub fn load(config: &NodeConfig) -> Result<Self, NodeRuntimeError> {
        let own_certificate = std::fs::read(&config.certificate_path)?;
        let mut certificates = BTreeMap::from([(config.node_id, own_certificate)]);
        for peer in config.peers.values() {
            certificates.insert(peer.node_id, std::fs::read(&peer.certificate_path)?);
        }
        if certificates.len() != 3 {
            return Err(NodeRuntimeError::InvalidConfiguration);
        }
        Ok(Self { certificates })
    }

    pub fn decode(&self, entry: &LogEntry) -> Result<DecodedCommand, NodeRuntimeError> {
        let [kind] = entry.command.as_slice() else {
            return Err(NodeRuntimeError::InvalidConfiguration);
        };
        let command = match *kind {
            BOOTSTRAP => bootstrap()?,
            ISSUE_NODE_TWO => issue_join(2)?,
            ENROL_NODE_TWO => self.enrol(2)?,
            ISSUE_NODE_THREE => issue_join(3)?,
            ENROL_NODE_THREE => self.enrol(3)?,
            REGISTER_ROUTING_SIGNER => register_routing_signer()?,
            CREATE_SECOND_PARTITION => create_second_partition()?,
            CREATE_SCOPE_ROUTE => create_scope_route()?,
            BEGIN_SCOPE_HANDOFF => begin_scope_handoff()?,
            FREEZE_SCOPE_HANDOFF => freeze_scope_handoff()?,
            ACTIVATE_SCOPE_HANDOFF => activate_scope_handoff()?,
            CONFIRM_RECOVERY => confirm_recovery()?,
            value if value >= FIRST_USER_COMMAND => create_group(value)?,
            _ => return Err(NodeRuntimeError::InvalidConfiguration),
        };
        Ok(DecodedCommand {
            context: context(*kind, entry.operation_id)?,
            command,
        })
    }

    fn enrol(&self, number: u8) -> Result<AuthoritativeCommand, NodeRuntimeError> {
        let node_id = node_id(number)?;
        let certificate_der = self
            .certificates
            .get(&node_id)
            .cloned()
            .ok_or(NodeRuntimeError::InvalidConfiguration)?;
        let fingerprint = certificate_fingerprint(&CertificateDer::from(certificate_der.clone()));
        Ok(AuthoritativeCommand::ConsumeJoinGrant(ConsumeJoinGrant {
            join_grant_id: join_grant_id(number)?,
            secret_digest: join_secret(number),
            host_id: HostId::from_bytes([60_u8.saturating_add(number); 16])?,
            new_host_name: Some(RecordName::new(&format!("Proof host {number}"))?),
            node_id,
            node_name: RecordName::new(&format!("Proof node {number}"))?,
            incarnation: 1,
            requested_roles: proof_roles()?,
            wrapping_public_key: [70_u8.saturating_add(number); 32],
            private_endpoint: format!("proof-node-{number}.meshspan.local:7443"),
            certificate_der,
            certificate_fingerprint: fingerprint,
            certificate_valid_until: UnixMicros::new(10_000_000),
        }))
    }
}

fn bootstrap() -> Result<AuthoritativeCommand, NodeRuntimeError> {
    let administrator_id = administrator_id()?;
    let mesh = BootstrapMesh {
        mesh_id: MeshId::from_bytes([9; 16])?,
        mesh_name: RecordName::new("Stage 3 proof mesh")?,
        administrator_id,
        administrator_name: RecordName::new("Proof administrator")?,
        administrator_role_id: RoleId::from_bytes([11; 16])?,
        host_id: HostId::from_bytes([12; 16])?,
        host_name: RecordName::new("Proof host 1")?,
        node_id: node_id(1)?,
        node_name: RecordName::new("Proof node 1")?,
        partition_name: RecordName::new("Proof authority")?,
    };
    let recovery = recovery_identity()?;
    let recovery_key = WrappingPublicKey::from_bytes(recovery.public_wrapping_key)
        .map_err(|_| NodeRuntimeError::InvalidConfiguration)?;
    let node_key = WrappingPrivateKey::from_bytes([20; 32])
        .map_err(|_| NodeRuntimeError::InvalidConfiguration)?
        .public_key();
    let (permit_secret, permit_recipients) = encrypt_secret(
        SecretContext::new(STORAGE_PERMIT_KEY_SECRET_KIND, mesh.mesh_id.as_bytes(), 1)
            .map_err(|_| NodeRuntimeError::InvalidConfiguration)?,
        &[21; 32],
        &[node_key, recovery_key],
        &mut ProofRandom(22),
    )
    .map_err(|_| NodeRuntimeError::InvalidConfiguration)?;
    let (authentication_secret, authentication_recipients) = encrypt_secret(
        SecretContext::new(
            AUTHENTICATION_ROOT_KEY_SECRET_KIND,
            mesh.mesh_id.as_bytes(),
            1,
        )
        .map_err(|_| NodeRuntimeError::InvalidConfiguration)?,
        &[23; 32],
        &[node_key, recovery_key],
        &mut ProofRandom(24),
    )
    .map_err(|_| NodeRuntimeError::InvalidConfiguration)?;
    let (online_authority_secret, online_authority_recipients) = encrypt_secret(
        SecretContext::new(ONLINE_AUTHORITY_KEY_SECRET_KIND, mesh.mesh_id.as_bytes(), 1)
            .map_err(|_| NodeRuntimeError::InvalidConfiguration)?,
        &[25; 96],
        &[node_key, recovery_key],
        &mut ProofRandom(26),
    )
    .map_err(|_| NodeRuntimeError::InvalidConfiguration)?;
    Ok(AuthoritativeCommand::BootstrapAppliance(Box::new(
        BootstrapAppliance {
            mesh,
            authentication: CreateAuthenticationMethod {
                method_id: AuthenticationMethodId::from_bytes([13; 16])?,
                principal_id: administrator_id,
                label: "Initial proof API key".to_owned(),
                service_scope: 7,
                expires_at: None,
                credential: NewAuthenticationCredential::ApiKey {
                    key_id: ApiKeyId::from_bytes([14; 16])?,
                    key_digest: [15; 32],
                    scopes: 1,
                    valid_from: UnixMicros::new(1_001),
                },
            },
            recovery: Box::new(recovery),
            node_wrapping_key: RegisterNodeWrappingKey {
                node_id: node_id(1)?,
                generation: 1,
                public_key: node_key.as_bytes(),
                key_fingerprint: node_key.fingerprint(),
            },
            node_certificate: BootstrapNodeCertificate {
                certificate_der: vec![27; 64],
                certificate_fingerprint: Sha256::digest([27; 64]).into(),
                certificate_valid_until: UnixMicros::new(10_000_000),
            },
            storage_permit_key_generation: Box::new(CommitSecretGeneration {
                secret: permit_secret.parts(),
                recipients: permit_recipients
                    .iter()
                    .map(meshspan_secret_envelope::RecipientKeyEnvelope::parts)
                    .collect(),
            }),
            authentication_root_key_generation: Box::new(CommitSecretGeneration {
                secret: authentication_secret.parts(),
                recipients: authentication_recipients
                    .iter()
                    .map(meshspan_secret_envelope::RecipientKeyEnvelope::parts)
                    .collect(),
            }),
            online_authority_key_generation: Box::new(CommitSecretGeneration {
                secret: online_authority_secret.parts(),
                recipients: online_authority_recipients
                    .iter()
                    .map(meshspan_secret_envelope::RecipientKeyEnvelope::parts)
                    .collect(),
            }),
        },
    )))
}

struct ProofRandom(u8);

impl RandomSource for ProofRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        for byte in destination {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}

fn recovery_identity() -> Result<BootstrapRecoveryIdentity, NodeRuntimeError> {
    let public_key = WrappingPublicKey::from_bytes([16; 32])
        .map_err(|_| NodeRuntimeError::InvalidConfiguration)?;
    let certificate = vec![17; 64];
    let online_certificate = vec![27; 64];
    Ok(BootstrapRecoveryIdentity {
        public_wrapping_key: public_key.as_bytes(),
        key_fingerprint: public_key.fingerprint(),
        root_certificate_digest: Sha256::digest(&certificate).into(),
        root_certificate_der: certificate,
        online_authority_certificate_digest: Sha256::digest(&online_certificate).into(),
        online_authority_certificate_der: online_certificate,
        bundle_digest: [18; 32],
        save_challenge_commitment: [19; 32],
    })
}

fn confirm_recovery() -> Result<AuthoritativeCommand, NodeRuntimeError> {
    Ok(AuthoritativeCommand::ConfirmRecoveryBundleSaved(
        ConfirmRecoveryBundleSaved {
            mesh_id: MeshId::from_bytes([9; 16])?,
            bundle_digest: [18; 32],
            save_challenge_commitment: [19; 32],
        },
    ))
}

fn issue_join(number: u8) -> Result<AuthoritativeCommand, NodeRuntimeError> {
    Ok(AuthoritativeCommand::IssueJoinGrant(IssueJoinGrant {
        join_grant_id: join_grant_id(number)?,
        secret_digest: join_secret(number),
        allowed_roles: proof_roles()?,
        maximum_uses: 1,
        expires_at: UnixMicros::new(9_000_000),
    }))
}

fn create_group(value: u8) -> Result<AuthoritativeCommand, NodeRuntimeError> {
    Ok(AuthoritativeCommand::CreateGroup(CreateGroup {
        group_id: GroupId::from_bytes([value; 16])?,
        name: RecordName::new(&format!("Proof group {value}"))?,
        activation_policy_id: None,
    }))
}

fn register_routing_signer() -> Result<AuthoritativeCommand, NodeRuntimeError> {
    Ok(AuthoritativeCommand::RegisterRoutingSigner(
        RegisterRoutingSigner {
            node_id: node_id(1)?,
            generation: 1,
            verifying_key: routing_signing_key().verifying_key().to_bytes(),
        },
    ))
}

fn create_second_partition() -> Result<AuthoritativeCommand, NodeRuntimeError> {
    Ok(AuthoritativeCommand::CreateMetadataPartition(
        CreateMetadataPartition {
            partition_id: destination_partition()?,
            name: RecordName::new("Proof namespace partition")?,
            partition_kind: 2,
        },
    ))
}

fn create_scope_route() -> Result<AuthoritativeCommand, NodeRuntimeError> {
    let route = initial_route()?;
    Ok(AuthoritativeCommand::CreateScopeRoute(CreateScopeRoute {
        root_partition_id: source_partition()?,
        scope: proof_delegated_scope()?,
        routing_epoch: 1,
        attestation: attest(&route)?,
    }))
}

fn begin_scope_handoff() -> Result<AuthoritativeCommand, NodeRuntimeError> {
    let mut route = initial_route()?;
    route
        .begin_delegation(destination_partition()?, 2, delegation_admission()?)
        .map_err(|_| NodeRuntimeError::InvalidConfiguration)?;
    Ok(AuthoritativeCommand::BeginScopeHandoff(BeginScopeHandoff {
        scope_id: proof_scope()?,
        destination_partition_id: destination_partition()?,
        routing_epoch: 2,
        admission: delegation_admission()?,
        attestation: attest(&route)?,
    }))
}

fn freeze_scope_handoff() -> Result<AuthoritativeCommand, NodeRuntimeError> {
    let mut route = preparing_route()?;
    let evidence = handoff_evidence();
    route
        .freeze(2, evidence)
        .map_err(|_| NodeRuntimeError::InvalidConfiguration)?;
    Ok(AuthoritativeCommand::FreezeScopeHandoff(
        FreezeScopeHandoff {
            scope_id: proof_scope()?,
            routing_epoch: 2,
            evidence,
            attestation: attest(&route)?,
        },
    ))
}

fn activate_scope_handoff() -> Result<AuthoritativeCommand, NodeRuntimeError> {
    let mut route = preparing_route()?;
    let evidence = handoff_evidence();
    let destination = destination_partition()?;
    route
        .freeze(2, evidence)
        .and_then(|()| route.activate(destination, 2, evidence))
        .map_err(|_| NodeRuntimeError::InvalidConfiguration)?;
    Ok(AuthoritativeCommand::ActivateScopeHandoff(
        ActivateScopeHandoff {
            scope_id: proof_scope()?,
            destination_partition_id: destination,
            routing_epoch: 2,
            evidence,
            attestation: attest(&route)?,
        },
    ))
}

fn initial_route() -> Result<RootDelegatedRoute, NodeRuntimeError> {
    RootDelegatedRoute::new(source_partition()?, proof_delegated_scope()?, 1, 1)
        .map_err(|_| NodeRuntimeError::InvalidConfiguration)
}

fn preparing_route() -> Result<RootDelegatedRoute, NodeRuntimeError> {
    let mut route = initial_route()?;
    route
        .begin_delegation(destination_partition()?, 2, delegation_admission()?)
        .map_err(|_| NodeRuntimeError::InvalidConfiguration)?;
    Ok(route)
}

fn attest(route: &RootDelegatedRoute) -> Result<RouteAttestation, NodeRuntimeError> {
    let signature = routing_signing_key()
        .sign(&route.signing_payload())
        .to_bytes();
    Ok(RouteAttestation {
        signer_node_id: node_id(1)?,
        signer_generation: 1,
        signature,
    })
}

fn proof_delegated_scope() -> Result<DelegatedMetadataScope, NodeRuntimeError> {
    DelegatedMetadataScope::new(
        proof_scope()?,
        MetadataOperationFamily::Namespace,
        MetadataKeyRange::All,
    )
    .map_err(|_| NodeRuntimeError::InvalidConfiguration)
}

fn delegation_admission() -> Result<DelegationAdmission, NodeRuntimeError> {
    DelegationAdmission::new(3, 3, [79; 32], [80; 32], UnixMicros::new(8))
        .map_err(|_| NodeRuntimeError::InvalidConfiguration)
}

fn routing_signing_key() -> SigningKey {
    SigningKey::from_bytes(&[77; 32])
}

fn handoff_evidence() -> HandoffEvidence {
    HandoffEvidence {
        frozen_revision: Revision::new(9),
        snapshot_digest: [78; 32],
    }
}

fn context(
    value: u8,
    operation_id: meshspan_domain::OperationId,
) -> Result<CommandContext, NodeRuntimeError> {
    Ok(CommandContext {
        operation_id,
        actor_principal_id: administrator_id()?,
        audit_event_id: AuditEventId::from_bytes([value.wrapping_add(100); 16])?,
        occurred_at: UnixMicros::new(1_000 + i64::from(value)),
        expected_revision: Some(Revision::new(expected_revision(value)?)),
    })
}

fn expected_revision(value: u8) -> Result<u64, NodeRuntimeError> {
    match value {
        BOOTSTRAP => Ok(0),
        CONFIRM_RECOVERY => Ok(1),
        ISSUE_NODE_TWO => Ok(2),
        ENROL_NODE_TWO => Ok(3),
        ISSUE_NODE_THREE => Ok(4),
        ENROL_NODE_THREE => Ok(5),
        REGISTER_ROUTING_SIGNER => Ok(6),
        CREATE_SECOND_PARTITION => Ok(7),
        CREATE_SCOPE_ROUTE => Ok(8),
        BEGIN_SCOPE_HANDOFF => Ok(9),
        FREEZE_SCOPE_HANDOFF => Ok(10),
        ACTIVATE_SCOPE_HANDOFF => Ok(11),
        value if value >= FIRST_USER_COMMAND => Ok(u64::from(value - FIRST_USER_COMMAND) + 12),
        _ => Err(NodeRuntimeError::InvalidConfiguration),
    }
}

fn proof_roles() -> Result<JoinRoles, NodeRuntimeError> {
    JoinRoles::new(JoinRoles::STORAGE | JoinRoles::GATEWAY | JoinRoles::METADATA_ELIGIBLE)
        .map_err(Into::into)
}

fn administrator_id() -> Result<PrincipalId, NodeRuntimeError> {
    PrincipalId::from_bytes([10; 16]).map_err(Into::into)
}

fn node_id(number: u8) -> Result<NodeId, NodeRuntimeError> {
    NodeId::from_bytes([number; 16]).map_err(Into::into)
}

fn source_partition() -> Result<PartitionId, NodeRuntimeError> {
    PartitionId::from_bytes([8; 16]).map_err(Into::into)
}

fn destination_partition() -> Result<PartitionId, NodeRuntimeError> {
    PartitionId::from_bytes([6; 16]).map_err(Into::into)
}

fn proof_scope() -> Result<ScopeId, NodeRuntimeError> {
    ScopeId::from_bytes([70; 16]).map_err(Into::into)
}

fn join_grant_id(number: u8) -> Result<JoinGrantId, NodeRuntimeError> {
    JoinGrantId::from_bytes([40_u8.saturating_add(number); 16]).map_err(Into::into)
}

const fn join_secret(number: u8) -> [u8; 32] {
    [50_u8.saturating_add(number); 32]
}
