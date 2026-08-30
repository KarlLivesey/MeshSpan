// SPDX-License-Identifier: GPL-2.0-only

use ed25519_dalek::SigningKey;
use meshspan_contracts::{
    BoundedItems, FederatedStoragePermitMacKey, verify_federated_shard_permit_mac,
};
use meshspan_data_plane::decode_federated_shard_permit;
use meshspan_domain::{
    AuditEventId, DurationMicros, FederatedPrincipal, FederationGrant, FederationGrantId,
    FederationPolicy, FederationRelationshipId, FederationRelationshipKind,
    FederationResourceScope, FederationStorageAllocation, FederationStorageAllocationId, HostId,
    MeshId, NodeId, OperationId, PartitionId, PrincipalId, Revision, RoleId,
    StorageFederationPolicy, StorageParticipation, TargetId, UnixMicros,
};
use meshspan_metadata::{
    ApproveFederationRelationship, AuthoritativeCommand, AuthoritativeRepository, BootstrapMesh,
    CommandContext, FederationGovernanceDirection, FederationGrantRestriction,
    FederationStorageQuotaDisposition, FederationTrustIdentity, IssueFederationGrant,
    IssueFederationStorageAllocation, LocalDatabase, LogPosition, PartitionDatabase,
    ProposeFederationRelationship, RecordName,
};
use meshspan_protocol::v1::federation_envelope::Message;
use meshspan_protocol::v1::{
    ProtocolVersion, RemoteShardAction, RequestFederatedStorageCapability, ShardIdentity,
};
use meshspan_protocol::{WireLimits, federation_storage_capability_request_digest_payload};
use meshspan_transport::{
    FederationExchangeContext, FederationLocalIdentity, FederationLocalIdentityBinding,
};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

use super::{
    AdmittedRequest, FederationStorageCapabilityIssuer, FederationStorageCapabilityIssuerError,
    IssueParameters,
};

#[test]
fn signed_put_permit_holds_quota_and_replays_after_restart()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::open(true)?;
    let request = fixture.request(RemoteShardAction::Put, 20);
    let admitted = fixture.admitted(&request, 41, 43)?;
    let first = fixture.issue(
        admitted,
        issue_parameters(44, 45, 15, 20, wire_limits()?),
        response_context(41, 44, 25)?,
    )?;

    assert_eq!(
        first.quota_disposition(),
        Some(FederationStorageQuotaDisposition::Applied)
    );
    assert!(verify_federated_shard_permit_mac(
        &fixture.permit_key,
        first.permit()
    ));
    let capability = response_capability(first.outbound().envelope())?;
    assert_eq!(
        decode_federated_shard_permit(&capability.canonical_capability)?,
        *first.permit()
    );
    assert_eq!(capability.signature.len(), 64);
    assert_eq!(fixture.reserved_bytes()?, 20);
    let original_permit = *first.permit();

    fixture.reopen_local()?;
    let retry = fixture.issue(
        AdmittedRequest {
            request_replay_nonce: [46; 32],
            ..admitted
        },
        issue_parameters(47, 48, 16, 21, wire_limits()?),
        response_context(41, 47, 25)?,
    )?;
    assert_eq!(
        retry.quota_disposition(),
        Some(FederationStorageQuotaDisposition::Replayed)
    );
    assert_eq!(*retry.permit(), original_permit);
    assert_eq!(fixture.reserved_bytes()?, 20);
    Ok(())
}

#[test]
fn authority_and_response_failures_leave_no_capacity_hold() -> Result<(), Box<dyn std::error::Error>>
{
    let mut fixture = Fixture::open(true)?;
    let request = fixture.request(RemoteShardAction::Put, 20);
    let admitted = fixture.admitted(&request, 51, 53)?;
    let wrong_remote = AdmittedRequest {
        remote_mesh_id: fixture.ids.local_mesh,
        ..admitted
    };
    assert!(matches!(
        fixture.issue(
            wrong_remote,
            issue_parameters(54, 55, 15, 20, wire_limits()?),
            response_context(51, 54, 25)?,
        ),
        Err(FederationStorageCapabilityIssuerError::AuthorityUnavailable)
    ));
    assert!(fixture.usage()?.is_none());

    let one_byte_limit = WireLimits::new(1, 1, 1, 1)?;
    assert!(matches!(
        fixture.issue(
            admitted,
            issue_parameters(56, 57, 15, 20, one_byte_limit),
            response_context(51, 56, 25)?,
        ),
        Err(FederationStorageCapabilityIssuerError::Transport(_))
    ));
    assert!(fixture.usage()?.is_none());
    Ok(())
}

#[test]
fn provider_that_does_not_serve_reads_rejects_get() -> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::open(false)?;
    let request = fixture.request(RemoteShardAction::Get, 20);
    let admitted = fixture.admitted(&request, 61, 63)?;
    assert!(matches!(
        fixture.issue(
            admitted,
            issue_parameters(64, 65, 15, 20, wire_limits()?),
            response_context(61, 64, 25)?,
        ),
        Err(FederationStorageCapabilityIssuerError::AuthorityUnavailable)
    ));
    assert!(fixture.usage()?.is_none());
    Ok(())
}

fn response_capability(
    envelope: &meshspan_protocol::v1::FederationEnvelope,
) -> Result<&meshspan_protocol::v1::FederatedStorageCapability, &'static str> {
    let Some(Message::StorageCapability(capability)) = envelope.message.as_ref() else {
        return Err("signed response did not contain a storage capability");
    };
    Ok(capability)
}

const fn issue_parameters(
    response_nonce: u8,
    capability_nonce: u8,
    observed_at: i64,
    valid_until: i64,
    limits: WireLimits,
) -> IssueParameters {
    IssueParameters {
        response_replay_nonce: [response_nonce; 32],
        capability_nonce: [capability_nonce; 32],
        valid_until: UnixMicros::new(valid_until),
        observed_at: UnixMicros::new(observed_at),
        limits,
    }
}

fn response_context(
    operation_seed: u8,
    response_nonce: u8,
    deadline: i64,
) -> Result<FederationExchangeContext, Box<dyn std::error::Error>> {
    Ok(FederationExchangeContext::new(
        ProtocolVersion { major: 1, minor: 0 },
        [70; 16],
        [operation_seed; 16],
        [71; 16],
        UnixMicros::new(deadline),
        [response_nonce; 32],
    )?)
}

fn wire_limits() -> Result<WireLimits, Box<dyn std::error::Error>> {
    Ok(WireLimits::new(64 * 1_024, 64 * 1_024, 256, 4_096)?)
}

#[derive(Clone, Copy)]
struct FixtureIds {
    administrator: PrincipalId,
    partition: PartitionId,
    local_mesh: MeshId,
    remote_mesh: MeshId,
    relationship: FederationRelationshipId,
    grant: FederationGrantId,
    provider_node: NodeId,
    allocation: FederationStorageAllocationId,
    target: TargetId,
}

struct Fixture {
    _directory: tempfile::TempDir,
    local_path: std::path::PathBuf,
    repository: AuthoritativeRepository,
    local: LocalDatabase,
    ids: FixtureIds,
    certificate: Vec<u8>,
    signing_key: SigningKey,
    permit_key: FederatedStoragePermitMacKey,
}

impl Fixture {
    fn open(serves_reads: bool) -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let ids = fixture_ids()?;
        let metadata_path = directory.path().join("metadata.sqlite3");
        let local_path = directory.path().join("local.sqlite3");
        let mut repository = AuthoritativeRepository::new(PartitionDatabase::open(
            &metadata_path,
            ids.partition,
            UnixMicros::new(1),
        )?);
        let certificate = b"provider-certificate-der-fixture".to_vec();
        let signing_key = SigningKey::from_bytes(&[81; 32]);
        prepare_authority(
            &mut repository,
            ids,
            &certificate,
            &signing_key,
            serves_reads,
        )?;
        let local = LocalDatabase::open(&local_path, ids.provider_node, UnixMicros::new(15))?;
        Ok(Self {
            _directory: directory,
            local_path,
            repository,
            local,
            ids,
            certificate,
            signing_key,
            permit_key: FederatedStoragePermitMacKey::from_bytes([82; 32])?,
        })
    }

    fn request(
        &self,
        action: RemoteShardAction,
        maximum_bytes: u64,
    ) -> RequestFederatedStorageCapability {
        RequestFederatedStorageCapability {
            grant_id: self.ids.grant.as_bytes().to_vec(),
            allocation_id: self.ids.allocation.as_bytes().to_vec(),
            target_id: self.ids.target.as_bytes().to_vec(),
            target_generation: 1,
            shard: Some(ShardIdentity {
                manifest_digest: vec![83; 32],
                stripe_index: 2,
                shard_index: 3,
                generation: 1,
            }),
            action: action.into(),
            maximum_bytes,
            scope_digest: vec![84; 32],
            signature: Vec::new(),
        }
    }

    fn admitted<'a>(
        &self,
        request: &'a RequestFederatedStorageCapability,
        operation_seed: u8,
        replay_seed: u8,
    ) -> Result<AdmittedRequest<'a>, Box<dyn std::error::Error>> {
        let actual_digest: [u8; 32] = Sha256::digest(
            federation_storage_capability_request_digest_payload(request),
        )
        .into();
        Ok(AdmittedRequest {
            relationship_id: self.ids.relationship,
            remote_mesh_id: self.ids.remote_mesh,
            operation_id: OperationId::from_bytes([operation_seed; 16])?,
            request_digest: actual_digest,
            request_replay_nonce: [replay_seed; 32],
            request,
        })
    }

    fn issue(
        &mut self,
        admitted: AdmittedRequest<'_>,
        parameters: IssueParameters,
        response_context: FederationExchangeContext,
    ) -> Result<super::IssuedFederationStorageCapability, FederationStorageCapabilityIssuerError>
    {
        let identity = local_identity(
            self.ids,
            &self.certificate,
            &self.signing_key,
            parameters.observed_at,
        )?;
        FederationStorageCapabilityIssuer::new(
            &self.repository,
            &mut self.local,
            &identity,
            &self.permit_key,
        )
        .issue_admitted(parameters, admitted, response_context)
    }

    fn usage(
        &self,
    ) -> Result<Option<meshspan_metadata::FederationStorageUsage>, Box<dyn std::error::Error>> {
        Ok(self.local.federated_storage_usage(self.ids.allocation)?)
    }

    fn reserved_bytes(&self) -> Result<u64, Box<dyn std::error::Error>> {
        Ok(self
            .usage()?
            .ok_or("allocation usage missing")?
            .reserved_bytes)
    }

    fn reopen_local(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        self.local = LocalDatabase::open(
            &self.local_path,
            self.ids.provider_node,
            UnixMicros::new(16),
        )?;
        Ok(())
    }
}

fn fixture_ids() -> Result<FixtureIds, Box<dyn std::error::Error>> {
    Ok(FixtureIds {
        administrator: PrincipalId::from_bytes([1; 16])?,
        partition: PartitionId::from_bytes([2; 16])?,
        local_mesh: MeshId::from_bytes([3; 16])?,
        remote_mesh: MeshId::from_bytes([4; 16])?,
        relationship: FederationRelationshipId::from_bytes([5; 16])?,
        grant: FederationGrantId::from_bytes([6; 16])?,
        provider_node: NodeId::from_bytes([7; 16])?,
        allocation: FederationStorageAllocationId::from_bytes([8; 16])?,
        target: TargetId::from_bytes([9; 16])?,
    })
}

fn prepare_authority(
    repository: &mut AuthoritativeRepository,
    ids: FixtureIds,
    certificate: &[u8],
    signing_key: &SigningKey,
    serves_reads: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    prepare_relationship(repository, ids, certificate, signing_key)?;
    issue_storage_authority(repository, ids, serves_reads)
}

fn prepare_relationship(
    repository: &mut AuthoritativeRepository,
    ids: FixtureIds,
    certificate: &[u8],
    signing_key: &SigningKey,
) -> Result<(), Box<dyn std::error::Error>> {
    apply(
        repository,
        1,
        ids,
        11,
        1,
        0,
        &AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
            mesh_id: ids.local_mesh,
            mesh_name: RecordName::new("Provider swarm")?,
            administrator_id: ids.administrator,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([12; 16])?,
            host_id: HostId::from_bytes([13; 16])?,
            host_name: RecordName::new("Provider host")?,
            node_id: ids.provider_node,
            node_name: RecordName::new("Provider node")?,
            partition_name: RecordName::new("Root authority")?,
        }),
    )?;
    apply(
        repository,
        2,
        ids,
        14,
        2,
        1,
        &AuthoritativeCommand::ProposeFederationRelationship(ProposeFederationRelationship {
            relationship_id: ids.relationship,
            remote_mesh_id: ids.remote_mesh,
            remote_name: RecordName::new("Consumer swarm")?,
            kind: FederationRelationshipKind::Horizontal,
            governance_direction: FederationGovernanceDirection::None,
        }),
    )?;
    let local_trust = trust_identity(certificate, signing_key);
    apply(
        repository,
        3,
        ids,
        15,
        3,
        2,
        &AuthoritativeCommand::ApproveFederationRelationship(ApproveFederationRelationship {
            relationship_id: ids.relationship,
            expected_authority_epoch: 1,
            local_identity: local_trust,
            remote_identity: FederationTrustIdentity {
                generation: 1,
                certificate_fingerprint: [16; 32],
                verifying_key: SigningKey::from_bytes(&[17; 32]).verifying_key().to_bytes(),
                valid_from: UnixMicros::new(1),
                valid_until: UnixMicros::new(100),
            },
            governance_proof: None,
        }),
    )?;
    Ok(())
}

fn issue_storage_authority(
    repository: &mut AuthoritativeRepository,
    ids: FixtureIds,
    serves_reads: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    let policy = FederationPolicy::Storage(StorageFederationPolicy::new(
        100,
        StorageParticipation::new(false, serves_reads),
        Some(DurationMicros::new(200)),
    )?);
    apply(
        repository,
        4,
        ids,
        18,
        4,
        3,
        &AuthoritativeCommand::IssueFederationGrant(IssueFederationGrant {
            grant: FederationGrant::new(
                ids.grant,
                ids.relationship,
                FederatedPrincipal::new(ids.remote_mesh, ids.administrator),
                FederationResourceScope::StorageCapacity {
                    provider_mesh_id: ids.local_mesh,
                },
                policy,
                1,
                UnixMicros::new(4),
                Some(UnixMicros::new(100)),
            )?,
            restrictions: BoundedItems::new(
                vec![
                    FederationGrantRestriction {
                        imposing_mesh_id: ids.local_mesh,
                        policy,
                    },
                    FederationGrantRestriction {
                        imposing_mesh_id: ids.remote_mesh,
                        policy,
                    },
                ],
                2,
            )?,
        }),
    )?;
    apply(
        repository,
        5,
        ids,
        19,
        5,
        4,
        &AuthoritativeCommand::IssueFederationStorageAllocation(IssueFederationStorageAllocation {
            allocation: FederationStorageAllocation::new(
                ids.allocation,
                ids.grant,
                ids.provider_node,
                ids.target,
                1,
                100,
                UnixMicros::new(10),
                UnixMicros::new(90),
            )?,
            expected_grant_revision: Revision::new(4),
        }),
    )?;
    Ok(())
}

fn apply(
    repository: &mut AuthoritativeRepository,
    index: u64,
    ids: FixtureIds,
    operation_seed: u8,
    occurred_at: i64,
    expected_revision: u64,
    command: &AuthoritativeCommand,
) -> Result<(), Box<dyn std::error::Error>> {
    repository.apply_committed(
        LogPosition { index, term: 1 },
        CommandContext {
            operation_id: OperationId::from_bytes([operation_seed; 16])?,
            actor_principal_id: ids.administrator,
            audit_event_id: AuditEventId::from_bytes([operation_seed.saturating_add(100); 16])?,
            occurred_at: UnixMicros::new(occurred_at),
            expected_revision: Some(Revision::new(expected_revision)),
        },
        command,
    )?;
    Ok(())
}

fn trust_identity(certificate: &[u8], signing_key: &SigningKey) -> FederationTrustIdentity {
    FederationTrustIdentity {
        generation: 1,
        certificate_fingerprint: Sha256::digest(certificate).into(),
        verifying_key: signing_key.verifying_key().to_bytes(),
        valid_from: UnixMicros::new(1),
        valid_until: UnixMicros::new(100),
    }
}

fn local_identity<'a>(
    ids: FixtureIds,
    certificate: &'a [u8],
    signing_key: &'a SigningKey,
    now: UnixMicros,
) -> Result<FederationLocalIdentity<'a>, FederationStorageCapabilityIssuerError> {
    Ok(FederationLocalIdentity::authenticate(
        FederationLocalIdentityBinding {
            relationship_id: ids.relationship,
            local_mesh_id: ids.local_mesh,
            remote_mesh_id: ids.remote_mesh,
            authority_epoch: 1,
            identity_generation: 1,
            certificate_fingerprint: Sha256::digest(certificate).into(),
            verifying_key: signing_key.verifying_key().to_bytes(),
            valid_from: UnixMicros::new(1),
            valid_until: UnixMicros::new(100),
        },
        certificate,
        signing_key,
        now,
    )?)
}
