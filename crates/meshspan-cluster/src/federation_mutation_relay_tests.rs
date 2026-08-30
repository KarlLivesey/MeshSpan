// SPDX-License-Identifier: GPL-2.0-only

use ed25519_dalek::{Signer, SigningKey, Verifier};
use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    AuditEventId, BranchId, ContentManifestId, FederatedMutationAcknowledgement,
    FederatedMutationAdmission, FederatedMutationEvidence, FederatedPrincipal, FederationAccess,
    FederationGrant, FederationGrantId, FederationGrantRoute, FederationPolicy,
    FederationRelationshipId, FederationRelationshipKind, FederationResourceScope, FileVersionId,
    HostId, MeshId, NamespaceCommitId, NamespaceFederationPolicy, NodeId, ObjectId,
    ObjectRevisionId, OperationId, PartitionId, PrincipalId, Revision, Rights, RoleId, UnixMicros,
    VolumeId,
};
use meshspan_filesystem::{
    FilePublication, ManifestPublication, NamespaceHistoryLimits, NamespaceLimits, NamespacePath,
    NamespacePublicationPath, RootFilePublication, VersionPublicationStore,
};
use meshspan_metadata::{
    ApproveFederationRelationship, AuthoritativeCommand, AuthoritativeRepository, BootstrapMesh,
    CommandContext, FederatedActorKind, FederatedActorState, FederationGovernanceDirection,
    FederationGrantRecord, FederationGrantRestriction, FederationRemoteAuthoritySnapshot,
    FederationTrustIdentity, IssueFederationGrant, LocalDatabase, LogPosition, PartitionDatabase,
    ProposeFederationRelationship, RecordFederatedActorAttestation, RecordName,
};
use tempfile::{TempDir, tempdir};

use crate::{
    FederatedHistoryMutationAdmissionError, FederationMutationRelayError,
    classify_federated_history_mutation, relay_federated_history_mutation,
};

#[test]
fn intermediary_verifies_downstream_then_countersigns_for_the_root_owner()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = RelayFixture::open()?;
    fixture.prepare()?;
    let (record, downstream) = fixture.downstream_history()?;

    assert!(matches!(
        classify_federated_history_mutation(
            &fixture.owner,
            &record,
            &downstream,
            UnixMicros::new(30),
        ),
        Err(FederatedHistoryMutationAdmissionError::Authority(_))
    ));

    let relayed = relay_federated_history_mutation(
        &fixture.intermediary,
        &fixture.owner_cache,
        &record,
        &downstream,
        fixture.ids.owner_relationship,
        fixture.ids.upstream_grant,
        UnixMicros::new(30),
        &fixture.intermediary_upstream_key,
    )?;

    assert_eq!(relayed.evidence.actor(), downstream.evidence.actor());
    assert_eq!(
        relayed.evidence.accepting_mesh_id(),
        fixture.ids.intermediary
    );
    assert_eq!(relayed.evidence.grant_id(), fixture.ids.upstream_grant);
    assert_eq!(relayed.evidence.resource(), fixture.ids.resource());
    assert_eq!(relayed.payload_digest, downstream.payload_digest);
    fixture.intermediary_upstream_key.verifying_key().verify(
        &relayed.signing_payload(),
        &ed25519_dalek::Signature::from_bytes(&relayed.signature),
    )?;
    assert_eq!(
        classify_federated_history_mutation(
            &fixture.owner,
            &record,
            &relayed,
            UnixMicros::new(31),
        )?
        .admission(),
        FederatedMutationAdmission::Admitted
    );
    Ok(())
}

#[test]
fn relay_rejects_forgery_and_withholds_new_signatures_after_upstream_expiry()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = RelayFixture::open()?;
    fixture.prepare()?;
    let (record, downstream) = fixture.downstream_history()?;

    let mut forged = downstream;
    forged.signature[0] ^= 1;
    assert!(matches!(
        relay_federated_history_mutation(
            &fixture.intermediary,
            &fixture.owner_cache,
            &record,
            &forged,
            fixture.ids.owner_relationship,
            fixture.ids.upstream_grant,
            UnixMicros::new(30),
            &fixture.intermediary_upstream_key,
        ),
        Err(FederationMutationRelayError::Downstream(_))
    ));
    assert!(matches!(
        relay_federated_history_mutation(
            &fixture.intermediary,
            &fixture.owner_cache,
            &record,
            &downstream,
            fixture.ids.owner_relationship,
            fixture.ids.upstream_grant,
            UnixMicros::new(80),
            &fixture.intermediary_upstream_key,
        ),
        Err(FederationMutationRelayError::AuthorityUnavailable)
    ));
    Ok(())
}

struct RelayFixture {
    directory: TempDir,
    owner: AuthoritativeRepository,
    intermediary: AuthoritativeRepository,
    owner_cache: LocalDatabase,
    ids: Ids,
    owner_key: SigningKey,
    intermediary_upstream_key: SigningKey,
    intermediary_downstream_key: SigningKey,
    recipient_key: SigningKey,
}

impl RelayFixture {
    fn open() -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let ids = Ids::new()?;
        Ok(Self {
            owner: repository(directory.path(), "owner.sqlite3", ids.owner_partition)?,
            intermediary: repository(
                directory.path(),
                "intermediary.sqlite3",
                ids.intermediary_partition,
            )?,
            owner_cache: LocalDatabase::open(
                &directory.path().join("owner-cache.sqlite3"),
                ids.intermediary_node,
                UnixMicros::new(0),
            )?,
            directory,
            ids,
            owner_key: SigningKey::from_bytes(&[40; 32]),
            intermediary_upstream_key: SigningKey::from_bytes(&[41; 32]),
            intermediary_downstream_key: SigningKey::from_bytes(&[42; 32]),
            recipient_key: SigningKey::from_bytes(&[43; 32]),
        })
    }

    fn prepare(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        bootstrap(&mut self.owner, self.ids.owner, self.ids.owner_node, 1)?;
        connect(
            &mut self.owner,
            self.ids.owner_relationship,
            self.ids.intermediary,
            &self.owner_key,
            &self.intermediary_upstream_key,
        )?;
        bootstrap(
            &mut self.intermediary,
            self.ids.intermediary,
            self.ids.intermediary_node,
            1,
        )?;
        connect(
            &mut self.intermediary,
            self.ids.owner_relationship,
            self.ids.owner,
            &self.intermediary_upstream_key,
            &self.owner_key,
        )?;
        connect(
            &mut self.intermediary,
            self.ids.recipient_relationship,
            self.ids.recipient,
            &self.intermediary_downstream_key,
            &self.recipient_key,
        )?;
        self.issue_grant_chain()?;
        self.record_recipient_actor()?;
        self.install_owner_observation()
    }

    fn issue_grant_chain(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let upstream = self.ids.upstream_grant()?;
        issue(&mut self.owner, &upstream)?;
        issue(&mut self.intermediary, &upstream)?;
        issue(&mut self.intermediary, &self.ids.child_grant()?)
    }

    fn record_recipient_actor(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut attestation = RecordFederatedActorAttestation {
            relationship_id: self.ids.recipient_relationship,
            home_mesh_id: self.ids.recipient,
            principal_id: self.ids.recipient_user,
            kind: FederatedActorKind::User,
            name: RecordName::new("Recipient user")?,
            state: FederatedActorState::Active,
            identity_revision: 1,
            authority_epoch: 1,
            signer_generation: 1,
            signature: [0; 64],
        };
        attestation.signature = self
            .recipient_key
            .sign(&attestation.signing_payload())
            .to_bytes();
        apply_next(
            &mut self.intermediary,
            &AuthoritativeCommand::RecordFederatedActorAttestation(attestation),
        )
    }

    fn install_owner_observation(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let authority_revision = self.owner.current_revision()?;
        let relationship = self
            .owner
            .federation_transport_authority(self.ids.owner_relationship)?
            .ok_or("owner relationship missing")?;
        let grant = self
            .owner
            .active_federation_grant(self.ids.upstream_grant)?
            .ok_or("owner grant missing")?;
        self.owner_cache.install_remote_federation_authority(
            &FederationRemoteAuthoritySnapshot {
                after_revision: Revision::ZERO,
                authority_revision,
                relationship,
                grants: vec![grant],
            },
            UnixMicros::new(25),
        )?;
        Ok(())
    }

    fn downstream_history(
        &self,
    ) -> Result<
        (
            meshspan_filesystem::NamespaceHistoryCommitRecord,
            FederatedMutationAcknowledgement,
        ),
        Box<dyn std::error::Error>,
    > {
        let publication = publication(self.ids)?;
        let proposal =
            VersionPublicationStore::root_file_federated_mutation_proposal(&publication)?;
        let mut acknowledgement = FederatedMutationAcknowledgement {
            source_operation_id: proposal.authority().operation_id(),
            evidence: FederatedMutationEvidence::new(
                self.ids.child_grant,
                self.ids.recipient_relationship,
                FederatedPrincipal::new(self.ids.recipient, self.ids.recipient_user),
                self.ids.resource(),
                1,
                UnixMicros::new(20),
                proposal.authority().required_rights(),
                0,
            ),
            payload_digest: proposal.payload_digest(),
            signer_generation: 1,
            signature: [0; 64],
        };
        acknowledgement.signature = self
            .recipient_key
            .sign(&acknowledgement.signing_payload())
            .to_bytes();
        let store_directory = self.directory.path().join("recipient-history");
        let mut store = VersionPublicationStore::open(&store_directory, UnixMicros::new(1))?;
        store.publish_federated_root_file(&publication, &acknowledgement)?;
        let mut records = store
            .export_namespace_history(
                self.ids.volume,
                &[publication.namespace_commit_id],
                &[],
                NamespaceHistoryLimits::DEFAULT,
            )?
            .commit_records()?;
        let record = records.pop().ok_or("history record missing")?;
        if !records.is_empty() {
            return Err("unexpected extra history records".into());
        }
        Ok((record, acknowledgement))
    }
}

fn repository(
    directory: &std::path::Path,
    name: &str,
    partition_id: PartitionId,
) -> Result<AuthoritativeRepository, Box<dyn std::error::Error>> {
    Ok(AuthoritativeRepository::new(PartitionDatabase::open(
        &directory.join(name),
        partition_id,
        UnixMicros::new(0),
    )?))
}

fn bootstrap(
    repository: &mut AuthoritativeRepository,
    mesh_id: MeshId,
    node_id: NodeId,
    seed: u8,
) -> Result<(), Box<dyn std::error::Error>> {
    apply_next(
        repository,
        &AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
            mesh_id,
            mesh_name: RecordName::new("Test swarm")?,
            administrator_id: PrincipalId::from_bytes([seed; 16])?,
            administrator_name: RecordName::new("Administrator")?,
            administrator_role_id: RoleId::from_bytes([seed.saturating_add(1); 16])?,
            host_id: HostId::from_bytes([seed.saturating_add(2); 16])?,
            host_name: RecordName::new("Host")?,
            node_id,
            node_name: RecordName::new("Node")?,
            partition_name: RecordName::new("Root authority")?,
        }),
    )
}

fn connect(
    repository: &mut AuthoritativeRepository,
    relationship_id: FederationRelationshipId,
    remote_mesh_id: MeshId,
    local_key: &SigningKey,
    remote_key: &SigningKey,
) -> Result<(), Box<dyn std::error::Error>> {
    apply_next(
        repository,
        &AuthoritativeCommand::ProposeFederationRelationship(ProposeFederationRelationship {
            relationship_id,
            remote_mesh_id,
            remote_name: RecordName::new("Peer swarm")?,
            kind: FederationRelationshipKind::Horizontal,
            governance_direction: FederationGovernanceDirection::None,
        }),
    )?;
    apply_next(
        repository,
        &AuthoritativeCommand::ApproveFederationRelationship(ApproveFederationRelationship {
            relationship_id,
            expected_authority_epoch: 1,
            local_identity: identity(local_key),
            remote_identity: identity(remote_key),
            governance_proof: None,
        }),
    )
}

fn issue(
    repository: &mut AuthoritativeRepository,
    grant: &FederationGrantRecord,
) -> Result<(), Box<dyn std::error::Error>> {
    apply_next(
        repository,
        &AuthoritativeCommand::IssueFederationGrant(IssueFederationGrant {
            grant: grant.grant.clone(),
            restrictions: BoundedItems::new(grant.restrictions.clone(), 3)?,
        }),
    )
}

fn apply_next(
    repository: &mut AuthoritativeRepository,
    command: &AuthoritativeCommand,
) -> Result<(), Box<dyn std::error::Error>> {
    let current = repository.current_revision()?;
    let next = current.next()?;
    let seed = u8::try_from(next.get())?;
    repository.apply_committed(
        LogPosition {
            index: next.get(),
            term: 1,
        },
        CommandContext {
            operation_id: OperationId::from_bytes([seed; 16])?,
            actor_principal_id: PrincipalId::from_bytes([1; 16])?,
            audit_event_id: AuditEventId::from_bytes([seed.saturating_add(100); 16])?,
            occurred_at: UnixMicros::new(i64::from(seed)),
            expected_revision: Some(current),
        },
        command,
    )?;
    Ok(())
}

fn identity(key: &SigningKey) -> FederationTrustIdentity {
    FederationTrustIdentity {
        generation: 1,
        certificate_fingerprint: key.verifying_key().to_bytes(),
        verifying_key: key.verifying_key().to_bytes(),
        valid_from: UnixMicros::new(1),
        valid_until: UnixMicros::new(100),
    }
}

fn publication(ids: Ids) -> Result<RootFilePublication, Box<dyn std::error::Error>> {
    Ok(RootFilePublication {
        file: FilePublication {
            operation_id: OperationId::from_bytes([70; 16])?,
            branch_id: BranchId::from_bytes([71; 16])?,
            volume_id: ids.volume,
            object_id: ObjectId::from_bytes([72; 16])?,
            expected_current_version_id: None,
            version_id: FileVersionId::from_bytes([73; 16])?,
            parent_version_id: None,
            retain_superseded_history: true,
            retention_policy_sequence: 1,
            manifest: ManifestPublication {
                manifest_id: ContentManifestId::from_bytes([74; 16])?,
                format_version: 1,
                logical_length: 4,
                content_digest: blake3::hash(b"data").into(),
                root_digest: blake3::hash(b"layout").into(),
            },
            created_by: ids.recipient_user,
            created_at: UnixMicros::new(19),
        },
        root_object_id: ObjectId::from_bytes([75; 16])?,
        expected_namespace_commit_id: None,
        expected_file_object_revision_id: None,
        file_object_revision_id: ObjectRevisionId::from_bytes([76; 16])?,
        root_object_revision_id: ObjectRevisionId::from_bytes([77; 16])?,
        namespace_commit_id: NamespaceCommitId::from_bytes([78; 16])?,
        path: NamespacePublicationPath::new(
            NamespacePath::from_components(["relay.txt"], NamespaceLimits::PORTABLE)?,
            Vec::new(),
        )?,
        entry_generation: 1,
    })
}

#[derive(Clone, Copy)]
struct Ids {
    owner: MeshId,
    intermediary: MeshId,
    recipient: MeshId,
    owner_partition: PartitionId,
    intermediary_partition: PartitionId,
    owner_node: NodeId,
    intermediary_node: NodeId,
    recipient_user: PrincipalId,
    owner_relationship: FederationRelationshipId,
    recipient_relationship: FederationRelationshipId,
    upstream_grant: FederationGrantId,
    child_grant: FederationGrantId,
    volume: VolumeId,
}

impl Ids {
    fn new() -> Result<Self, meshspan_domain::IdentifierError> {
        Ok(Self {
            owner: MeshId::from_bytes([20; 16])?,
            intermediary: MeshId::from_bytes([21; 16])?,
            recipient: MeshId::from_bytes([22; 16])?,
            owner_partition: PartitionId::from_bytes([23; 16])?,
            intermediary_partition: PartitionId::from_bytes([24; 16])?,
            owner_node: NodeId::from_bytes([25; 16])?,
            intermediary_node: NodeId::from_bytes([26; 16])?,
            recipient_user: PrincipalId::from_bytes([27; 16])?,
            owner_relationship: FederationRelationshipId::from_bytes([28; 16])?,
            recipient_relationship: FederationRelationshipId::from_bytes([29; 16])?,
            upstream_grant: FederationGrantId::from_bytes([30; 16])?,
            child_grant: FederationGrantId::from_bytes([31; 16])?,
            volume: VolumeId::from_bytes([32; 16])?,
        })
    }

    const fn resource(self) -> FederationResourceScope {
        FederationResourceScope::Volume {
            owner_mesh_id: self.owner,
            volume_id: self.volume,
        }
    }

    fn upstream_grant(self) -> Result<FederationGrantRecord, Box<dyn std::error::Error>> {
        let policy = policy(true);
        Ok(grant_record(
            FederationGrant::new(
                self.upstream_grant,
                self.owner_relationship,
                FederationGrantRoute::direct(self.owner, self.intermediary)?,
                None,
                self.resource(),
                policy,
                1,
                UnixMicros::new(1),
                Some(UnixMicros::new(80)),
            )?,
            &[(self.owner, policy), (self.intermediary, policy)],
        ))
    }

    fn child_grant(self) -> Result<FederationGrantRecord, Box<dyn std::error::Error>> {
        let policy = policy(false);
        Ok(grant_record(
            FederationGrant::new(
                self.child_grant,
                self.recipient_relationship,
                FederationGrantRoute::from_meshes(vec![
                    self.owner,
                    self.intermediary,
                    self.recipient,
                ])?,
                Some(self.upstream_grant),
                self.resource(),
                policy,
                1,
                UnixMicros::new(2),
                Some(UnixMicros::new(70)),
            )?,
            &[
                (self.owner, policy),
                (self.intermediary, policy),
                (self.recipient, policy),
            ],
        ))
    }
}

fn policy(allows_downstream: bool) -> FederationPolicy {
    let mut rights = Rights::TRAVERSE
        .union(Rights::CREATE_CHILD)
        .union(Rights::WRITE_DATA);
    if allows_downstream {
        rights = rights.union(Rights::DELETE);
    }
    FederationPolicy::Namespace(NamespaceFederationPolicy::new(
        FederationAccess::new(rights, allows_downstream),
        None,
    ))
}

fn grant_record(
    grant: FederationGrant,
    restrictions: &[(MeshId, FederationPolicy)],
) -> FederationGrantRecord {
    FederationGrantRecord {
        grant,
        restrictions: restrictions
            .iter()
            .map(|(imposing_mesh_id, policy)| FederationGrantRestriction {
                imposing_mesh_id: *imposing_mesh_id,
                policy: *policy,
            })
            .collect(),
        state: meshspan_metadata::FederationGrantState::Active,
        issued_at: UnixMicros::new(3),
        termination: None,
        predecessor_grant_id: None,
        successor_grant_id: None,
        revision: Revision::new(1),
    }
}
