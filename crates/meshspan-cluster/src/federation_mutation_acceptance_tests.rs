// SPDX-License-Identifier: GPL-2.0-only

use std::error::Error;

use ed25519_dalek::{Signature, SigningKey, Verifier};
use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    ActivationId, ActivationPolicyId, ApiKeyId, AssuranceLevel, AuditEventId,
    AuthenticationMethodId, AuthenticationService, BranchId, ContentManifestId, DurationMicros,
    FederatedPrincipal, FederationAccess, FederationAssignmentId, FederationGrant,
    FederationGrantId, FederationGrantRoute, FederationPolicy, FederationRelationshipId,
    FederationRelationshipKind, FederationResourceScope, FileVersionId, GroupId, HostId, MeshId,
    NamespaceCommitId, NamespaceFederationPolicy, NodeId, ObjectId, ObjectRevisionId, OperationId,
    PartitionId, PrincipalId, Revision, Rights, RoleId, SessionId, UnixMicros, VolumeId,
};
use meshspan_filesystem::{
    FilePublication, ManifestPublication, NamespaceLimits, NamespacePath, NamespacePublicationPath,
    RootFilePublication, VersionPublicationStore,
};
use meshspan_metadata::{
    ActivateFederationGrantAssignment, AddGroupMember, ApproveFederationRelationship,
    AuthoritativeCommand, AuthoritativeRepository, BootstrapMesh, CommandContext,
    CreateActivationPolicy, CreateAuthenticationMethod, CreateFederationGrantAssignment,
    CreateGroup, CreateUser, FederationGovernanceDirection, FederationGrantRecord,
    FederationGrantRestriction, FederationGrantState, FederationIdentityOwner,
    FederationRelationshipRecord, FederationRelationshipState, FederationRemoteAuthoritySnapshot,
    FederationTransportAuthority, FederationTrustIdentity, FederationTrustIdentityRecord,
    IssueAuthenticationSession, IssueFederationGrant, LocalDatabase, LogPosition,
    NewAuthenticationCredential, PartitionDatabase, ProposeFederationRelationship, RecordName,
    RevokeAuthenticationSession, SessionAccessRequest, SessionAuthenticationFactor, TotpAlgorithm,
};
use tempfile::{TempDir, tempdir};

use super::{
    FederationMutationAcceptanceError, FederationMutationAcceptanceRequest,
    FederationMutationAcceptor, MetadataFederationMutationAcceptanceAuthority,
    MetadataFederationMutationAcceptanceError,
};

#[test]
fn local_group_and_activated_assignment_gate_signing_then_session_revokes_immediately()
-> Result<(), Box<dyn Error>> {
    let mut fixture = Fixture::open()?;
    fixture.prepare()?;
    let proposal =
        VersionPublicationStore::root_file_federated_mutation_proposal(&fixture.publication()?)?;
    let before_activation = FederationMutationAcceptor::new(
        MetadataFederationMutationAcceptanceAuthority::new(
            &fixture.repository,
            &fixture.remote_cache,
        ),
        &fixture.local_key,
    )
    .acknowledge(fixture.request(13), &proposal);
    assert!(matches!(
        before_activation,
        Err(FederationMutationAcceptanceError::Authority(
            MetadataFederationMutationAcceptanceError::Denied
        ))
    ));
    fixture.activate_write_assignment()?;
    let request = fixture.request(20);
    let acknowledgement = FederationMutationAcceptor::new(
        MetadataFederationMutationAcceptanceAuthority::new(
            &fixture.repository,
            &fixture.remote_cache,
        ),
        &fixture.local_key,
    )
    .acknowledge(request, &proposal)?;

    assert_eq!(acknowledgement.payload_digest, proposal.payload_digest());
    assert_eq!(acknowledgement.evidence.grant_id(), fixture.ids.grant);
    assert_eq!(
        acknowledgement.evidence.actor(),
        FederatedPrincipal::new(fixture.ids.local_mesh, fixture.ids.user)
    );
    assert_eq!(
        acknowledgement.evidence.required_rights(),
        proposal.authority().required_rights()
    );
    fixture.local_key.verifying_key().verify(
        &acknowledgement.signing_payload(),
        &Signature::from_bytes(&acknowledgement.signature),
    )?;
    assert!(
        fixture
            .repository
            .evaluate_federation_grant_assignment(
                fixture.ids.grant,
                fixture.ids.user,
                Revision::new(10),
                proposal.authority().required_rights(),
                UnixMicros::new(20),
            )?
            .is_some()
    );
    assert!(
        fixture
            .repository
            .evaluate_federation_grant_assignment(
                fixture.ids.grant,
                fixture.ids.administrator,
                Revision::new(10),
                Rights::TRAVERSE,
                UnixMicros::new(20),
            )?
            .is_none()
    );
    assert!(
        fixture
            .repository
            .evaluate_federation_grant_assignment(
                fixture.ids.grant,
                fixture.ids.user,
                Revision::new(10),
                Rights::CHANGE_PERMISSIONS,
                UnixMicros::new(20),
            )?
            .is_none()
    );

    fixture.revoke_session()?;
    let denial = FederationMutationAcceptor::new(
        MetadataFederationMutationAcceptanceAuthority::new(
            &fixture.repository,
            &fixture.remote_cache,
        ),
        &fixture.local_key,
    )
    .acknowledge(fixture.request(21), &proposal);
    assert!(matches!(
        denial,
        Err(FederationMutationAcceptanceError::Authority(
            MetadataFederationMutationAcceptanceError::SessionDenied(_)
        ))
    ));
    Ok(())
}

struct FixtureIds {
    administrator: PrincipalId,
    user: PrincipalId,
    writers: GroupId,
    partition: PartitionId,
    local_mesh: MeshId,
    remote_mesh: MeshId,
    owner_mesh: MeshId,
    relationship: FederationRelationshipId,
    grant: FederationGrantId,
    group_assignment: FederationAssignmentId,
    write_assignment: FederationAssignmentId,
    activation_policy: ActivationPolicyId,
    activation: ActivationId,
    volume: VolumeId,
    host: HostId,
    node: NodeId,
    session: SessionId,
}

struct Fixture {
    _directory: TempDir,
    repository: AuthoritativeRepository,
    remote_cache: LocalDatabase,
    ids: FixtureIds,
    local_key: SigningKey,
    remote_key: SigningKey,
}

impl Fixture {
    fn open() -> Result<Self, Box<dyn Error>> {
        let directory = tempdir()?;
        let ids = FixtureIds {
            administrator: PrincipalId::from_bytes([1; 16])?,
            user: PrincipalId::from_bytes([2; 16])?,
            writers: GroupId::from_bytes([24; 16])?,
            partition: PartitionId::from_bytes([3; 16])?,
            local_mesh: MeshId::from_bytes([4; 16])?,
            remote_mesh: MeshId::from_bytes([5; 16])?,
            owner_mesh: MeshId::from_bytes([28; 16])?,
            relationship: FederationRelationshipId::from_bytes([6; 16])?,
            grant: FederationGrantId::from_bytes([7; 16])?,
            group_assignment: FederationAssignmentId::from_bytes([23; 16])?,
            write_assignment: FederationAssignmentId::from_bytes([25; 16])?,
            activation_policy: ActivationPolicyId::from_bytes([26; 16])?,
            activation: ActivationId::from_bytes([27; 16])?,
            volume: VolumeId::from_bytes([8; 16])?,
            host: HostId::from_bytes([9; 16])?,
            node: NodeId::from_bytes([10; 16])?,
            session: SessionId::from_bytes([11; 16])?,
        };
        let repository = AuthoritativeRepository::new(PartitionDatabase::open(
            &directory.path().join("authority.sqlite3"),
            ids.partition,
            UnixMicros::new(0),
        )?);
        let remote_cache = LocalDatabase::open(
            &directory.path().join("remote-cache.sqlite3"),
            ids.node,
            UnixMicros::new(0),
        )?;
        Ok(Self {
            _directory: directory,
            repository,
            remote_cache,
            ids,
            local_key: SigningKey::from_bytes(&[12; 32]),
            remote_key: SigningKey::from_bytes(&[13; 32]),
        })
    }

    fn prepare(&mut self) -> Result<(), Box<dyn Error>> {
        self.bootstrap_local_identity()?;
        self.connect_owner()?;
        self.configure_grant_assignments()?;
        self.issue_session()?;
        Ok(())
    }

    fn bootstrap_local_identity(&mut self) -> Result<(), Box<dyn Error>> {
        self.apply(
            1,
            20,
            self.ids.administrator,
            &AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
                mesh_id: self.ids.local_mesh,
                mesh_name: RecordName::new("Accepting swarm")?,
                administrator_id: self.ids.administrator,
                administrator_name: RecordName::new("Administrator")?,
                administrator_role_id: RoleId::from_bytes([14; 16])?,
                host_id: self.ids.host,
                host_name: RecordName::new("Gateway host")?,
                node_id: self.ids.node,
                node_name: RecordName::new("Gateway node")?,
                partition_name: RecordName::new("Root authority")?,
            }),
        )?;
        self.apply(
            2,
            21,
            self.ids.administrator,
            &AuthoritativeCommand::CreateUser(CreateUser {
                principal_id: self.ids.user,
                name: RecordName::new("Federated writer")?,
            }),
        )
    }

    fn connect_owner(&mut self) -> Result<(), Box<dyn Error>> {
        self.apply(
            3,
            30,
            self.ids.administrator,
            &AuthoritativeCommand::CreateGroup(CreateGroup {
                group_id: self.ids.writers,
                name: RecordName::new("Federated writers")?,
                activation_policy_id: None,
            }),
        )?;
        self.apply(
            4,
            31,
            self.ids.administrator,
            &AuthoritativeCommand::AddGroupMember(AddGroupMember {
                containing_group_id: self.ids.writers,
                member_principal_id: self.ids.user,
                valid_from: None,
                valid_until: None,
                activation_required: false,
            }),
        )?;
        self.apply(
            5,
            25,
            self.ids.administrator,
            &AuthoritativeCommand::ProposeFederationRelationship(ProposeFederationRelationship {
                relationship_id: self.ids.relationship,
                remote_mesh_id: self.ids.remote_mesh,
                remote_name: RecordName::new("Owning swarm")?,
                kind: FederationRelationshipKind::Horizontal,
                governance_direction: FederationGovernanceDirection::None,
            }),
        )?;
        self.apply(
            6,
            26,
            self.ids.administrator,
            &AuthoritativeCommand::ApproveFederationRelationship(ApproveFederationRelationship {
                relationship_id: self.ids.relationship,
                expected_authority_epoch: 1,
                local_identity: identity(&self.local_key, 16),
                remote_identity: identity(&self.remote_key, 17),
                governance_proof: None,
            }),
        )
    }

    fn configure_grant_assignments(&mut self) -> Result<(), Box<dyn Error>> {
        let record = self.grant_record()?;
        self.apply(
            7,
            27,
            self.ids.administrator,
            &AuthoritativeCommand::IssueFederationGrant(IssueFederationGrant {
                grant: record.grant.clone(),
                restrictions: BoundedItems::new(record.restrictions.clone(), 3)?,
            }),
        )?;
        self.apply(
            8,
            32,
            self.ids.administrator,
            &AuthoritativeCommand::CreateActivationPolicy(CreateActivationPolicy {
                policy_id: self.ids.activation_policy,
                maximum_duration: DurationMicros::new(60),
                reason_required: true,
                minimum_assurance: AssuranceLevel::SingleFactor,
                valid_from: None,
                valid_until: None,
            }),
        )?;
        self.apply(
            9,
            29,
            self.ids.administrator,
            &AuthoritativeCommand::CreateFederationGrantAssignment(
                CreateFederationGrantAssignment {
                    assignment_id: self.ids.group_assignment,
                    grant_id: self.ids.grant,
                    subject_principal_id: self.ids.writers.principal_id(),
                    rights: Rights::TRAVERSE.union(Rights::CREATE_CHILD),
                    valid_from: None,
                    valid_until: None,
                    activation_policy_id: None,
                },
            ),
        )?;
        self.apply(
            10,
            33,
            self.ids.administrator,
            &AuthoritativeCommand::CreateFederationGrantAssignment(
                CreateFederationGrantAssignment {
                    assignment_id: self.ids.write_assignment,
                    grant_id: self.ids.grant,
                    subject_principal_id: self.ids.user,
                    rights: Rights::WRITE_DATA,
                    valid_from: None,
                    valid_until: None,
                    activation_policy_id: Some(self.ids.activation_policy),
                },
            ),
        )?;
        self.remote_cache.install_remote_federation_authority(
            &self.remote_snapshot(record),
            UnixMicros::new(19),
        )?;
        Ok(())
    }

    fn issue_session(&mut self) -> Result<(), Box<dyn Error>> {
        self.apply(
            11,
            22,
            self.ids.user,
            &AuthoritativeCommand::CreateAuthenticationMethod(CreateAuthenticationMethod {
                method_id: AuthenticationMethodId::from_bytes([18; 16])?,
                principal_id: self.ids.user,
                label: "API key".to_owned(),
                service_scope: AuthenticationService::Https.scope_bit(),
                expires_at: None,
                credential: NewAuthenticationCredential::ApiKey {
                    key_id: ApiKeyId::from_bytes([20; 16])?,
                    key_digest: [21; 32],
                    scopes: AuthenticationService::Https.api_key_login_scope(),
                    valid_from: UnixMicros::new(1),
                },
            }),
        )?;
        self.apply(
            12,
            23,
            self.ids.user,
            &AuthoritativeCommand::CreateAuthenticationMethod(CreateAuthenticationMethod {
                method_id: AuthenticationMethodId::from_bytes([19; 16])?,
                principal_id: self.ids.user,
                label: "TOTP".to_owned(),
                service_scope: AuthenticationService::Https.scope_bit(),
                expires_at: None,
                credential: NewAuthenticationCredential::Totp {
                    secret_ciphertext: vec![22; 64],
                    algorithm: TotpAlgorithm::Sha256,
                    digits: 6,
                    period_seconds: 30,
                    accepted_step_window: 1,
                },
            }),
        )?;
        self.apply(
            13,
            24,
            self.ids.user,
            &AuthoritativeCommand::IssueAuthenticationSession(IssueAuthenticationSession {
                session_id: self.ids.session,
                principal_id: self.ids.user,
                token_digest: [15; 32],
                csrf_digest: [16; 32],
                client_label: meshspan_metadata::SessionClientLabel::Missing,
                persistent_cookie: false,
                service: AuthenticationService::Https,
                factors: BoundedItems::new(
                    vec![
                        SessionAuthenticationFactor::ApiKey {
                            method_id: AuthenticationMethodId::from_bytes([18; 16])?,
                            credential_generation: 1,
                            method_revision: Revision::new(11),
                            key_id: ApiKeyId::from_bytes([20; 16])?,
                        },
                        SessionAuthenticationFactor::Totp {
                            method_id: AuthenticationMethodId::from_bytes([19; 16])?,
                            credential_generation: 1,
                            method_revision: Revision::new(12),
                            accepted_step: 0,
                        },
                    ],
                    8,
                )?,
                expires_at: UnixMicros::new(90),
            }),
        )
    }

    fn revoke_session(&mut self) -> Result<(), Box<dyn Error>> {
        self.apply(
            15,
            28,
            self.ids.user,
            &AuthoritativeCommand::RevokeAuthenticationSession(RevokeAuthenticationSession {
                session_id: self.ids.session,
                principal_id: self.ids.user,
            }),
        )
    }

    fn activate_write_assignment(&mut self) -> Result<(), Box<dyn Error>> {
        self.apply(
            14,
            34,
            self.ids.user,
            &AuthoritativeCommand::ActivateFederationGrantAssignment(
                ActivateFederationGrantAssignment {
                    activation_id: self.ids.activation,
                    principal_id: self.ids.user,
                    assignment_id: self.ids.write_assignment,
                    policy_id: self.ids.activation_policy,
                    reason: "Edit the shared report".to_owned(),
                    duration: DurationMicros::new(50),
                    session_expires_at: UnixMicros::new(90),
                    assurance: AssuranceLevel::MultiFactor,
                    authentication_digest: [15; 32],
                },
            ),
        )
    }

    fn apply(
        &mut self,
        index: u64,
        seed: u8,
        actor: PrincipalId,
        command: &AuthoritativeCommand,
    ) -> Result<(), Box<dyn Error>> {
        self.repository.apply_committed(
            LogPosition { index, term: 1 },
            CommandContext {
                operation_id: OperationId::from_bytes([seed; 16])?,
                actor_principal_id: actor,
                audit_event_id: AuditEventId::from_bytes([seed.saturating_add(30); 16])?,
                occurred_at: UnixMicros::new(i64::try_from(index)?),
                expected_revision: Some(Revision::new(index.saturating_sub(1))),
            },
            command,
        )?;
        Ok(())
    }

    fn grant_record(&self) -> Result<FederationGrantRecord, Box<dyn Error>> {
        let policy = FederationPolicy::Namespace(NamespaceFederationPolicy::new(
            FederationAccess::new(
                Rights::TRAVERSE
                    .union(Rights::CREATE_CHILD)
                    .union(Rights::WRITE_DATA),
                false,
            ),
            None,
        ));
        let mut restrictions = vec![
            FederationGrantRestriction {
                imposing_mesh_id: self.ids.owner_mesh,
                policy,
            },
            FederationGrantRestriction {
                imposing_mesh_id: self.ids.local_mesh,
                policy,
            },
            FederationGrantRestriction {
                imposing_mesh_id: self.ids.remote_mesh,
                policy,
            },
        ];
        restrictions.sort_by_key(|restriction| restriction.imposing_mesh_id);
        Ok(FederationGrantRecord {
            grant: FederationGrant::new(
                self.ids.grant,
                self.ids.relationship,
                FederationGrantRoute::from_meshes(vec![
                    self.ids.owner_mesh,
                    self.ids.remote_mesh,
                    self.ids.local_mesh,
                ])?,
                Some(FederationGrantId::from_bytes([29; 16])?),
                FederationResourceScope::Volume {
                    owner_mesh_id: self.ids.owner_mesh,
                    volume_id: self.ids.volume,
                },
                policy,
                1,
                UnixMicros::new(10),
                Some(UnixMicros::new(90)),
            )?,
            restrictions,
            state: FederationGrantState::Active,
            issued_at: UnixMicros::new(16),
            termination: None,
            predecessor_grant_id: None,
            successor_grant_id: None,
            revision: Revision::new(6),
        })
    }

    fn remote_snapshot(&self, grant: FederationGrantRecord) -> FederationRemoteAuthoritySnapshot {
        FederationRemoteAuthoritySnapshot {
            after_revision: Revision::ZERO,
            authority_revision: Revision::new(6),
            relationship: FederationTransportAuthority {
                authority_revision: Revision::new(6),
                relationship: FederationRelationshipRecord {
                    relationship_id: self.ids.relationship,
                    local_mesh_id: self.ids.remote_mesh,
                    remote_mesh_id: self.ids.local_mesh,
                    kind: FederationRelationshipKind::Horizontal,
                    governance_direction: FederationGovernanceDirection::None,
                    state: FederationRelationshipState::Active,
                    authority_epoch: 1,
                    remote_display_name: "Accepting swarm".to_owned(),
                    revision: Revision::new(5),
                },
                local_identity: identity_record(
                    self.ids.relationship,
                    FederationIdentityOwner::Local,
                    &self.remote_key,
                    17,
                ),
                remote_identity: identity_record(
                    self.ids.relationship,
                    FederationIdentityOwner::Remote,
                    &self.local_key,
                    16,
                ),
            },
            grants: vec![grant],
        }
    }

    fn request(&self, now: i64) -> FederationMutationAcceptanceRequest {
        FederationMutationAcceptanceRequest {
            relationship_id: self.ids.relationship,
            grant_id: self.ids.grant,
            session: SessionAccessRequest {
                token_digest: [15; 32],
                required_assurance: AssuranceLevel::SingleFactor,
                gateway_node_id: self.ids.node,
                gateway_incarnation: 1,
                now: UnixMicros::new(now),
            },
            now: UnixMicros::new(now),
        }
    }

    fn publication(&self) -> Result<RootFilePublication, Box<dyn Error>> {
        Ok(RootFilePublication {
            file: FilePublication {
                operation_id: OperationId::from_bytes([40; 16])?,
                branch_id: BranchId::from_bytes([41; 16])?,
                volume_id: self.ids.volume,
                object_id: ObjectId::from_bytes([42; 16])?,
                expected_current_version_id: None,
                version_id: FileVersionId::from_bytes([43; 16])?,
                parent_version_id: None,
                retain_superseded_history: true,
                retention_policy_sequence: 1,
                manifest: ManifestPublication {
                    manifest_id: ContentManifestId::from_bytes([44; 16])?,
                    format_version: 1,
                    logical_length: 4,
                    content_digest: [45; 32],
                    root_digest: [46; 32],
                },
                created_by: self.ids.user,
                created_at: UnixMicros::new(13),
            },
            root_object_id: ObjectId::from_bytes([47; 16])?,
            expected_namespace_commit_id: None,
            expected_file_object_revision_id: None,
            file_object_revision_id: ObjectRevisionId::from_bytes([48; 16])?,
            root_object_revision_id: ObjectRevisionId::from_bytes([49; 16])?,
            namespace_commit_id: NamespaceCommitId::from_bytes([50; 16])?,
            path: NamespacePublicationPath::new(
                NamespacePath::from_components(["report"], NamespaceLimits::PORTABLE)?,
                Vec::new(),
            )?,
            entry_generation: 1,
        })
    }
}

fn identity(key: &SigningKey, fingerprint: u8) -> FederationTrustIdentity {
    FederationTrustIdentity {
        generation: 1,
        certificate_fingerprint: [fingerprint; 32],
        verifying_key: key.verifying_key().to_bytes(),
        valid_from: UnixMicros::new(1),
        valid_until: UnixMicros::new(100),
    }
}

fn identity_record(
    relationship_id: FederationRelationshipId,
    owner: FederationIdentityOwner,
    key: &SigningKey,
    fingerprint: u8,
) -> FederationTrustIdentityRecord {
    FederationTrustIdentityRecord {
        relationship_id,
        owner,
        identity: identity(key, fingerprint),
        revision: Revision::new(5),
    }
}
