// SPDX-License-Identifier: GPL-2.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use meshspan_cluster::{
    ConsensusMessageTransport, MetadataAuthorityConfig, MetadataAuthorityHandle,
    MetadataAuthorityRuntimeError, PartitionConsensusDriver, spawn_metadata_authority,
};
use meshspan_consensus::{ConsensusCore, CoreConfig, MemberIncarnations, compile_plan, flat_plan};
use meshspan_contracts::{
    BoundedItems, ShardIdentity, ShardReadPermit, StoragePermitMacKey, read_permit_mac,
};
use meshspan_domain::{
    ApiKeyBundle, AuditEventId, AuthenticationMethodId, AuthenticationService, EntropyError,
    HostId, MeshId, NodeId, OperationId, PartitionId, PrincipalId, QuorumPlanId, RandomSource,
    Revision, RoleId, SessionCsrfBundle, SessionTokenBundle, UnixMicros,
};
use meshspan_metadata::{
    AuthoritativeCommand, AuthoritativeRepository, BootstrapMesh, BootstrapRecoveryIdentity,
    BrowserSessionAccessRequest, BrowserSessionProtection, CommandContext,
    ConfirmRecoveryBundleSaved, CreateAuthenticationMethod, IssueAuthenticationSession,
    NewAuthenticationCredential, PageLimit, PartitionDatabase, PrincipalKind, RecordName,
    RevokeAuthenticationMethod, RevokeAuthenticationSession, SessionAccessDecision,
    SessionAccessRequest, SessionAuthenticationFactor, SessionClientLabel,
    VOLUME_CONTENT_KEY_SECRET_KIND,
};
use meshspan_secret_envelope::{SecretContext, WrappingPublicKey, encrypt_secret};
use sha2::{Digest, Sha256};

use crate::{
    ApiKeyIssuanceAuthority, AuthenticationMethodListingAuthority,
    AuthenticationMethodRevocationAuthority, BrowserSessionAuthority,
    ConsensusAuthenticationAuthority, IdentityAdministrationAuthority,
    IdentityAdministrationAuthorityError, LocalWrappingKey, RecoveryBundleVerificationAuthority,
    RecoveryBundleVerificationAuthorityError, SessionAuthority, SessionRevocationAuthority,
    StoragePermitLoadingService, VolumeAdministrationAuthority, VolumeKeyLoadingService,
};

#[path = "backup_schedule_service_tests.rs"]
mod backup_schedule;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authentication_reads_and_session_mutation_share_committed_consensus_state()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = RunningAuthority::start().await?;
    let committed = fixture.create_session()?;
    assert_ne!(committed.session.result_digest, [0; 32]);
    assert!(matches!(
        committed.before_revocation,
        SessionAccessDecision::Granted(_)
    ));
    assert_ne!(committed.revocation.result_digest, [0; 32]);
    assert!(matches!(
        committed.after_revocation,
        SessionAccessDecision::Denied(_)
    ));
    fixture.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn api_key_lifecycle_is_committed_listed_and_revoked_through_consensus()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = RunningAuthority::start().await?;
    let result = fixture.api_key_lifecycle()?;
    assert_eq!(result.method_count, 2);
    assert_eq!(result.issuance.method_id, result.revocation.method_id);
    assert!(result.authenticated_before_revocation);
    assert!(!result.authenticated_after_revocation);
    fixture.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn identity_creation_conflict_and_later_work_share_consensus()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = RunningAuthority::start().await?;
    let result = fixture.identity_lifecycle()?;
    assert_eq!(result.first_revision, 2);
    assert_eq!(result.final_revision, 3);
    assert_eq!(result.user_count, 3);
    assert_eq!(
        result.conflict,
        IdentityAdministrationAuthorityError::Conflict
    );
    fixture.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn volume_creation_returns_exact_committed_projection()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = RunningAuthority::start().await?;
    let commit = fixture.volume_lifecycle()?;
    assert_eq!(commit.record.display_name, "Shared files");
    assert_eq!(commit.record.revision.get(), 3);
    fixture.shutdown().await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn recovery_bundle_verification_round_trips_through_consensus()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = RunningAuthority::start().await?;
    let (commit, replay, conflict) = fixture.recovery_lifecycle()?;
    assert_eq!(commit, replay);
    assert_eq!(
        commit.authority.state,
        meshspan_metadata::RecoveryBundleState::Verified
    );
    assert_eq!(commit.authority.revision, Revision::new(2));
    assert_eq!(conflict, RecoveryBundleVerificationAuthorityError::Conflict);
    fixture.shutdown().await
}

type AuthorityRuntime = tokio::task::JoinHandle<Result<(), MetadataAuthorityRuntimeError>>;

struct AuthenticationRoundTrip {
    session: crate::SessionCommit,
    before_revocation: SessionAccessDecision,
    revocation: crate::SessionRevocationCommit,
    after_revocation: SessionAccessDecision,
}

struct ApiKeyLifecycle {
    issuance: crate::ApiKeyIssuanceCommit,
    revocation: crate::AuthenticationMethodRevocationCommit,
    method_count: usize,
    authenticated_before_revocation: bool,
    authenticated_after_revocation: bool,
}

struct IdentityLifecycle {
    first_revision: u64,
    final_revision: u64,
    user_count: usize,
    conflict: IdentityAdministrationAuthorityError,
}

struct RunningAuthority {
    directory: tempfile::TempDir,
    node_id: NodeId,
    administrator_id: PrincipalId,
    api_key: ApiKeyBundle,
    reader: Option<AuthoritativeRepository>,
    handle: MetadataAuthorityHandle,
    runtime: AuthorityRuntime,
}

impl RunningAuthority {
    async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        Self::start_with_partition(PartitionId::from_bytes([2; 16])?).await
    }

    async fn start_with_partition(
        partition_id: PartitionId,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let database_path = directory.path().join("partition.sqlite3");
        let node_id = NodeId::from_bytes([1; 16])?;
        let plan = compile_plan(flat_plan(
            QuorumPlanId::from_bytes([3; 16])?,
            1,
            BTreeSet::from([node_id]),
            BTreeSet::new(),
        )?)?;
        let mut writer = AuthoritativeRepository::new(PartitionDatabase::open(
            &database_path,
            partition_id,
            UnixMicros::new(1),
        )?);
        writer.initialise_consensus_quorum_plan(&plan, UnixMicros::new(2))?;
        let reader = AuthoritativeRepository::new(PartitionDatabase::open(
            &database_path,
            partition_id,
            UnixMicros::new(1),
        )?);
        let incarnations = MemberIncarnations::new(BTreeMap::from([(node_id, 1)]), &plan)?;
        let core = ConsensusCore::new(CoreConfig {
            partition_id,
            local_node_id: node_id,
            local_incarnation: 1,
            plan,
            member_incarnations: incarnations,
        })?;
        let transport: Arc<dyn ConsensusMessageTransport> = Arc::new(|_, _| {});
        let (handle, runtime) = spawn_metadata_authority(
            PartitionConsensusDriver::new(core, writer),
            transport,
            MetadataAuthorityConfig::default(),
        )?;
        handle.begin_election().await?;
        let mut random = SequentialRandom(10);
        let api_key = ApiKeyBundle::generate(&mut random)?;
        let administrator_id = PrincipalId::from_bytes([4; 16])?;
        let wrapping_key_path = directory.path().join("volume-wrapping.key");
        let wrapping_key = LocalWrappingKey::open_or_create(&wrapping_key_path)?;
        let context = command_context(administrator_id, 5, 6, 10, Some(Revision::ZERO))?;
        handle
            .commit_or_resolve(
                context,
                bootstrap_command(
                    node_id,
                    administrator_id,
                    &api_key,
                    wrapping_key.public_key(),
                )?,
            )
            .await?;
        Ok(Self {
            directory,
            node_id,
            administrator_id,
            api_key,
            reader: Some(reader),
            handle,
            runtime,
        })
    }

    fn create_session(&mut self) -> Result<AuthenticationRoundTrip, Box<dyn std::error::Error>> {
        let reader = self
            .reader
            .take()
            .ok_or("test read connection was already consumed")?;
        let authority_handle = self.handle.clone();
        let api_key = &self.api_key;
        let administrator_id = self.administrator_id;
        let node_id = self.node_id;
        tokio::task::block_in_place(move || {
            let mut authority = ConsensusAuthenticationAuthority::new(
                reader,
                authority_handle,
                tokio::runtime::Handle::current(),
            );
            let authenticated = authority
                .authenticate_api_key(
                    api_key.key_id(),
                    api_key.secret_digest(),
                    UnixMicros::new(20),
                )
                .map_err(|error| std::io::Error::other(format!("authentication read: {error:?}")))?
                .ok_or("API key was not visible through the read connection")?;
            let operation_id = OperationId::from_bytes([7; 16])?;
            let bearer = SessionTokenBundle::derive(api_key, operation_id)?;
            let csrf = SessionCsrfBundle::derive(api_key, operation_id)?;
            let command = session_command(administrator_id, &authenticated, &bearer, &csrf)?;
            let context = command_context(administrator_id, 7, 8, 20, None)?;
            let receipt = authority
                .commit_or_resolve(context, &command)
                .map_err(|error| std::io::Error::other(format!("session commit: {error:?}")))?;
            let access_request = BrowserSessionAccessRequest {
                expected_session_id: bearer.session_id(),
                session: SessionAccessRequest {
                    token_digest: bearer.token_digest(),
                    required_assurance: meshspan_domain::AssuranceLevel::SingleFactor,
                    gateway_node_id: node_id,
                    gateway_incarnation: 1,
                    now: UnixMicros::new(21),
                },
                protection: BrowserSessionProtection::Mutation {
                    csrf_digest: csrf.token_digest(),
                },
            };
            let before_revocation = authority
                .evaluate_browser_session(access_request)
                .map_err(|error| std::io::Error::other(format!("session read: {error:?}")))?;
            let revocation = authority
                .commit_or_resolve_revocation(
                    command_context(administrator_id, 13, 14, 22, None)?,
                    &AuthoritativeCommand::RevokeAuthenticationSession(
                        RevokeAuthenticationSession {
                            session_id: bearer.session_id(),
                            principal_id: administrator_id,
                        },
                    ),
                )
                .map_err(|error| std::io::Error::other(format!("revocation commit: {error:?}")))?;
            let after_revocation = authority
                .evaluate_browser_session(BrowserSessionAccessRequest {
                    session: SessionAccessRequest {
                        now: UnixMicros::new(23),
                        ..access_request.session
                    },
                    ..access_request
                })
                .map_err(|error| {
                    std::io::Error::other(format!("revoked session read: {error:?}"))
                })?;
            Ok::<_, Box<dyn std::error::Error>>(AuthenticationRoundTrip {
                session: receipt,
                before_revocation,
                revocation,
                after_revocation,
            })
        })
    }

    fn api_key_lifecycle(&mut self) -> Result<ApiKeyLifecycle, Box<dyn std::error::Error>> {
        let reader = self
            .reader
            .take()
            .ok_or("test read connection was already consumed")?;
        let authority_handle = self.handle.clone();
        let administrator_id = self.administrator_id;
        tokio::task::block_in_place(move || {
            let mut authority = ConsensusAuthenticationAuthority::new(
                reader,
                authority_handle,
                tokio::runtime::Handle::current(),
            );
            let mut random = SequentialRandom(100);
            let api_key = ApiKeyBundle::generate(&mut random)?;
            let method_id = AuthenticationMethodId::from_bytes([15; 16])?;
            let creation = api_key_creation(administrator_id, method_id, &api_key);
            let issuance = authority.commit_or_resolve_api_key_issuance(
                command_context(administrator_id, 16, 17, 30, None)?,
                &creation,
            )?;
            let method_count = authority
                .authentication_methods(administrator_id, None, PageLimit::new(10)?)?
                .items
                .len();
            let authenticated_before_revocation = authority
                .authenticate_api_key(
                    api_key.key_id(),
                    api_key.secret_digest(),
                    UnixMicros::new(31),
                )?
                .is_some();
            let revocation = authority.commit_or_resolve_authentication_method_revocation(
                command_context(administrator_id, 18, 19, 32, None)?,
                &AuthoritativeCommand::RevokeAuthenticationMethod(RevokeAuthenticationMethod {
                    method_id,
                    principal_id: administrator_id,
                    reason: "No longer needed".to_owned(),
                }),
            )?;
            let authenticated_after_revocation = authority
                .authenticate_api_key(
                    api_key.key_id(),
                    api_key.secret_digest(),
                    UnixMicros::new(33),
                )?
                .is_some();
            Ok::<_, Box<dyn std::error::Error>>(ApiKeyLifecycle {
                issuance,
                revocation,
                method_count,
                authenticated_before_revocation,
                authenticated_after_revocation,
            })
        })
    }

    fn identity_lifecycle(&mut self) -> Result<IdentityLifecycle, Box<dyn std::error::Error>> {
        let reader = self
            .reader
            .take()
            .ok_or("test read connection was already consumed")?;
        let authority_handle = self.handle.clone();
        let administrator_id = self.administrator_id;
        tokio::task::block_in_place(move || {
            let mut authority = ConsensusAuthenticationAuthority::new(
                reader,
                authority_handle,
                tokio::runtime::Handle::current(),
            );
            let first = user_creation(20, "Managed user")?;
            let first_commit = authority.commit_or_resolve_principal_creation(
                command_context(administrator_id, 20, 21, 40, None)?,
                &first,
                PrincipalKind::User,
            )?;
            let duplicate = user_creation(30, "Managed user")?;
            let Err(conflict) = authority.commit_or_resolve_principal_creation(
                command_context(administrator_id, 30, 31, 41, None)?,
                &duplicate,
                PrincipalKind::User,
            ) else {
                return Err("duplicate canonical name was accepted".into());
            };
            let final_command = user_creation(40, "Later user")?;
            let final_commit = authority.commit_or_resolve_principal_creation(
                command_context(administrator_id, 40, 41, 42, None)?,
                &final_command,
                PrincipalKind::User,
            )?;
            let user_count = authority
                .principals(PrincipalKind::User, None, PageLimit::new(10)?)?
                .items
                .len();
            Ok::<_, Box<dyn std::error::Error>>(IdentityLifecycle {
                first_revision: first_commit.committed_revision,
                final_revision: final_commit.committed_revision,
                user_count,
                conflict,
            })
        })
    }

    fn volume_lifecycle(
        &mut self,
    ) -> Result<crate::VolumeAdministrationCommit, Box<dyn std::error::Error>> {
        let reader = self
            .reader
            .take()
            .ok_or("test read connection was already consumed")?;
        let authority_handle = self.handle.clone();
        let administrator_id = self.administrator_id;
        let wrapping_key_path = self.directory.path().join("volume-wrapping.key");
        tokio::task::block_in_place(move || {
            let mut authority = ConsensusAuthenticationAuthority::new(
                reader,
                authority_handle,
                tokio::runtime::Handle::current(),
            );
            let recovery =
                AuthoritativeCommand::ConfirmRecoveryBundleSaved(ConfirmRecoveryBundleSaved {
                    mesh_id: MeshId::from_bytes([9; 16])?,
                    bundle_digest: [92; 32],
                    save_challenge_commitment: [93; 32],
                });
            authority.commit_or_resolve_recovery_bundle_verification(
                command_context(administrator_id, 45, 46, 39, None)?,
                &recovery,
            )?;
            let local_wrapping_key = LocalWrappingKey::open_or_create(&wrapping_key_path)?;
            let mesh_id = MeshId::from_bytes([9; 16])?;
            let permit = ShardReadPermit {
                operation_id: OperationId::from_bytes([47; 16])?,
                mesh_id,
                target_id: meshspan_domain::TargetId::from_bytes([48; 16])?,
                target_generation: 1,
                shard: ShardIdentity {
                    manifest_digest: [49; 32],
                    stripe_index: 1,
                    shard_index: 2,
                    generation: 3,
                },
                authorization_revision: Revision::new(2),
                expires_at: UnixMicros::new(100),
                permit_digest: [0; 32],
            };
            let permit_key = StoragePermitLoadingService::new(&authority, &local_wrapping_key)
                .load_latest(mesh_id)?;
            if read_permit_mac(&permit_key, permit)
                != read_permit_mac(&StoragePermitMacKey::from_bytes([93; 32])?, permit)
            {
                return Err("loaded storage permit authority changed".into());
            }
            let volume_id = meshspan_domain::VolumeId::from_bytes([50; 16])?;
            let recipients = authority.volume_key_recipients()?;
            let (secret, envelopes) = encrypt_secret(
                SecretContext::new(VOLUME_CONTENT_KEY_SECRET_KIND, volume_id.as_bytes(), 1)?,
                &[49; 32],
                &recipients,
                &mut SequentialRandom(94),
            )?;
            let command = AuthoritativeCommand::CreateVolume(meshspan_metadata::CreateVolume {
                volume_id,
                name: RecordName::new("Shared files")?,
                root_object_id: meshspan_domain::ObjectId::from_bytes([51; 16])?,
                owner_set_id: meshspan_domain::OwnerSetId::from_bytes([52; 16])?,
                owners: BoundedItems::new(vec![administrator_id], 1_024)?,
                key_generation: Box::new(meshspan_metadata::CommitSecretGeneration {
                    secret: secret.parts(),
                    recipients: envelopes
                        .into_iter()
                        .map(|envelope| envelope.parts())
                        .collect(),
                }),
            });
            let commit = authority.commit_or_resolve_volume_creation(
                command_context(administrator_id, 50, 51, 41, None)?,
                &command,
            )?;
            let loaded =
                VolumeKeyLoadingService::new(&authority, &local_wrapping_key).load(volume_id, 1)?;
            if loaded.generation() != 1 {
                return Err("loaded volume key generation changed".into());
            }
            Ok(commit)
        })
    }

    fn recovery_lifecycle(
        &mut self,
    ) -> Result<
        (
            crate::RecoveryBundleVerificationCommit,
            crate::RecoveryBundleVerificationCommit,
            RecoveryBundleVerificationAuthorityError,
        ),
        Box<dyn std::error::Error>,
    > {
        let reader = self
            .reader
            .take()
            .ok_or("test read connection was already consumed")?;
        let authority_handle = self.handle.clone();
        let administrator_id = self.administrator_id;
        tokio::task::block_in_place(move || {
            let mut authority = ConsensusAuthenticationAuthority::new(
                reader,
                authority_handle,
                tokio::runtime::Handle::current(),
            );
            let mesh_id = MeshId::from_bytes([9; 16])?;
            let recovery_confirmation = ConfirmRecoveryBundleSaved {
                mesh_id,
                bundle_digest: [92; 32],
                save_challenge_commitment: [93; 32],
            };
            let command = AuthoritativeCommand::ConfirmRecoveryBundleSaved(recovery_confirmation);
            let context = command_context(administrator_id, 94, 95, 20, None)?;
            let commit =
                authority.commit_or_resolve_recovery_bundle_verification(context, &command)?;
            let replay = authority
                .resolve_recovery_bundle_verification(context.operation_id)?
                .ok_or("recovery verification was not resolved")?;
            let changed =
                AuthoritativeCommand::ConfirmRecoveryBundleSaved(ConfirmRecoveryBundleSaved {
                    save_challenge_commitment: [96; 32],
                    ..recovery_confirmation
                });
            let conflict = authority
                .commit_or_resolve_recovery_bundle_verification(context, &changed)
                .err()
                .ok_or("changed recovery proof reused an operation ID without conflict")?;
            Ok::<_, Box<dyn std::error::Error>>((commit, replay, conflict))
        })
    }

    async fn shutdown(self) -> Result<(), Box<dyn std::error::Error>> {
        self.handle.shutdown().await?;
        self.runtime.await??;
        Ok(())
    }
}

fn user_creation(
    marker: u8,
    name: &str,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    Ok(AuthoritativeCommand::CreateUser(
        meshspan_metadata::CreateUser {
            principal_id: PrincipalId::from_bytes([marker; 16])?,
            name: RecordName::new(name)?,
        },
    ))
}

fn api_key_creation(
    principal_id: PrincipalId,
    method_id: AuthenticationMethodId,
    api_key: &ApiKeyBundle,
) -> AuthoritativeCommand {
    AuthoritativeCommand::CreateAuthenticationMethod(CreateAuthenticationMethod {
        method_id,
        principal_id,
        label: "Automation".to_owned(),
        service_scope: AuthenticationService::Https.scope_bit()
            | AuthenticationService::HeadlessApi.scope_bit()
            | AuthenticationService::Smb.scope_bit(),
        expires_at: None,
        credential: NewAuthenticationCredential::ApiKey {
            key_id: api_key.key_id(),
            key_digest: api_key.secret_digest(),
            smb_verifier_ciphertext: Some(vec![41; 65]),
            scopes: AuthenticationService::Https.api_key_login_scope()
                | AuthenticationService::HeadlessApi.api_key_login_scope()
                | AuthenticationService::Smb.api_key_login_scope(),
            valid_from: UnixMicros::new(30),
        },
    })
}

fn bootstrap_command(
    node_id: NodeId,
    administrator_id: PrincipalId,
    api_key: &ApiKeyBundle,
    wrapping_public_key: WrappingPublicKey,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    Ok(AuthoritativeCommand::BootstrapAppliance(Box::new(
        crate::bootstrap_test_support::bootstrap_appliance_with_node_key(
            BootstrapMesh {
                mesh_id: MeshId::from_bytes([9; 16])?,
                mesh_name: RecordName::new("Test mesh")?,
                administrator_id,
                administrator_name: RecordName::new("Administrator")?,
                administrator_role_id: RoleId::from_bytes([10; 16])?,
                host_id: HostId::from_bytes([11; 16])?,
                host_name: RecordName::new("Test host")?,
                node_id,
                node_name: RecordName::new("Test node")?,
                partition_name: RecordName::new("Root authority")?,
            },
            CreateAuthenticationMethod {
                method_id: AuthenticationMethodId::from_bytes([12; 16])?,
                principal_id: administrator_id,
                label: "Initial API key".to_owned(),
                service_scope: AuthenticationService::Https.scope_bit()
                    | AuthenticationService::HeadlessApi.scope_bit()
                    | AuthenticationService::Smb.scope_bit(),
                expires_at: None,
                credential: NewAuthenticationCredential::ApiKey {
                    key_id: api_key.key_id(),
                    key_digest: api_key.secret_digest(),
                    smb_verifier_ciphertext: Some(vec![42; 65]),
                    scopes: AuthenticationService::Https.api_key_login_scope()
                        | AuthenticationService::HeadlessApi.api_key_login_scope()
                        | AuthenticationService::Smb.api_key_login_scope(),
                    valid_from: UnixMicros::new(10),
                },
            },
            Box::new(recovery_identity()?),
            wrapping_public_key,
        )?,
    )))
}

fn recovery_identity() -> Result<BootstrapRecoveryIdentity, Box<dyn std::error::Error>> {
    let public_key = WrappingPublicKey::from_bytes([90; 32])?;
    let certificate = vec![91; 64];
    Ok(BootstrapRecoveryIdentity {
        public_wrapping_key: public_key.as_bytes(),
        key_fingerprint: public_key.fingerprint(),
        online_authority_certificate_digest: Sha256::digest(&certificate).into(),
        online_authority_certificate_der: certificate.clone(),
        root_certificate_digest: Sha256::digest(&certificate).into(),
        root_certificate_der: certificate,
        bundle_digest: [92; 32],
        save_challenge_commitment: [93; 32],
    })
}

fn session_command(
    principal_id: PrincipalId,
    authenticated: &meshspan_metadata::ApiKeyAuthentication,
    bearer: &SessionTokenBundle,
    csrf: &SessionCsrfBundle,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    Ok(AuthoritativeCommand::IssueAuthenticationSession(
        IssueAuthenticationSession {
            session_id: bearer.session_id(),
            principal_id,
            token_digest: bearer.token_digest(),
            csrf_digest: csrf.token_digest(),
            client_label: SessionClientLabel::Missing,
            persistent_cookie: false,
            service: AuthenticationService::Https,
            factors: BoundedItems::new(
                vec![SessionAuthenticationFactor::ApiKey {
                    method_id: authenticated.method_id,
                    credential_generation: authenticated.credential_generation,
                    method_revision: authenticated.revision,
                    key_id: authenticated.key_id,
                }],
                8,
            )?,
            expires_at: UnixMicros::new(1_000_000),
        },
    ))
}

fn command_context(
    actor_principal_id: PrincipalId,
    operation_marker: u8,
    audit_marker: u8,
    occurred_at: i64,
    expected_revision: Option<Revision>,
) -> Result<CommandContext, Box<dyn std::error::Error>> {
    Ok(CommandContext {
        operation_id: OperationId::from_bytes([operation_marker; 16])?,
        actor_principal_id,
        audit_event_id: AuditEventId::from_bytes([audit_marker; 16])?,
        occurred_at: UnixMicros::new(occurred_at),
        expected_revision,
    })
}

struct SequentialRandom(u8);

impl RandomSource for SequentialRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        for byte in destination {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}
