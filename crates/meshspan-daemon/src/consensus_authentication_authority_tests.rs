// SPDX-License-Identifier: GPL-2.0-only

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use meshspan_cluster::{
    ConsensusMessageTransport, MetadataAuthorityConfig, MetadataAuthorityHandle,
    MetadataAuthorityRuntimeError, PartitionConsensusDriver, spawn_metadata_authority,
};
use meshspan_consensus::{ConsensusCore, CoreConfig, MemberIncarnations, compile_plan, flat_plan};
use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    ApiKeyBundle, AuditEventId, AuthenticationMethodId, AuthenticationService, EntropyError,
    HostId, MeshId, NodeId, OperationId, PartitionId, PrincipalId, QuorumPlanId, RandomSource,
    Revision, RoleId, SessionCsrfBundle, SessionTokenBundle, UnixMicros,
};
use meshspan_metadata::{
    AuthoritativeCommand, AuthoritativeRepository, BootstrapAppliance, BootstrapMesh,
    BrowserSessionAccessRequest, BrowserSessionProtection, CommandContext,
    CreateAuthenticationMethod, IssueAuthenticationSession, NewAuthenticationCredential,
    PartitionDatabase, RecordName, SessionAccessDecision, SessionAccessRequest,
    SessionAuthenticationFactor, SessionClientLabel,
};

use crate::{BrowserSessionAuthority, ConsensusAuthenticationAuthority, SessionAuthority};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn authentication_reads_and_session_mutation_share_committed_consensus_state()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = RunningAuthority::start().await?;
    let committed = fixture.create_session()?;
    assert_ne!(committed.0.result_digest, [0; 32]);
    assert!(matches!(committed.1, SessionAccessDecision::Granted(_)));
    fixture.shutdown().await
}

type AuthorityRuntime = tokio::task::JoinHandle<Result<(), MetadataAuthorityRuntimeError>>;

struct RunningAuthority {
    _directory: tempfile::TempDir,
    node_id: NodeId,
    administrator_id: PrincipalId,
    api_key: ApiKeyBundle,
    reader: Option<AuthoritativeRepository>,
    handle: MetadataAuthorityHandle,
    runtime: AuthorityRuntime,
}

impl RunningAuthority {
    async fn start() -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let database_path = directory.path().join("partition.sqlite3");
        let node_id = NodeId::from_bytes([1; 16])?;
        let partition_id = PartitionId::from_bytes([2; 16])?;
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
        let context = command_context(administrator_id, 5, 6, 10, Some(Revision::ZERO))?;
        handle
            .commit_or_resolve(
                context,
                bootstrap_command(node_id, administrator_id, &api_key)?,
            )
            .await?;
        Ok(Self {
            _directory: directory,
            node_id,
            administrator_id,
            api_key,
            reader: Some(reader),
            handle,
            runtime,
        })
    }

    fn create_session(
        &mut self,
    ) -> Result<(crate::SessionCommit, SessionAccessDecision), Box<dyn std::error::Error>> {
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
            let decision = authority
                .evaluate_browser_session(BrowserSessionAccessRequest {
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
                })
                .map_err(|error| std::io::Error::other(format!("session read: {error:?}")))?;
            Ok::<_, Box<dyn std::error::Error>>((receipt, decision))
        })
    }

    async fn shutdown(self) -> Result<(), Box<dyn std::error::Error>> {
        self.handle.shutdown().await?;
        self.runtime.await??;
        Ok(())
    }
}

fn bootstrap_command(
    node_id: NodeId,
    administrator_id: PrincipalId,
    api_key: &ApiKeyBundle,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    Ok(AuthoritativeCommand::BootstrapAppliance(
        BootstrapAppliance {
            mesh: BootstrapMesh {
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
            authentication: CreateAuthenticationMethod {
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
                    scopes: AuthenticationService::Https.api_key_login_scope(),
                    valid_from: UnixMicros::new(10),
                },
            },
        },
    ))
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
