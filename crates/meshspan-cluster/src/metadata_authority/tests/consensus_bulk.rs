// SPDX-License-Identifier: GPL-2.0-only

use meshspan_domain::{ComponentInstanceId, TargetId};
use meshspan_metadata::{CreateComponent, RegisterStorageTarget, StorageUsageLimit};
use sha2::{Digest as _, Sha256};

use super::*;

#[tokio::test]
async fn three_real_voters_commit_and_reopen_a_legal_command_above_control_limit()
-> Result<(), Box<dyn std::error::Error>> {
    prove_committed_bytes(70 * 1024).await
}

#[tokio::test]
async fn three_real_voters_commit_and_reopen_maximum_provider_configuration()
-> Result<(), Box<dyn std::error::Error>> {
    prove_committed_bytes(512 * 1024).await
}

async fn prove_committed_bytes(
    configuration_bytes: usize,
) -> Result<(), Box<dyn std::error::Error>> {
    let cluster = RealAuthorityCluster::start().await?;
    let (mut context, command) = large_target_command(cluster.nodes[0], configuration_bytes)?;
    context.expected_revision = Some(Revision::new(8));
    let encoded = encode_authoritative_command(context, &command)?;
    assert!(encoded.len() > configuration_bytes);
    assert!(encoded.len() <= 1024 * 1024);
    let mut phase = "small bootstrap command";
    let proof = tokio::time::timeout(Duration::from_secs(15), async {
        cluster.authorities[0].0.begin_election().await?;
        prepare_admitted_bulk_members(&cluster).await?;
        phase = "legal >64KiB command replication";
        let receipt = commit_on_survivor(&cluster.authorities, context, &command)
            .await
            .map_err(|error| format!("large provider command: {error:?}"))?;
        assert_eq!(receipt.committed_revision, Revision::new(9));
        phase = "all-voter durable replay";
        for (authority, _) in &cluster.authorities {
            let replay = resolve_after_replication(authority, context, &command).await?;
            assert_eq!(replay.operation_id, receipt.operation_id);
            assert_eq!(replay.result_digest, receipt.result_digest);
            assert_eq!(replay.committed_position, receipt.committed_position);
        }
        Ok::<_, Box<dyn std::error::Error>>(receipt)
    })
    .await;
    // Stop every authority even when the regression reproduces a replication timeout.
    let directory = stop_preserving_storage(cluster).await?;
    let receipt = proof.map_err(|_| format!("real Quinn {phase} timed out"))??;
    for index in 0..3 {
        let file = directory.path().join(format!("quinn-node-{index}.sqlite3"));
        let repository =
            AuthoritativeRepository::new(PartitionDatabase::open_existing(&file, now())?);
        let state = repository.load_consensus_state(1)?;
        assert!(state.applied_index >= receipt.committed_position.index);
        let entry = state
            .log
            .iter()
            .find(|entry| entry.operation_id == context.operation_id)
            .ok_or("reopened voter lost the replicated command")?;
        assert_eq!(entry.command.as_ref(), encoded);
        let durable = repository
            .resolve_operation(context.operation_id)?
            .ok_or("reopened receipt missing")?;
        assert_eq!(durable.result_digest, receipt.result_digest);
        assert_eq!(durable.committed_position, receipt.committed_position);
    }
    Ok(())
}

fn large_target_command(
    node: NodeId,
    configuration_bytes: usize,
) -> Result<(CommandContext, AuthoritativeCommand), Box<dyn std::error::Error>> {
    let configuration = vec![b'x'; configuration_bytes];
    let context = CommandContext {
        operation_id: OperationId::from_bytes([101; 16])?,
        actor_principal_id: PrincipalId::from_bytes([30; 16])?,
        audit_event_id: AuditEventId::from_bytes([102; 16])?,
        occurred_at: UnixMicros::new(20),
        expected_revision: Some(Revision::new(1)),
    };
    let command = AuthoritativeCommand::RegisterStorageTarget(RegisterStorageTarget {
        target_id: TargetId::from_bytes([103; 16])?,
        node_id: node,
        host_id: HostId::from_bytes([34; 16])?,
        provider: CreateComponent {
            instance_id: ComponentInstanceId::from_bytes([104; 16])?,
            component_kind: 1,
            name: RecordName::new("Large configuration provider")?,
            implementation_id: "meshspan-folder".to_owned(),
            contract_major: 1,
            contract_minor: 0,
            schema_version: 1,
            configuration_digest: Sha256::digest(&configuration).into(),
            canonical_configuration: configuration,
        },
        name: RecordName::new("Large configuration target")?,
        generation: 1,
        marker_fingerprint: [105; 32],
        backing_device_fingerprint: None,
        filesystem_fingerprint: None,
        usage_limit: StorageUsageLimit::Percent(95),
    });
    Ok((context, command))
}

async fn stop_preserving_storage(
    cluster: RealAuthorityCluster,
) -> Result<tempfile::TempDir, Box<dyn std::error::Error>> {
    for (authority, _) in &cluster.authorities {
        authority.shutdown().await?;
    }
    for (_, runtime) in cluster.authorities {
        runtime.await??;
    }
    for forwarder in cluster.forwarders {
        forwarder.abort();
        match forwarder.await {
            Err(error) if error.is_cancelled() => {}
            Err(error) => return Err(error.into()),
            Ok(()) => {}
        }
    }
    Ok(cluster.directory)
}

async fn prepare_admitted_bulk_members(
    cluster: &RealAuthorityCluster,
) -> Result<(), Box<dyn std::error::Error>> {
    use meshspan_domain::JoinGrantId;
    use meshspan_metadata::{ActivateNode, ConsumeJoinGrant, IssueJoinGrant, JoinRoles};
    let (bootstrap_context, mut bootstrap) = super::command(cluster.nodes[0], [84; 16])?;
    let AuthoritativeCommand::BootstrapAppliance(value) = &mut bootstrap else {
        return Err("bootstrap fixture".into());
    };
    value.node_certificate.certificate_valid_until = UnixMicros::new(i64::MAX);
    value.node_certificate.certificate_der = cluster.certificate_der[0].clone();
    value.node_certificate.certificate_fingerprint =
        Sha256::digest(&value.node_certificate.certificate_der).into();
    commit_after_election(&cluster.authorities[0].0, bootstrap_context, &bootstrap)
        .await
        .map_err(|error| format!("capability setup bootstrap: {error:?}"))?;
    commit_on_survivor(
        &cluster.authorities,
        setup_context(109)?,
        &crate::protected_volume_test_support::confirm_recovery(MeshId::from_bytes([84; 16])?),
    )
    .await
    .map_err(|error| format!("capability setup recovery confirmation: {error:?}"))?;
    let roles =
        JoinRoles::new(JoinRoles::METADATA_ELIGIBLE | JoinRoles::STORAGE | JoinRoles::GATEWAY)?;
    let grant = JoinGrantId::from_bytes([110; 16])?;
    commit_on_survivor(
        &cluster.authorities,
        setup_context(111)?,
        &AuthoritativeCommand::IssueJoinGrant(IssueJoinGrant {
            join_grant_id: grant,
            secret_digest: [112; 32],
            allowed_roles: roles,
            maximum_uses: 2,
            expires_at: UnixMicros::new(i64::MAX),
        }),
    )
    .await
    .map_err(|error| format!("capability setup grant: {error:?}"))?;
    for index in 1..3 {
        let node = cluster.nodes[index];
        let endpoint = format!("node-{index}.internal:9412");
        let digest = Sha256::digest(&cluster.certificate_der[index]).into();
        let wrapping = meshspan_secret_envelope::WrappingPrivateKey::from_bytes(
            [u8::try_from(120 + index)?; 32],
        )?
        .public_key();
        let consume = AuthoritativeCommand::ConsumeJoinGrant(ConsumeJoinGrant {
            join_grant_id: grant,
            secret_digest: [112; 32],
            host_id: HostId::from_bytes([u8::try_from(121 + index)?; 16])?,
            new_host_name: Some(RecordName::new(&format!("Host {index}"))?),
            node_id: node,
            node_name: RecordName::new(&format!("Node {index}"))?,
            incarnation: 1,
            requested_roles: roles,
            wrapping_public_key: wrapping.as_bytes(),
            private_endpoint: endpoint.clone(),
            certificate_der: cluster.certificate_der[index].clone(),
            certificate_fingerprint: digest,
            certificate_valid_until: UnixMicros::new(i64::MAX),
        });
        commit_on_survivor(
            &cluster.authorities,
            setup_context(u8::try_from(113 + index * 2)?)?,
            &consume,
        )
        .await
        .map_err(|error| format!("capability setup consume {index}: {error:?}"))?;
        let observed = cluster.networks[index].local_capability_presentation()?;
        let activation = AuthoritativeCommand::ActivateNode(ActivateNode {
            node_id: node,
            incarnation: 1,
            private_endpoint: endpoint,
            capability_digest: observed.observed.capability_digest,
        });
        commit_on_survivor(
            &cluster.authorities,
            setup_context(u8::try_from(114 + index * 2)?)?,
            &activation,
        )
        .await
        .map_err(|error| format!("capability setup activation {index}: {error:?}"))?;
    }
    commit_root_capability_presentation(cluster).await
}

async fn commit_root_capability_presentation(
    cluster: &RealAuthorityCluster,
) -> Result<(), Box<dyn std::error::Error>> {
    use meshspan_metadata::{NodeCapabilityPrior, NodeCommandContext, RefreshNodeCapabilities};
    let local = cluster.networks[0].local_capability_presentation()?;
    let refresh = RefreshNodeCapabilities {
        node_id: cluster.nodes[0],
        incarnation: 1,
        certificate_generation: local.certificate_generation,
        certificate_fingerprint: local.binding.certificate_fingerprint,
        capability_digest: local.observed.capability_digest,
        prior: NodeCapabilityPrior::InitialAdmittedCertificate {
            revision: Revision::new(1),
            generation: local.certificate_generation,
            certificate_fingerprint: local.binding.certificate_fingerprint,
        },
    };
    let node_context = NodeCommandContext {
        operation_id: OperationId::from_bytes([125; 16])?,
        actor_node_id: cluster.nodes[0],
        audit_event_id: AuditEventId::from_bytes([126; 16])?,
        occurred_at: UnixMicros::new(20),
        expected_revision: None,
    };
    for (authority, _) in &cluster.authorities {
        match authority
            .commit_or_resolve_node(node_context, refresh)
            .await
        {
            Err(MetadataAuthorityRequestError::NotLeader { .. }) => {}
            outcome => {
                assert_eq!(
                    outcome
                        .map_err(|error| format!("capability setup self refresh: {error:?}"))?
                        .committed_revision,
                    Revision::new(8)
                );
                return Ok(());
            }
        }
    }
    Err("capability refresh had no leader".into())
}

fn setup_context(marker: u8) -> Result<CommandContext, Box<dyn std::error::Error>> {
    Ok(CommandContext {
        operation_id: OperationId::from_bytes([marker; 16])?,
        actor_principal_id: PrincipalId::from_bytes([30; 16])?,
        audit_event_id: AuditEventId::from_bytes([marker.wrapping_add(40); 16])?,
        occurred_at: UnixMicros::new(15),
        expected_revision: None,
    })
}

#[test]
fn unknown_or_unsupported_bulk_capability_never_appends_a_local_proposal()
-> Result<(), Box<dyn std::error::Error>> {
    for support in [
        None,
        Some(crate::ObservedConsensusTransferSupport {
            capability_digest: [140; 32],
            support: None,
        }),
    ] {
        let directory = tempfile::tempdir()?;
        let local = NodeId::from_bytes([76; 16])?;
        let driver = driver(&directory.path().join("admission.sqlite3"), local)?;
        let (_sender, events) = mpsc::channel(8);
        let mut runtime = MetadataAuthorityRuntime::new(
            driver,
            Arc::new(|_, _| {}),
            MetadataAuthorityConfig::default(),
            events,
            false,
        );
        runtime.process_input(CoreInput::ElectionTimeout)?;
        let (context, mut bootstrap) = command(local, [84; 16])?;
        let AuthoritativeCommand::BootstrapAppliance(value) = &mut bootstrap else {
            return Err("bootstrap fixture".into());
        };
        value.node_certificate.certificate_valid_until = UnixMicros::new(i64::MAX);
        submit_fixture(
            &mut runtime,
            AuthoritativeCommandContext::Principal(context),
            bootstrap,
        )?;
        let certificate = runtime
            .driver
            .persistence()
            .active_node_certificate(local)?
            .ok_or("certificate")?;
        let node_context = NodeCommandContext {
            operation_id: OperationId::from_bytes([141; 16])?,
            actor_node_id: local,
            audit_event_id: AuditEventId::from_bytes([142; 16])?,
            occurred_at: UnixMicros::new(20),
            expected_revision: None,
        };
        let refresh = RefreshNodeCapabilities {
            node_id: local,
            incarnation: 1,
            certificate_generation: certificate.generation,
            certificate_fingerprint: certificate.certificate_fingerprint,
            capability_digest: [140; 32],
            prior: meshspan_metadata::NodeCapabilityPrior::InitialAdmittedCertificate {
                revision: certificate.revision,
                generation: certificate.generation,
                certificate_fingerprint: certificate.certificate_fingerprint,
            },
        };
        submit_fixture(
            &mut runtime,
            AuthoritativeCommandContext::Node(node_context),
            AuthoritativeCommand::RefreshNodeCapabilities(refresh),
        )?;
        let expected = if support.is_some() {
            MetadataAuthorityRequestError::Unsupported
        } else {
            MetadataAuthorityRequestError::Unavailable
        };
        runtime.transport = Arc::new(FixtureTransferSupport(support));
        let before = runtime.driver.persistence().load_consensus_state(1)?.log;
        let (mut context, command) = large_target_command(local, 70 * 1024)?;
        context.expected_revision = Some(Revision::new(2));
        let (respond, mut response) = oneshot::channel();
        runtime.submit(AuthoritySubmission {
            context: AuthoritativeCommandContext::Principal(context),
            command,
            respond,
        })?;
        assert_eq!(response.try_recv()?, Err(expected));
        assert_eq!(
            runtime.driver.persistence().load_consensus_state(1)?.log,
            before
        );
        assert!(
            runtime
                .driver
                .persistence()
                .resolve_operation(context.operation_id)?
                .is_none()
        );
        assert!(runtime.pending.is_empty());
    }
    Ok(())
}

struct FixtureTransferSupport(Option<crate::ObservedConsensusTransferSupport>);
impl ConsensusMessageTransport for FixtureTransferSupport {
    fn send(&self, _to: NodeId, _message: CoreMessage) {}
    fn consensus_transfer_support_for(
        &self,
        _expected: meshspan_transport::PeerBinding,
        _digest: [u8; 32],
    ) -> Result<Option<crate::ObservedConsensusTransferSupport>, ConsensusNetworkError> {
        Ok(self.0.clone())
    }
}

fn submit_fixture(
    runtime: &mut MetadataAuthorityRuntime,
    context: AuthoritativeCommandContext,
    command: AuthoritativeCommand,
) -> Result<(), Box<dyn std::error::Error>> {
    let (respond, mut response) = oneshot::channel();
    runtime.submit(AuthoritySubmission {
        context,
        command,
        respond,
    })?;
    response.try_recv()??;
    Ok(())
}
