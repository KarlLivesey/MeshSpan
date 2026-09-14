// SPDX-License-Identifier: GPL-2.0-only

//! Real consumer consensus fixes a route without inventing a stored backup copy.

use super::{RunningAuthority, TestResult};
use crate::backup_publication::evidence::{PublicationStep, provider_context};
use meshspan_contracts::{BackupObjectIdentity, FederatedBackupScope};
use meshspan_domain::{DurationMicros, PartitionId, Revision};
use meshspan_metadata::{
    AuthoritativeCommand, AuthoritativeRepository, BindFederatedBackupRoute,
    FederatedBackupRouteRecord, PartitionDatabase,
};

pub(super) fn prepare(
    consumer: &RunningAuthority,
    sessions: &std::sync::Arc<crate::federation_sessions::FederationSessions>,
    scope: FederatedBackupScope,
    object: BackupObjectIdentity,
) -> TestResult<FederatedBackupRouteRecord> {
    let authority = super::super::authority(consumer)?;
    let claim = provision(consumer, &authority, scope, object)?;
    let destination = authority
        .reader()
        .backup_destination(object.destination_id)?
        .ok_or("destination")?;
    let value = BindFederatedBackupRoute {
        object,
        scope,
        claim,
        expected_destination_revision: destination.revision,
    };
    let command = AuthoritativeCommand::BindFederatedBackupRoute(value);
    let context = super::context_for(consumer, 236)?;
    verify_command_encoding(context, &command)?;
    assert!(
        authority
            .reader()
            .federated_backup_route(object.backup_id, object.destination_id)?
            .is_none()
    );
    for invalid in [
        BindFederatedBackupRoute {
            claim: meshspan_metadata::MetadataBackupRunClaim { fence: 2, ..claim },
            ..value
        },
        BindFederatedBackupRoute {
            expected_destination_revision: Revision::new(destination.revision.get() + 1),
            ..value
        },
    ] {
        assert!(
            authority
                .commit_authoritative(
                    super::context_for(consumer, 237)?,
                    &AuthoritativeCommand::BindFederatedBackupRoute(invalid)
                )
                .is_err()
        );
    }
    select_route(consumer, sessions, &authority, &destination, &value)?;
    let selected = authority
        .reader()
        .federated_backup_route(object.backup_id, object.destination_id)?
        .ok_or("automatically selected route")?;
    assert_eq!(selected.binding, value);
    let receipt = authority.commit_authoritative(context, &command)?;
    assert_eq!(
        receipt.entity.kind,
        meshspan_metadata::EntityKind::FederatedBackupRoute
    );
    let reopened = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &consumer.directory.path().join("partition.sqlite3"),
        crate::api_http::current_time().ok_or("clock")?,
    )?);
    let stored = reopened
        .federated_backup_route(object.backup_id, object.destination_id)?
        .ok_or("route after reopen")?;
    assert_eq!(stored.binding, value);
    assert_eq!(stored.revision, selected.revision);
    assert!(stored.revision < receipt.committed_revision);
    assert!(reopened.metadata_backup(object.backup_id)?.is_none());
    assert!(
        reopened
            .backup_copy(object.backup_id, object.destination_id)?
            .is_none()
    );
    let replay = authority.commit_authoritative(context, &command)?;
    assert_eq!(replay.committed_revision, receipt.committed_revision);
    let mut changed = value;
    changed.scope.allocation_id =
        meshspan_domain::FederationStorageAllocationId::from_bytes([211; 16])?;
    assert!(
        authority
            .commit_authoritative(
                super::context_for(consumer, 238)?,
                &AuthoritativeCommand::BindFederatedBackupRoute(changed)
            )
            .is_err()
    );
    changed = value;
    changed.object.digest = [199; 32];
    assert!(
        authority
            .commit_authoritative(
                super::context_for(consumer, 239)?,
                &AuthoritativeCommand::BindFederatedBackupRoute(changed)
            )
            .is_err()
    );
    assert_eq!(
        reopened.federated_backup_route(object.backup_id, object.destination_id)?,
        Some(stored)
    );
    Ok(stored)
}

fn verify_command_encoding(
    context: meshspan_metadata::CommandContext,
    command: &AuthoritativeCommand,
) -> TestResult<()> {
    let encoded = meshspan_metadata::encode_authoritative_command(context, command)?;
    let decoded = meshspan_metadata::decode_authoritative_command(&encoded)?;
    assert_eq!(&decoded.command, command);
    assert_eq!(decoded.context, context);
    let mut trailing = encoded;
    trailing.push(0);
    assert!(meshspan_metadata::decode_authoritative_command(&trailing).is_err());
    Ok(())
}

fn select_route(
    consumer: &RunningAuthority,
    sessions: &std::sync::Arc<crate::federation_sessions::FederationSessions>,
    authority: &crate::ConsensusAuthenticationAuthority,
    destination: &meshspan_metadata::BackupDestinationRecord,
    expected: &BindFederatedBackupRoute,
) -> TestResult<()> {
    use meshspan_domain::Clock;
    tokio::task::block_in_place(|| {
        let handle = crate::federation_sessions::FederationBackupConsumer::default();
        handle.attach(sessions)?;
        let now = crate::OperatingSystemClock.now();
        let source = consumer.directory.path().join("not-published-yet.msb");
        let request = crate::BackupPublicationRequest {
            encrypted_source: &source,
            evidence: meshspan_backup::BackupFileEvidence {
                source: meshspan_backup::BackupSourceManifest {
                    backup_id: expected.object.backup_id,
                    partition_id: PartitionId::from_bytes([2; 16])?,
                    mesh_id: expected.scope.remote_mesh_id,
                    last_log_index: 1,
                    last_log_term: 1,
                    state_revision: 1,
                    schema_version: 97,
                    byte_length: 1024,
                    digest: [17; 32],
                    created_at: now,
                },
                byte_length: expected.object.byte_length,
                digest: expected.object.digest,
            },
            destination_id: expected.object.destination_id,
            claim: expected.claim,
            actor_principal_id: consumer.administrator_id,
            now,
            deadline: now
                .checked_add(DurationMicros::new(5_000_000))
                .ok_or("selection deadline")?,
        };
        assert_capacity_refusal(&handle, authority, destination, &request)?;
        let mut provider = handle.prepare_publication(
            destination,
            &request,
            authority,
            &tokio::runtime::Handle::current(),
        )?;
        let first = authority
            .reader()
            .federated_backup_route(expected.object.backup_id, expected.object.destination_id)?;
        handle.prepare_publication(
            destination,
            &request,
            authority,
            &tokio::runtime::Handle::current(),
        )?;
        assert_eq!(
            authority.reader().federated_backup_route(
                expected.object.backup_id,
                expected.object.destination_id
            )?,
            first
        );
        assert!(
            !source.exists(),
            "route selection unexpectedly wrote a backup source"
        );
        // Fail the source after admission and durable route commitment. The replacement
        // consumer must reuse this route, not mistake missing acknowledgement for absence.
        let interrupted = provider.store_exact(
            meshspan_contracts::BackupStoreRequest {
                context: provider_context(
                    PublicationStep::StoreProvider,
                    request.evidence,
                    request.destination_id,
                    request.now,
                    request.deadline,
                    destination.revision,
                )?,
                object: expected.object,
            },
            &mut std::io::Cursor::new(&super::execution::PAYLOAD[..5]),
            crate::OperatingSystemClock.now(),
        );
        assert_eq!(
            interrupted,
            Err(meshspan_contracts::ContractError::InternalContract)
        );
        Ok(())
    })
}

fn assert_capacity_refusal(
    handle: &crate::federation_sessions::FederationBackupConsumer,
    authority: &crate::ConsensusAuthenticationAuthority,
    destination: &meshspan_metadata::BackupDestinationRecord,
    request: &crate::BackupPublicationRequest<'_>,
) -> TestResult<()> {
    let too_large = crate::BackupPublicationRequest {
        evidence: meshspan_backup::BackupFileEvidence {
            byte_length: 8192,
            ..request.evidence
        },
        ..*request
    };
    assert!(matches!(
        handle.prepare_publication(
            destination,
            &too_large,
            authority,
            &tokio::runtime::Handle::current()
        ),
        Err(crate::BackupPublicationError::Provider(
            meshspan_contracts::ContractError::ResourceExhausted
        ))
    ));
    assert!(
        authority
            .reader()
            .federated_backup_route(request.evidence.source.backup_id, request.destination_id)?
            .is_none()
    );
    Ok(())
}

pub(super) fn lookup_provider(
    consumer: &RunningAuthority,
    sessions: &std::sync::Arc<crate::federation_sessions::FederationSessions>,
    object: BackupObjectIdentity,
    operation: u8,
) -> TestResult<meshspan_contracts::BackupObjectReceipt> {
    use meshspan_contracts::{BackupLookupRequest, ContractVersion, RequestContext};
    use meshspan_domain::{Clock, OperationId};
    tokio::task::block_in_place(|| {
        let authority = super::super::authority(consumer)?;
        let destination = authority
            .reader()
            .backup_destination(object.destination_id)?
            .ok_or("consumer destination")?;
        let handle = crate::federation_sessions::FederationBackupConsumer::default();
        handle.attach(sessions)?;
        let provider = handle.resolve(&destination, tokio::runtime::Handle::current())?;
        let now = crate::OperatingSystemClock.now();
        let request = BackupLookupRequest {
            context: RequestContext {
                contract_version: ContractVersion::V1_0,
                operation_id: OperationId::from_bytes([operation; 16])?,
                expected_revision: Some(Revision::new(1)),
                deadline: now
                    .checked_add(DurationMicros::new(5_000_000))
                    .ok_or("lookup deadline")?,
            },
            object,
        };
        let receipt = provider.lookup_exact(&request, now)?;
        assert_eq!(receipt.object, object);
        assert_eq!(receipt.operation_id, request.context.operation_id);
        Ok(receipt)
    })
}

pub(super) fn verify_provider(
    consumer: &RunningAuthority,
    sessions: &std::sync::Arc<crate::federation_sessions::FederationSessions>,
    object: BackupObjectIdentity,
    reference: &meshspan_contracts::BackupObjectReference,
    first_operation: u8,
) -> TestResult<()> {
    use meshspan_contracts::{
        BackupReadRequest, BackupStoreRequest, BackupVerifyRequest, ContractVersion, RequestContext,
    };
    use meshspan_domain::Clock;
    tokio::task::block_in_place(|| {
        let payload = super::execution::PAYLOAD;
        let authority = super::super::authority(consumer)?;
        let destination = authority
            .reader()
            .backup_destination(object.destination_id)?
            .ok_or("consumer destination")?;
        let handle = crate::federation_sessions::FederationBackupConsumer::default();
        assert!(
            handle
                .resolve(&destination, tokio::runtime::Handle::current())
                .is_err()
        );
        handle.attach(sessions)?;
        assert!(handle.attach(sessions).is_err());
        let mut provider = handle.resolve(&destination, tokio::runtime::Handle::current())?;
        let now = crate::OperatingSystemClock.now();
        let context = RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id: meshspan_domain::OperationId::from_bytes([first_operation; 16])?,
            expected_revision: Some(Revision::new(1)),
            deadline: now
                .checked_add(DurationMicros::new(5_000_000))
                .ok_or("deadline")?,
        };
        let stored = provider.store_exact(
            BackupStoreRequest { context, object },
            &mut std::io::Cursor::new(payload),
            now,
        )?;
        assert_eq!(stored.object, object);
        assert_eq!(stored.object_reference, *reference);
        assert_eq!(stored.operation_id, context.operation_id);
        let mut output = Vec::new();
        let read = provider.read_exact(
            &BackupReadRequest {
                context: RequestContext {
                    operation_id: meshspan_domain::OperationId::from_bytes(
                        [first_operation.checked_add(1).ok_or("read operation")?; 16],
                    )?,
                    ..context
                },
                object,
                object_reference: reference.clone(),
            },
            &mut output,
            now,
        )?;
        assert_eq!(output, payload);
        assert_eq!(read.byte_length, payload.len() as u64);
        assert_eq!(read.digest, object.digest);
        let request = BackupVerifyRequest {
            context: RequestContext {
                operation_id: meshspan_domain::OperationId::from_bytes(
                    [first_operation.checked_add(2).ok_or("verify operation")?; 16],
                )?,
                ..context
            },
            object,
            object_reference: reference.clone(),
        };
        let verified = provider.verify_exact(&request, now)?;
        assert_eq!(verified.object, object);
        assert_eq!(verified.object_reference, *reference);
        let changed = BackupVerifyRequest {
            object: BackupObjectIdentity {
                digest: [199; 32],
                ..object
            },
            ..request
        };
        assert!(provider.verify_exact(&changed, now).is_err());
        Ok(())
    })
}

fn provision(
    consumer: &RunningAuthority,
    authority: &crate::ConsensusAuthenticationAuthority,
    scope: FederatedBackupScope,
    object: BackupObjectIdentity,
) -> TestResult<meshspan_metadata::MetadataBackupRunClaim> {
    use meshspan_metadata::{
        BackupDestinationBinding, BackupFailureRelationship, ClaimMetadataBackupRun,
        ConfigureBackupDestination, ConfigureMetadataBackupSchedule, MetadataBackupRunClaim,
        QueueMetadataBackupRun, RecordName,
    };
    let now = crate::api_http::current_time().ok_or("clock")?;
    let partition_id = PartitionId::from_bytes([2; 16])?;
    let sequence = authority
        .reader()
        .metadata_backup_schedule()?
        .map_or(0, |schedule| schedule.sequence);
    let claim = MetadataBackupRunClaim {
        claim_generation: 1,
        worker_node_id: consumer.node_id,
        worker_incarnation: 1,
        fence: 1,
    };
    let commands = [
        AuthoritativeCommand::ConfigureBackupDestination(ConfigureBackupDestination {
            destination_id: object.destination_id,
            expected_destination_revision: Revision::new(0),
            name: RecordName::new("Partner backups")?,
            binding: BackupDestinationBinding::FederatedMesh {
                remote_mesh_id: scope.provider_mesh_id,
                provider_generation: object.provider_generation,
            },
            failure_relationship: BackupFailureRelationship::Unknown,
            failure_evidence_digest: [0; 32],
            enabled: true,
        }),
        AuthoritativeCommand::ConfigureMetadataBackupSchedule(ConfigureMetadataBackupSchedule {
            partition_id,
            expected_schedule_sequence: sequence,
            interval: DurationMicros::new(86_400_000_000),
            retained_generations: 3,
            minimum_verified_copies: 1,
            minimum_independent_copies: 0,
            enabled: true,
            next_due_at: now,
        }),
        AuthoritativeCommand::QueueMetadataBackupRun(QueueMetadataBackupRun {
            backup_id: object.backup_id,
            partition_id,
            expected_schedule_sequence: sequence + 1,
            scheduled_for: now,
        }),
        AuthoritativeCommand::ClaimMetadataBackupRun(ClaimMetadataBackupRun {
            backup_id: object.backup_id,
            claim,
            lease_expires_at: now
                .checked_add(DurationMicros::new(60_000_000))
                .ok_or("lease")?,
        }),
    ];
    for (index, command) in commands.iter().enumerate() {
        let mut context = super::context_for(consumer, 230 + u8::try_from(index)?)?;
        // Schedule creation and its initial due instant use the same logical observation.
        context.occurred_at = now;
        authority
            .commit_authoritative(context, command)
            .map_err(|error| format!("backup-route fixture command {index}: {error}"))?;
    }
    Ok(claim)
}
