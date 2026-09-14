// SPDX-License-Identifier: GPL-2.0-only

//! Committed cleanup through actual recovered daemons, not a replacement provider service.

use super::super::{self as harness, ProcessCleanup};
use super::{Error, ProcessFixture, StorageIoClient, prepare};
use meshspan_cluster::ConsensusPeerConfig;
use meshspan_contracts::{ReclamationReceipt, ShardReadPermit, TombstoneReceipt, read_permit_mac};
use meshspan_daemon::OperatingSystemClock;
use meshspan_domain::{
    AuditEventId, Clock as _, NodeId, OperationId, PrincipalId, RandomSource as _, Revision,
    VolumeId,
};
use meshspan_metadata::{
    AuthoritativeCommand, AuthoritativeRepository, CommandContext, CommandReceipt,
    LocalTargetRecord, PageLimit, PartitionDatabase, PrincipalKind,
};
use meshspan_protocol::v1::{ErrorCode, OperationOutcome};

#[path = "recovery_cleanup_authority.rs"]
mod authority;

pub(crate) async fn prove_committed_cleanup(
    original: &ProcessFixture,
    gateway: &ProcessFixture,
    storage: &ProcessFixture,
    target: &LocalTargetRecord,
    storage_process: &mut std::process::Child,
) -> Result<(), Box<dyn Error>> {
    let peer = ProcessFixture::new()?;
    let (key, volume) = harness::recovery_live_file::original_credentials(original)?;
    let https = harness::wait_for_client(&gateway.identity_path).await?;
    let grant = harness::issue_join_code(gateway, &https, &key).await?;
    let mut processes = ProcessCleanup(vec![peer.start_join(&grant)?]);
    let proof = async {
        let peer_https = harness::wait_for_client(&peer.identity_path).await?;
        harness::wait_for_status(peer.address, &peer_https, "configured").await?;
        let directory = peer.state_path.clone();
        let destination = storage.private_address;
        let target = target.clone();
        let runtime = tokio::runtime::Handle::current();
        let io = tokio::task::spawn_blocking(move || {
            prepare(&directory, destination, &target, &runtime).map_err(|error| error.to_string())
        })
        .await??;
        let client = CleanupClient::new(io, gateway, VolumeId::parse(&volume.replace('-', ""))?)?;
        let result = async {
            client.wait_for_routes().await?;
            let cleanup = authority::prepare_cleanup(&client).await?;
            let receipt = client.remove(cleanup, storage, storage_process).await?;
            harness::recovery_runtime::restart(storage, storage_process).await?;
            assert_eq!(
                client.reclaim(receipt.tombstone).await?,
                receipt,
                "restart changed reclamation receipt"
            );
            harness::recovery_live_file::verify(original, gateway).await?;
            harness::recovery_live_file::verify_new_files(original, gateway).await
        }
        .await;
        let closed = client.io.network.close();
        result?;
        closed?;
        Ok::<_, Box<dyn Error>>(())
    }
    .await;
    harness::stop_processes(&mut processes.0);
    harness::retain_failure_state(proof, [peer.temporary])
}

struct CleanupClient {
    io: StorageIoClient,
    repository: AuthoritativeRepository,
    repository_path: std::path::PathBuf,
    leader: NodeId,
    administrator: PrincipalId,
    volume: VolumeId,
}

impl CleanupClient {
    fn new(
        io: StorageIoClient,
        gateway: &ProcessFixture,
        volume: VolumeId,
    ) -> Result<Self, Box<dyn Error>> {
        let repository = AuthoritativeRepository::new(PartitionDatabase::open_existing(
            &gateway.state_path.join("root-authority.sqlite3"),
            OperatingSystemClock.now(),
        )?);
        // Recovery installs the authorised replacement identity; it need not be key-derived.
        let leader = meshspan_metadata::LocalDatabase::open_existing(
            &gateway.state_path.join("local.sqlite3"),
            OperatingSystemClock.now(),
        )?
        .node_id();
        let certificate = repository
            .active_node_certificate(leader)?
            .ok_or("leader certificate missing")?;
        io.network.upsert_peer(&ConsensusPeerConfig {
            node_id: leader,
            incarnation: certificate.incarnation,
            address: gateway.private_address,
            certificate_der: certificate.certificate_der,
            certificate_name: super::name(leader),
        })?;
        let principals = repository.principals(PrincipalKind::User, None, PageLimit::new(10)?)?;
        let mut administrator = None;
        for principal in principals.items {
            if repository
                .principal_is_system_manager(principal.principal_id, OperatingSystemClock.now())?
            {
                administrator = Some(principal.principal_id);
                break;
            }
        }
        let administrator = administrator.ok_or("fixture administrator missing")?;
        Ok(Self {
            io,
            repository,
            repository_path: gateway.state_path.join("root-authority.sqlite3"),
            leader,
            administrator,
            volume,
        })
    }

    async fn wait_for_routes(&self) -> Result<(), Box<dyn Error>> {
        let deadline = tokio::time::Instant::now() + harness::WAIT_LIMIT;
        loop {
            let failure = match self.io.network.probe_peer(self.leader).await {
                Ok(()) => match self.read_original_shard().await {
                    Ok(()) => return Ok(()),
                    Err(error) => format!("storage read: {error}"),
                },
                Err(error) => format!("leader probe: {error:?}"),
            };
            if tokio::time::Instant::now() >= deadline {
                return Err(format!("cleanup client routes unavailable: {failure}").into());
            }
            tokio::time::sleep(harness::RETRY_INTERVAL).await;
        }
    }

    /// A hello proves peer routing, not provider reopening after membership changes.
    async fn read_original_shard(&self) -> Result<(), Box<dyn Error>> {
        let connection = self
            .io
            .network
            .connect_data_peer(self.io.destination)
            .await
            .map_err(|error| format!("connect storage peer: {error:?}"))?;
        let expires_at = meshspan_domain::UnixMicros::new(
            OperatingSystemClock
                .now()
                .get()
                .checked_add(30_000_000)
                .ok_or("clock overflow")?,
        );
        let mut permit = ShardReadPermit {
            operation_id: OperationId::from_bytes(random_id()?)?,
            mesh_id: self.io.write.mesh_id,
            target_id: self.io.write.target_id,
            target_generation: self.io.write.target_generation,
            shard: self.io.write.shard,
            authorization_revision: self.repository.current_revision()?,
            expires_at,
            permit_digest: [0; 32],
        };
        permit.permit_digest = read_permit_mac(&self.io.key, permit);
        let header = self
            .io
            .network
            .control_header(permit.operation_id, expires_at.get())?;
        let bytes = meshspan_data_plane::get_shard(
            &connection,
            header,
            permit,
            8192,
            self.io.network.wire_limits(),
        )
        .await
        .map_err(|error| format!("read source shard: {error:?}"))?;
        if bytes.as_slice() != [0x52; 8192] {
            return Err("cleanup source shard bytes changed".into());
        }
        Ok(())
    }

    /// Rebuild only after definite rejection; unknown transport outcomes never become retries.
    async fn commit(
        &self,
        build: impl Fn(
            &AuthoritativeRepository,
            Revision,
        ) -> Result<AuthoritativeCommand, Box<dyn Error>>,
    ) -> Result<CommandReceipt, Box<dyn Error>> {
        let deadline = tokio::time::Instant::now() + harness::WAIT_LIMIT;
        loop {
            let (revision, command) = self.repository.with_read_view(|repo| {
                let revision = repo.current_revision()?;
                Ok::<_, Box<dyn Error>>((revision, build(repo, revision)?))
            })??;
            let context = CommandContext {
                operation_id: OperationId::from_bytes(random_id()?)?,
                actor_principal_id: self.administrator,
                audit_event_id: AuditEventId::from_bytes(random_id()?)?,
                occurred_at: OperatingSystemClock.now(),
                expected_revision: Some(revision),
            };
            let result = harness::recovery_storage_control::submit(
                &self.io.network,
                self.leader,
                context,
                &command,
            )
            .await?;
            // The authority currently maps preflight StaleRevision to Rejected/Invalid.
            // Confirm a newer revision and absence of this operation before rebuilding;
            // never retry a durable, indeterminate or unchanged-state rejection.
            let changed_revision_rejection = result.outcome
                == i32::from(OperationOutcome::Rejected)
                && result
                    .error
                    .as_ref()
                    .is_some_and(|error| error.code == i32::from(ErrorCode::Invalid))
                && result.committed_revision.is_none()
                && result.result_digest.is_empty()
                && self.repository.current_revision()? > revision
                && self
                    .repository
                    .resolve_operation(context.operation_id)?
                    .is_none();
            if (result.outcome == i32::from(OperationOutcome::Stale) || changed_revision_rejection)
                && tokio::time::Instant::now() < deadline
            {
                continue;
            }
            if result.outcome != i32::from(OperationOutcome::Durable) {
                return Err(self
                    .rejection_detail(context, command, &result)
                    .await?
                    .into());
            }
            let receipt = self
                .repository
                .resolve_operation(context.operation_id)?
                .ok_or("committed command missing")?;
            assert_eq!(receipt.request_digest, command.request_digest(context));
            assert_eq!(result.result_digest, receipt.result_digest);
            return Ok(receipt);
        }
    }

    /// Inspect the same typed validation after rejection; this transaction always rolls back.
    /// Return an error rather than panic so the enclosing fixture retains its evidence.
    async fn rejection_detail(
        &self,
        context: CommandContext,
        command: AuthoritativeCommand,
        result: &meshspan_protocol::v1::OperationResult,
    ) -> Result<String, Box<dyn Error>> {
        let bytes = meshspan_metadata::encode_authoritative_command(context, &command)?;
        // The context always carries an expected revision: its fixed header occupies 69 bytes.
        let tag = u16::from_be_bytes(bytes.get(69..71).ok_or("command tag missing")?.try_into()?);
        let directory = self.repository_path.clone();
        let detail = tokio::task::spawn_blocking(move || {
            let database = PartitionDatabase::open_existing(&directory, OperatingSystemClock.now())
                .map_err(|error| error.to_string())?;
            let mut repository = AuthoritativeRepository::new(database);
            let revision = repository
                .current_revision()
                .map_err(|error| error.to_string())?;
            let validation = repository.preflight_command(&[], context, &command);
            Ok::<_, String>(format!(
                "current revision {revision:?}; rolled-back validation {validation:?}"
            ))
        })
        .await??;
        Ok(format!(
            "cleanup command kind {tag}, expected revision {:?}: {result:?}; {detail}",
            context.expected_revision
        ))
    }

    async fn remove(
        &self,
        cleanup: OperationId,
        storage: &ProcessFixture,
        process: &mut std::process::Child,
    ) -> Result<ReclamationReceipt, Box<dyn Error>> {
        let permit = self
            .repository
            .version_cleanup_permit_attempt(cleanup, 0)?
            .ok_or("permit missing")?;
        let connection = self
            .io
            .network
            .connect_data_peer(self.io.destination)
            .await?;
        let header = self
            .io
            .network
            .control_header(permit.permit.operation_id, permit.permit.expires_at.get())?;
        let tombstone = meshspan_data_plane::tombstone_shard(
            &connection,
            header.clone(),
            permit.permit,
            self.io.network.wire_limits(),
        )
        .await
        .map_err(|error| format!("initial tombstone: {error:?}"))?;
        assert_eq!(tombstone.shard, self.io.write.shard);
        assert_eq!(
            tombstone.tombstone_digest,
            meshspan_contracts::tombstone_receipt_digest(permit.permit)
        );
        // Lose the storage process before its receipt is committed to metadata.
        // Recovery must resolve the same permit, not create a second deletion.
        drop(connection);
        harness::recovery_runtime::restart(storage, process).await?;
        let connection = self
            .io
            .network
            .connect_data_peer(self.io.destination)
            .await?;
        assert_eq!(
            meshspan_data_plane::tombstone_shard(
                &connection,
                header,
                permit.permit,
                self.io.network.wire_limits()
            )
            .await
            .map_err(|error| format!("tombstone replay: {error:?}"))?,
            tombstone
        );
        let premature = self.reclaim(tombstone).await;
        assert!(
            matches!(premature, Err(ref error) if matches!(error.downcast_ref::<meshspan_data_plane::DataPlaneError>(), Some(meshspan_data_plane::DataPlaneError::Remote(ErrorCode::Unauthorised)))),
            "reclamation preceded committed completion: {premature:?}"
        );
        let inventory = self
            .repository
            .version_cleanup_inventory(cleanup)?
            .ok_or("inventory missing")?;
        let sealed = inventory.sealed_revision.ok_or("inventory unsealed")?;
        self.commit(|repository, _| {
            let reporter = repository
                .active_node_certificate(self.io.destination)?
                .ok_or("storage certificate missing")?;
            Ok(meshspan_cluster::version_cleanup_tombstone_completion(
                sealed,
                permit,
                tombstone,
                self.io.destination,
                reporter.incarnation,
            )?)
        })
        .await?;
        let receipt = self.reclaim(tombstone).await?;
        assert_eq!(receipt.reclaimed_bytes, 8192);
        // Bytes are gone but accounting is not committed: retry must recover the exact receipt.
        harness::recovery_runtime::restart(storage, process).await?;
        assert_eq!(self.reclaim(tombstone).await?, receipt);
        self.commit(|repository, _| {
            let completion = repository
                .version_cleanup_item_completion(cleanup, 0)?
                .ok_or("completion missing")?;
            let reporter = repository
                .active_node_certificate(self.io.destination)?
                .ok_or("storage certificate missing")?;
            Ok(meshspan_cluster::version_cleanup_reclamation(
                completion,
                receipt,
                self.io.destination,
                reporter.incarnation,
            )?)
        })
        .await?;
        let recorded = self
            .repository
            .version_cleanup_reclamation(cleanup)?
            .ok_or("reclamation missing")?;
        assert_eq!(recorded.reclaimed_item_count, 1);
        assert_eq!(recorded.reclaimed_bytes, 8192);
        Ok(receipt)
    }

    async fn reclaim(
        &self,
        tombstone: TombstoneReceipt,
    ) -> Result<ReclamationReceipt, Box<dyn Error>> {
        let connection = self
            .io
            .network
            .connect_data_peer(self.io.destination)
            .await?;
        let deadline = OperatingSystemClock
            .now()
            .get()
            .checked_add(30_000_000)
            .ok_or("clock overflow")?;
        let header = self
            .io
            .network
            .control_header(tombstone.operation_id, deadline)?;
        Ok(meshspan_data_plane::reclaim_shard(
            &connection,
            header,
            tombstone,
            self.io.network.wire_limits(),
        )
        .await?)
    }
}

fn random_id() -> Result<[u8; 16], Box<dyn Error>> {
    let mut bytes = [0; 16];
    meshspan_daemon::OperatingSystemRandom.fill_bytes(&mut bytes)?;
    Ok(bytes)
}
