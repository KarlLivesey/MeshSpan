// SPDX-License-Identifier: GPL-2.0-only

//! Independent wire client exercises the native dispatcher, not a test-side backup server.

use super::{RunningAuthority, TestResult};
use crate::federation_sessions::{FederationBackupTargets, NativeFederationSession};
use meshspan_contracts::{
    BackupDeleteRequest, BackupObjectIdentity, BackupObjectReference, BackupReadRequest,
    BackupVerifyRequest, ContractVersion, FederatedBackupRequest, FederatedBackupScope,
    RequestContext,
};
use meshspan_domain::{Clock, DurationMicros, OperationId, Revision};
use meshspan_protocol::v1::{
    DataFrame, ExecuteFederatedBackup, federated_backup_result::Outcome,
    federation_envelope::Message,
};
use meshspan_transport::{
    FederationExchangeContext, FederationLocalIdentity, FederationPeerRegistry,
    FederationReplayGuard, OutboundFederationBackupMessage, StreamKind, open_stream,
    receive_data_frame, receive_federation, send_data_frame, send_federation,
    signed_federation_backup_message,
};
use sha2::{Digest, Sha256};

#[path = "federation_backup_interruption_tests.rs"]
mod interruption;
#[path = "federation_backup_native_owner_tests.rs"]
mod native_owner;

pub(super) const PAYLOAD: &[u8] = b"opaque encrypted native backup bytes";

pub(super) struct Client<'a, 'identity> {
    session: &'a NativeFederationSession,
    identity: &'a FederationLocalIdentity<'identity>,
    peers: &'a FederationPeerRegistry,
    scope: FederatedBackupScope,
    consumer: &'a std::sync::Arc<crate::federation_sessions::FederationSessions>,
    nonce: u8,
}

impl<'a, 'identity> Client<'a, 'identity> {
    pub(super) fn new(
        session: &'a NativeFederationSession,
        identity: &'a FederationLocalIdentity<'identity>,
        peers: &'a FederationPeerRegistry,
        scope: FederatedBackupScope,
        consumer: &'a std::sync::Arc<crate::federation_sessions::FederationSessions>,
    ) -> Self {
        Self {
            session,
            identity,
            peers,
            scope,
            consumer,
            nonce: 150,
        }
    }

    pub(super) async fn verify(
        mut self,
        fixture: &RunningAuthority,
        consumer: &RunningAuthority,
        hosts: &super::super::SessionHosts,
        internal: super::relay::InternalConnection,
    ) -> TestResult<FederatedBackupScope> {
        let targets = &hosts.backup_targets;
        let host = &hosts.inviter;
        let (folder_path, target) = prepare_target(fixture, targets, self.scope)?;
        Box::pin(native_owner::verify(&mut self, fixture, host, internal)).await?;
        let object = BackupObjectIdentity {
            destination_id: meshspan_domain::BackupDestinationId::from_bytes([212; 16])?,
            backup_id: meshspan_domain::BackupId::from_bytes([215; 16])?,
            provider_generation: 1,
            byte_length: PAYLOAD.len() as u64,
            digest: Sha256::digest(PAYLOAD).into(),
        };
        let full = Box::pin(self.fill_first_allocation(object)).await?;
        let first_scope = self.scope;
        let second = super::super::authority(fixture)?
            .reader()
            .federation_storage_allocation(
                meshspan_domain::FederationStorageAllocationId::from_bytes([218; 16])?,
            )?
            .ok_or("second allocation")?;
        self.scope.allocation_id = second.allocation.allocation_id();
        self.scope.allocation_revision = second.revision;
        let route = super::routing::prepare(consumer, self.consumer, self.scope, object)?;
        self.scope = route.binding.scope;
        Box::pin(self.remove_filler(first_scope, full)).await?;
        interruption::assert_usage(fixture, self.scope, 0, object.byte_length)?;
        let store = FederatedBackupRequest::Store(meshspan_contracts::BackupStoreRequest {
            context: context(170)?,
            object,
        });
        let failed = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            self.control_during_stalled_upload(&store),
        )
        .await
        .map_err(|error| format!("control during stalled backup upload: {error}"))??;
        assert!(matches!(failed, Outcome::Rejection(error)
            if error.code == i32::from(meshspan_protocol::v1::ErrorCode::Unavailable)));
        interruption::assert_usage(fixture, self.scope, 0, object.byte_length)?;
        Box::pin(self.recover_lost_store_result(fixture, consumer, object)).await?;
        // A new attempt gets its own deadline after the independent lost-result proof;
        // the operation/object stay fixed, and the successful receipt is replayed exactly.
        let store = FederatedBackupRequest::Store(meshspan_contracts::BackupStoreRequest {
            context: context(170)?,
            object,
        });
        let stored = self
            .cycle(&store, PAYLOAD)
            .await
            .map_err(|error| format!("store backup after interruption proofs: {error}"))?;
        let Outcome::Stored(receipt) = &stored else {
            return Err("missing native stored receipt".into());
        };
        assert_eq!(receipt.operation_id, [170; 16]);
        let recorded = receipt.object.as_ref().ok_or("stored object")?;
        assert_eq!(recorded.backup_id, [215; 16]);
        assert_eq!(recorded.destination_id, [212; 16]);
        assert_eq!(recorded.provider_generation, 1);
        assert_eq!(recorded.byte_length, PAYLOAD.len() as u64);
        assert_eq!(recorded.digest, object.digest);
        assert_eq!(self.cycle(&store, PAYLOAD).await?, stored);
        // Retiring an idle target closes the cached catalogue. Bringing it back must
        // reopen the same physical namespace and recover its durable accounting/bytes.
        targets.replace(std::iter::empty())?;
        host.refresh_trust().await?;
        let physical = meshspan_contracts::federated_provider_backup_identity(self.scope, object)?;
        // An independent exclusive open proves the retired cache released its lock.
        drop(meshspan_backup::DirectoryBackupProvider::open(
            &folder_path,
            physical.destination_id,
            physical.provider_generation,
            i64::MAX.unsigned_abs(),
            crate::OperatingSystemClock.now(),
        )?);
        targets.replace([(&folder_path, &target)])?;
        let reference = BackupObjectReference::new(receipt.object_reference.clone())?;
        Box::pin(self.verify_retained_bytes(object, &reference)).await?;
        self.scope =
            super::renewal::verify(fixture, consumer, self.consumer, &route.binding, &reference)?;
        self.retire_and_assert_absence(object, reference).await?;
        let local = meshspan_metadata::LocalDatabase::open_existing(
            &fixture.directory.path().join("local.sqlite3"),
            crate::OperatingSystemClock.now(),
        )?;
        for allocation in [first_scope.allocation_id, self.scope.allocation_id] {
            let usage = local
                .federated_storage_usage(allocation)?
                .ok_or("allocation usage")?;
            assert_eq!((usage.committed_bytes, usage.reserved_bytes), (0, 0));
        }
        Ok(self.scope)
    }

    async fn verify_retained_bytes(
        &mut self,
        object: BackupObjectIdentity,
        reference: &BackupObjectReference,
    ) -> TestResult<()> {
        let read = self
            .cycle(
                &FederatedBackupRequest::Read(BackupReadRequest {
                    context: context(171)?,
                    object,
                    object_reference: reference.clone(),
                }),
                &[],
            )
            .await?;
        let Outcome::Read(read) = read else {
            return Err("missing native read receipt".into());
        };
        assert_eq!(read.byte_length, PAYLOAD.len() as u64);
        assert_eq!(read.digest, object.digest);
        let verified = self
            .cycle(
                &FederatedBackupRequest::Verify(BackupVerifyRequest {
                    context: context(172)?,
                    object,
                    object_reference: reference.clone(),
                }),
                &[],
            )
            .await?;
        let Outcome::Verified(verified) = verified else {
            return Err("missing native verification".into());
        };
        assert_eq!(verified.object_reference, reference.as_str());
        Box::pin(self.production_round_trip(object, reference.clone())).await?;
        Ok(())
    }

    async fn fill_first_allocation(
        &mut self,
        object: BackupObjectIdentity,
    ) -> TestResult<meshspan_contracts::BackupObjectReceipt> {
        let bytes = [42; 2048];
        let object = BackupObjectIdentity {
            backup_id: meshspan_domain::BackupId::from_bytes([219; 16])?,
            destination_id: meshspan_domain::BackupDestinationId::from_bytes([220; 16])?,
            byte_length: 2048,
            digest: Sha256::digest(bytes).into(),
            ..object
        };
        let request = FederatedBackupRequest::Store(meshspan_contracts::BackupStoreRequest {
            context: context(186)?,
            object,
        });
        let Outcome::Stored(receipt) = self.cycle(&request, &bytes).await? else {
            return Err("filler did not occupy first allocation".into());
        };
        assert_eq!(
            receipt.object.as_ref().ok_or("filler object")?.byte_length,
            2048
        );
        Ok(meshspan_contracts::BackupObjectReceipt {
            operation_id: request.context().operation_id,
            object,
            object_reference: BackupObjectReference::new(receipt.object_reference)?,
        })
    }

    async fn remove_filler(
        &self,
        scope: FederatedBackupScope,
        receipt: meshspan_contracts::BackupObjectReceipt,
    ) -> TestResult<()> {
        let mut client = meshspan_data_plane::FederatedBackupClient::new(
            &self.session.connection,
            self.identity,
            self.peers,
            self.session.limits.wire,
            &crate::OperatingSystemClock,
        )?;
        let result = client
            .execute(
                scope,
                &FederatedBackupRequest::Delete(BackupDeleteRequest {
                    context: context(187)?,
                    object: receipt.object,
                    object_reference: receipt.object_reference,
                    retirement_revision: Revision::new(1),
                }),
                meshspan_data_plane::FederatedBackupIo::None,
                &mut crate::OperatingSystemRandom,
            )
            .await?;
        assert!(matches!(
            result,
            meshspan_data_plane::FederatedBackupReceipt::Deleted(_)
        ));
        Ok(())
    }

    async fn retire_and_assert_absence(
        &mut self,
        object: BackupObjectIdentity,
        reference: BackupObjectReference,
    ) -> TestResult<()> {
        let deletion = FederatedBackupRequest::Delete(BackupDeleteRequest {
            context: context(173)?,
            object,
            object_reference: reference.clone(),
            retirement_revision: Revision::new(1),
        });
        let mut client = meshspan_data_plane::FederatedBackupClient::new(
            &self.session.connection,
            self.identity,
            self.peers,
            self.session.limits.wire,
            &crate::OperatingSystemClock,
        )?;
        let deleted = client
            .execute(
                self.scope,
                &deletion,
                meshspan_data_plane::FederatedBackupIo::None,
                &mut crate::OperatingSystemRandom,
            )
            .await?;
        let meshspan_data_plane::FederatedBackupReceipt::Deleted(deleted) = deleted else {
            return Err("missing production deletion receipt".into());
        };
        let deleted = Outcome::Deleted(meshspan_data_plane::encode_backup_delete_receipt(deleted));
        let Outcome::Deleted(receipt) = &deleted else {
            return Err("missing native deletion".into());
        };
        assert_eq!(receipt.retirement_revision, 1);
        assert_eq!(self.cycle(&deletion, &[]).await?, deleted);
        let absent = self
            .cycle(
                &FederatedBackupRequest::Verify(BackupVerifyRequest {
                    context: context(174)?,
                    object,
                    object_reference: reference,
                }),
                &[],
            )
            .await?;
        assert!(
            matches!(absent, Outcome::Rejection(error) if error.code == i32::from(meshspan_protocol::v1::ErrorCode::NotFound))
        );
        Ok(())
    }

    async fn production_round_trip(
        &self,
        object: BackupObjectIdentity,
        reference: BackupObjectReference,
    ) -> TestResult<()> {
        use meshspan_data_plane::{
            FederatedBackupClient, FederatedBackupIo, FederatedBackupReceipt,
        };
        let mut client = FederatedBackupClient::new(
            &self.session.connection,
            self.identity,
            self.peers,
            self.session.limits.wire,
            &crate::OperatingSystemClock,
        )?;
        let mut random = crate::OperatingSystemRandom;
        let store = FederatedBackupRequest::Store(meshspan_contracts::BackupStoreRequest {
            context: context(181)?,
            object,
        });
        let mut source = PAYLOAD;
        let stored = client
            .execute(
                self.scope,
                &store,
                FederatedBackupIo::Upload(&mut source),
                &mut random,
            )
            .await?;
        let FederatedBackupReceipt::Stored(stored) = stored else {
            return Err("production store".into());
        };
        assert_eq!(stored.object, object);
        assert_eq!(stored.operation_id.as_bytes(), [181; 16]);
        assert_eq!(stored.object_reference, reference);
        let request = FederatedBackupRequest::Read(BackupReadRequest {
            // HTTPS exports allow an hour overall, while each signed capability
            // and exchange must still obey the five-minute attempt bound.
            context: RequestContext {
                deadline: crate::OperatingSystemClock
                    .now()
                    .checked_add(DurationMicros::new(3_600_000_000))
                    .ok_or("export deadline")?,
                ..context(182)?
            },
            object,
            object_reference: reference.clone(),
        });
        let mut output = Vec::new();
        let read = client
            .execute(
                self.scope,
                &request,
                FederatedBackupIo::Download(&mut output),
                &mut random,
            )
            .await?;
        let FederatedBackupReceipt::Read(read) = read else {
            return Err("production read".into());
        };
        assert_eq!(output, PAYLOAD);
        assert_eq!(read.byte_length, PAYLOAD.len() as u64);
        assert_eq!(read.digest, object.digest);
        assert_eq!(read.operation_id.as_bytes(), [182; 16]);
        let request = FederatedBackupRequest::Verify(BackupVerifyRequest {
            context: context(183)?,
            object,
            object_reference: reference.clone(),
        });
        let verified = client
            .execute(self.scope, &request, FederatedBackupIo::None, &mut random)
            .await?;
        let FederatedBackupReceipt::Verified(verified) = verified else {
            return Err("production verify".into());
        };
        assert_eq!(verified.object, object);
        assert_eq!(verified.object_reference, reference);
        assert_eq!(verified.operation_id.as_bytes(), [183; 16]);
        Ok(())
    }

    async fn control_during_stalled_upload(
        &mut self,
        request: &FederatedBackupRequest,
    ) -> TestResult<Outcome> {
        let outbound = self.permit(request).await?;
        let limits = self.session.limits.wire;
        let (mut send, mut receive) =
            open_stream(&self.session.connection, StreamKind::Federation).await?;
        send_federation(&mut send, outbound.envelope(), limits).await?;
        let ready = receive_federation(&mut receive, limits).await?;
        let mut replay = replay()?;
        let ready = self.peers.authenticate_backup_response(
            &self.session.connection,
            &ready,
            &outbound.expectation()?,
            crate::OperatingSystemClock.now(),
            &mut replay,
        )?;
        let expected = ready.result_expectation()?;
        // The provider has admitted capacity and is waiting for data. A fresh signed
        // capability must still complete through the separate control metadata workers.
        self.permit(request).await?;
        send_data_frame(
            &mut send,
            &DataFrame {
                offset: 0,
                bytes: PAYLOAD[..5].to_vec(),
            },
            limits,
        )
        .await?;
        send.finish()?;
        let result = receive_federation(&mut receive, limits).await?;
        let result = self.peers.authenticate_backup_response(
            &self.session.connection,
            &result,
            &expected,
            crate::OperatingSystemClock.now(),
            &mut replay,
        )?;
        let Message::BackupResult(result) = result.message() else {
            return Err("missing short-upload result".into());
        };
        result
            .outcome
            .clone()
            .ok_or_else(|| "missing outcome".into())
    }

    async fn cycle(
        &mut self,
        request: &FederatedBackupRequest,
        source: &[u8],
    ) -> TestResult<Outcome> {
        let outbound = self.permit(request).await?;
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            self.execute(&outbound, request, source),
        )
        .await
        .map_err(|error| {
            format!(
                "native backup execution for operation {:?}: {error}",
                request.context().operation_id
            )
        })?
    }

    async fn permit(
        &mut self,
        request: &FederatedBackupRequest,
    ) -> TestResult<OutboundFederationBackupMessage> {
        let now = crate::OperatingSystemClock.now();
        let message = Message::RequestBackupCapability(
            meshspan_data_plane::encode_federated_backup_request(self.scope, request, now)?,
        );
        let outbound = self.sign(message, request)?;
        let response = super::exchange(self.session, outbound.envelope()).await??;
        let authenticated = self.peers.authenticate_backup_response(
            &self.session.connection,
            &response,
            &outbound.expectation()?,
            crate::OperatingSystemClock.now(),
            &mut replay()?,
        )?;
        let Message::BackupCapability(value) = authenticated.message() else {
            return Err("missing capability".into());
        };
        assert!(value.rejection.is_none());
        self.sign(
            Message::ExecuteBackup(ExecuteFederatedBackup {
                permit: Some(value.permit.clone().ok_or("permit")?),
                signature: Vec::new(),
            }),
            request,
        )
    }

    fn sign(
        &mut self,
        message: Message,
        request: &FederatedBackupRequest,
    ) -> TestResult<OutboundFederationBackupMessage> {
        let nonce = self.nonce;
        self.nonce = self.nonce.checked_add(1).ok_or("nonce exhausted")?;
        Ok(signed_federation_backup_message(
            self.identity,
            FederationExchangeContext::new(
                super::ProtocolVersion { major: 1, minor: 0 },
                request.context().operation_id.as_bytes(),
                request.context().operation_id.as_bytes(),
                [190; 16],
                request.context().deadline,
                [nonce; 32],
            )?,
            message,
            self.session.limits.wire,
            crate::OperatingSystemClock.now(),
        )?)
    }

    async fn execute(
        &self,
        outbound: &OutboundFederationBackupMessage,
        request: &FederatedBackupRequest,
        source: &[u8],
    ) -> TestResult<Outcome> {
        let limits = self.session.limits.wire;
        let connection = &self.session.connection;
        let (mut send, mut receive) = open_stream(connection, StreamKind::Federation).await?;
        send_federation(&mut send, outbound.envelope(), limits).await?;
        if !matches!(request, FederatedBackupRequest::Store(_)) {
            send.finish()?;
        }
        let mut replay = replay()?;
        let ready = receive_federation(&mut receive, limits).await?;
        let ready = self.peers.authenticate_backup_response(
            connection,
            &ready,
            &outbound.expectation()?,
            crate::OperatingSystemClock.now(),
            &mut replay,
        )?;
        let expected = ready.result_expectation()?;
        match request {
            FederatedBackupRequest::Store(_) => {
                for (index, bytes) in source.chunks(5).enumerate() {
                    send_data_frame(
                        &mut send,
                        &DataFrame {
                            offset: (index * 5) as u64,
                            bytes: bytes.to_vec(),
                        },
                        limits,
                    )
                    .await?;
                }
                send.finish()?;
            }
            FederatedBackupRequest::Read(_) => {
                let mut bytes = Vec::new();
                while bytes.len() < PAYLOAD.len() {
                    let frame = receive_data_frame(&mut receive, limits).await?.into_inner();
                    assert_eq!(frame.offset, bytes.len() as u64);
                    bytes.extend_from_slice(&frame.bytes);
                }
                assert_eq!(bytes, PAYLOAD);
            }
            FederatedBackupRequest::Lookup(_)
            | FederatedBackupRequest::Verify(_)
            | FederatedBackupRequest::Delete(_) => {}
        }
        let result = receive_federation(&mut receive, limits).await?;
        let result = self.peers.authenticate_backup_response(
            connection,
            &result,
            &expected,
            crate::OperatingSystemClock.now(),
            &mut replay,
        )?;
        let Message::BackupResult(result) = result.message() else {
            return Err("missing native result".into());
        };
        result
            .outcome
            .clone()
            .ok_or_else(|| "missing outcome".into())
    }
}

fn context(marker: u8) -> TestResult<RequestContext> {
    Ok(RequestContext {
        contract_version: ContractVersion::V1_0,
        operation_id: OperationId::from_bytes([marker; 16])?,
        expected_revision: Some(Revision::new(1)),
        deadline: crate::OperatingSystemClock
            .now()
            .checked_add(DurationMicros::new(5_000_000))
            .ok_or("deadline")?,
    })
}

fn replay() -> TestResult<FederationReplayGuard> {
    Ok(FederationReplayGuard::new(
        64,
        DurationMicros::new(30_000_000),
    )?)
}

fn prepare_target(
    fixture: &RunningAuthority,
    targets: &FederationBackupTargets,
    scope: FederatedBackupScope,
) -> TestResult<(std::path::PathBuf, crate::NativeStorageTarget)> {
    use meshspan_storage::{
        CapacityPolicy, FolderRegistration, FolderShardStore, RegisteredFolder,
        SharedStorageProvider, StoragePermitVerifier, UsageLimit,
    };
    let now = crate::OperatingSystemClock.now();
    meshspan_metadata::LocalDatabase::open(
        &fixture.directory.path().join("local.sqlite3"),
        fixture.node_id,
        now,
    )?;
    let folder_path = fixture.directory.path().join("native-backup-folder");
    std::fs::create_dir(&folder_path)?;
    let limit = UsageLimit::Bytes(4096);
    let folder = RegisteredFolder::register_new(
        &folder_path,
        FolderRegistration {
            mesh_id: scope.provider_mesh_id,
            target_id: scope.target_id,
            generation: 1,
            usage_limit: limit,
        },
        &mut crate::OperatingSystemRandom,
    )?;
    let provider = SharedStorageProvider::new(FolderShardStore::open(
        folder,
        &fixture.directory.path().join("native-target-state"),
        CapacityPolicy {
            usage_limit: limit,
            repair_reserve_bytes: 0,
            revision: Revision::new(1),
        },
        StoragePermitVerifier::new(
            scope.provider_mesh_id,
            1,
            Revision::new(1),
            meshspan_contracts::StoragePermitMacKey::from_bytes([42; 32])?,
        )?,
        now,
        &mut crate::OperatingSystemRandom,
    )?);
    let target = crate::NativeStorageTarget::new(
        meshspan_metadata::StorageTargetProviderContext {
            mesh_id: scope.provider_mesh_id,
            node_id: fixture.node_id,
            target_id: scope.target_id,
            generation: 1,
            usage_limit: meshspan_metadata::StorageUsageLimit::Bytes(4096),
            policy_revision: Revision::new(1),
            catalogue_revision: scope.allocation_revision,
        },
        provider,
    );
    targets.replace([(&folder_path, &target)])?;
    Ok((folder_path, target))
}
