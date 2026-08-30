// SPDX-License-Identifier: GPL-2.0-only

//! Admission-gated durable receiver boundary for authenticated federation history.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use meshspan_domain::{
    FederatedMutationAcknowledgement, FederatedMutationAdmission, NamespaceCommitId, PartitionId,
    QuarantineReason, UnixMicros,
};
use meshspan_filesystem::{
    NamespaceHistoryCommitRecord, NamespaceHistoryImmutableRecord,
    NamespaceHistoryMutationDecision, NamespaceHistoryPage, NamespaceHistoryReceiveCompletion,
    NamespaceHistoryReceiveRequest, NamespaceHistoryReceiveStatus, PublicationError,
    VersionPublicationStore,
};
use meshspan_metadata::{AuthoritativeRepository, MetadataStoreError, PartitionDatabase};
use thiserror::Error;

use crate::{
    FederatedHistoryMutationAdmissionError, FilesystemFederationHistorySource,
    classify_federated_history_mutation,
};

/// Owned future returned by a receiver which may dispatch blocking persistence work.
pub type FederationHistoryReceiveFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, FederationHistoryReceiveError>> + Send + 'a>>;

/// Persistence boundary required by the federation history convergence driver.
pub trait FederationHistoryReceiver: Send + Sync {
    /// Starts or resumes an exact durable receive transaction.
    fn begin(
        &self,
        request: NamespaceHistoryReceiveRequest,
    ) -> FederationHistoryReceiveFuture<'_, NamespaceHistoryReceiveStatus>;

    /// Persists one exact sequential authenticated page.
    fn accept_page(
        &self,
        session_id: [u8; 32],
        input_cursor: Vec<u8>,
        page: NamespaceHistoryPage,
        now: UnixMicros,
    ) -> FederationHistoryReceiveFuture<'_, NamespaceHistoryReceiveStatus>;

    /// Persists one independently authenticated advertised body.
    fn accept_object(
        &self,
        session_id: [u8; 32],
        record: NamespaceHistoryImmutableRecord,
        now: UnixMicros,
    ) -> FederationHistoryReceiveFuture<'_, NamespaceHistoryReceiveStatus>;

    /// Classifies every signed mutation, commits quarantine first, then imports exact decisions.
    fn complete(
        &self,
        session_id: [u8; 32],
        now: UnixMicros,
    ) -> FederationHistoryReceiveFuture<'_, NamespaceHistoryReceiveCompletion>;
}

/// Complete owner-side classifications and mandatory quarantine work for one receive session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationHistoryAdmissionBatch {
    decisions: Vec<NamespaceHistoryMutationDecision>,
    quarantines: Vec<FederationQuarantineRetention>,
}

impl FederationHistoryAdmissionBatch {
    /// Exact immutable decisions supplied to the filesystem transaction.
    #[must_use]
    pub fn decisions(&self) -> &[NamespaceHistoryMutationDecision] {
        &self.decisions
    }

    /// Authentic quarantined mutations which must commit before filesystem completion.
    #[must_use]
    pub fn quarantines(&self) -> &[FederationQuarantineRetention] {
        &self.quarantines
    }

    /// Constructs a batch only for admission sources which validated every exact record.
    #[must_use]
    pub fn new(
        decisions: Vec<NamespaceHistoryMutationDecision>,
        quarantines: Vec<FederationQuarantineRetention>,
    ) -> Self {
        Self {
            decisions,
            quarantines,
        }
    }
}

/// One authentic inadmissible mutation requiring replicated metadata retention.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationQuarantineRetention {
    /// Receiver session providing idempotency scope to the consensus committer.
    pub session_id: [u8; 32],
    /// Exact immutable commit retained by the filesystem transaction.
    pub commit_id: NamespaceCommitId,
    /// Signed remote acceptance proof reclassified by the owner.
    pub acknowledgement: FederatedMutationAcknowledgement,
    /// Owner classification; metadata must independently derive the same reason.
    pub reason: QuarantineReason,
    /// Authoritative mesh time used for classification and command submission.
    pub retained_at: UnixMicros,
}

/// Asynchronous authority which verifies every signed mutation against replicated metadata.
pub trait FederationHistoryAdmissionSource: Send + Sync {
    /// Returns one decision per record and quarantine work for every rejected decision.
    fn classify(
        &self,
        session_id: [u8; 32],
        records: Vec<NamespaceHistoryCommitRecord>,
        now: UnixMicros,
    ) -> FederationHistoryAdmissionFuture<'_>;
}

/// Owned future for one bounded metadata classification batch.
pub type FederationHistoryAdmissionFuture<'a> = Pin<
    Box<
        dyn Future<
                Output = Result<FederationHistoryAdmissionBatch, FederationHistoryAdmissionError>,
            > + Send
            + 'a,
    >,
>;

/// Consensus boundary which confirms exact quarantine retention before returning.
pub trait FederationQuarantineCommitter: Send + Sync {
    /// Idempotently commits one quarantine record and verifies its durable committed receipt.
    fn retain(
        &self,
        retention: FederationQuarantineRetention,
    ) -> FederationQuarantineCommitFuture<'_>;
}

/// Owned future for one replicated quarantine commit.
pub type FederationQuarantineCommitFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), FederationQuarantineCommitError>> + Send + 'a>>;

/// Filesystem receiver composed with mandatory metadata admission and quarantine consensus.
pub struct AdmittingFederationHistoryReceiver<A, Q> {
    filesystem: FilesystemFederationHistorySource,
    admission: A,
    quarantine: Q,
}

impl<A, Q> AdmittingFederationHistoryReceiver<A, Q> {
    /// Constructs the federation receiver composition.
    #[must_use]
    pub const fn new(
        filesystem: FilesystemFederationHistorySource,
        admission: A,
        quarantine: Q,
    ) -> Self {
        Self {
            filesystem,
            admission,
            quarantine,
        }
    }
}

impl<A, Q> FederationHistoryReceiver for AdmittingFederationHistoryReceiver<A, Q>
where
    A: FederationHistoryAdmissionSource,
    Q: FederationQuarantineCommitter,
{
    fn begin(
        &self,
        request: NamespaceHistoryReceiveRequest,
    ) -> FederationHistoryReceiveFuture<'_, NamespaceHistoryReceiveStatus> {
        let state_directory = self.filesystem.state_directory().to_owned();
        blocking(move || {
            let mut store = VersionPublicationStore::open(&state_directory, request.now)?;
            store.begin_namespace_history_receive(&request)
        })
    }

    fn accept_page(
        &self,
        session_id: [u8; 32],
        input_cursor: Vec<u8>,
        page: NamespaceHistoryPage,
        now: UnixMicros,
    ) -> FederationHistoryReceiveFuture<'_, NamespaceHistoryReceiveStatus> {
        let state_directory = self.filesystem.state_directory().to_owned();
        blocking(move || {
            let mut store = VersionPublicationStore::open(&state_directory, now)?;
            store.receive_namespace_history_page(session_id, &input_cursor, &page, now)
        })
    }

    fn accept_object(
        &self,
        session_id: [u8; 32],
        record: NamespaceHistoryImmutableRecord,
        now: UnixMicros,
    ) -> FederationHistoryReceiveFuture<'_, NamespaceHistoryReceiveStatus> {
        let state_directory = self.filesystem.state_directory().to_owned();
        blocking(move || {
            let mut store = VersionPublicationStore::open(&state_directory, now)?;
            store.receive_namespace_history_object(session_id, &record, now)
        })
    }

    fn complete(
        &self,
        session_id: [u8; 32],
        now: UnixMicros,
    ) -> FederationHistoryReceiveFuture<'_, NamespaceHistoryReceiveCompletion> {
        Box::pin(async move {
            let state_directory = self.filesystem.state_directory().to_owned();
            let preparation_directory = state_directory.clone();
            let preparation = blocking(move || {
                let store = VersionPublicationStore::open(&preparation_directory, now)?;
                store.prepare_namespace_history_receive(session_id, now)
            })
            .await?;
            let admission = self
                .admission
                .classify(session_id, preparation.commits().to_vec(), now)
                .await?;
            validate_admission_batch(session_id, preparation.commits(), &admission, now)?;
            for retention in admission.quarantines() {
                self.quarantine.retain(*retention).await?;
            }
            let decisions = admission.decisions().to_vec();
            blocking(move || {
                let mut store = VersionPublicationStore::open(&state_directory, now)?;
                store.complete_federated_namespace_history_receive(session_id, &decisions, now)
            })
            .await
        })
    }
}

/// Opens one authoritative metadata partition per batch on a blocking worker.
#[derive(Clone, Debug)]
pub struct MetadataFederationHistoryAdmissionSource {
    database_path: PathBuf,
    partition_id: PartitionId,
}

impl MetadataFederationHistoryAdmissionSource {
    /// Selects the authoritative partition database and its immutable identity.
    #[must_use]
    pub fn new(database_path: impl Into<PathBuf>, partition_id: PartitionId) -> Self {
        Self {
            database_path: database_path.into(),
            partition_id,
        }
    }
}

impl FederationHistoryAdmissionSource for MetadataFederationHistoryAdmissionSource {
    fn classify(
        &self,
        session_id: [u8; 32],
        records: Vec<NamespaceHistoryCommitRecord>,
        now: UnixMicros,
    ) -> FederationHistoryAdmissionFuture<'_> {
        let database_path = self.database_path.clone();
        let partition_id = self.partition_id;
        Box::pin(async move {
            tokio::task::spawn_blocking(move || {
                let database = PartitionDatabase::open(&database_path, partition_id, now)?;
                classify_records(
                    &AuthoritativeRepository::new(database),
                    session_id,
                    &records,
                    now,
                )
            })
            .await
            .map_err(|_| FederationHistoryAdmissionError::Unavailable)?
        })
    }
}

fn classify_records(
    repository: &AuthoritativeRepository,
    session_id: [u8; 32],
    records: &[NamespaceHistoryCommitRecord],
    now: UnixMicros,
) -> Result<FederationHistoryAdmissionBatch, FederationHistoryAdmissionError> {
    let mut decisions = Vec::with_capacity(records.len());
    let mut quarantines = Vec::new();
    for record in records {
        let acknowledgement = record
            .federated_acknowledgement()?
            .ok_or(FederationHistoryAdmissionError::MissingAcknowledgement)?;
        let classified =
            classify_federated_history_mutation(repository, record, &acknowledgement, now)?;
        let admission = classified.admission();
        decisions.push(NamespaceHistoryMutationDecision::new(
            classified.commit_id(),
            admission,
            now,
        ));
        if let FederatedMutationAdmission::Quarantined(reason) = admission {
            quarantines.push(FederationQuarantineRetention {
                session_id,
                commit_id: classified.commit_id(),
                acknowledgement,
                reason,
                retained_at: now,
            });
        }
    }
    Ok(FederationHistoryAdmissionBatch::new(decisions, quarantines))
}

fn validate_admission_batch(
    session_id: [u8; 32],
    records: &[NamespaceHistoryCommitRecord],
    batch: &FederationHistoryAdmissionBatch,
    now: UnixMicros,
) -> Result<(), FederationHistoryAdmissionError> {
    let mut expected = BTreeMap::new();
    for record in records {
        let authority = record.mutation_authority()?;
        let acknowledgement = record
            .federated_acknowledgement()?
            .ok_or(FederationHistoryAdmissionError::MissingAcknowledgement)?;
        if expected
            .insert(
                authority.commit_id(),
                (authority.created_at(), acknowledgement),
            )
            .is_some()
        {
            return Err(FederationHistoryAdmissionError::InvalidBatch);
        }
    }
    if expected.len() != batch.decisions.len() {
        return Err(FederationHistoryAdmissionError::InvalidBatch);
    }
    let mut decisions = BTreeMap::new();
    for decision in &batch.decisions {
        let Some((created_at, _)) = expected.get(&decision.commit_id()) else {
            return Err(FederationHistoryAdmissionError::InvalidBatch);
        };
        if decision.classified_at() != now
            || decision.classified_at() < *created_at
            || decisions
                .insert(decision.commit_id(), decision.admission())
                .is_some()
        {
            return Err(FederationHistoryAdmissionError::InvalidBatch);
        }
    }
    let mut quarantines = BTreeMap::new();
    for retention in &batch.quarantines {
        let Some((_, acknowledgement)) = expected.get(&retention.commit_id) else {
            return Err(FederationHistoryAdmissionError::InvalidBatch);
        };
        if retention.session_id != session_id
            || retention.retained_at != now
            || retention.acknowledgement != *acknowledgement
            || decisions.get(&retention.commit_id)
                != Some(&FederatedMutationAdmission::Quarantined(retention.reason))
            || quarantines
                .insert(retention.commit_id, retention.reason)
                .is_some()
        {
            return Err(FederationHistoryAdmissionError::InvalidBatch);
        }
    }
    let expected_quarantines = decisions
        .values()
        .filter(|admission| matches!(admission, FederatedMutationAdmission::Quarantined(_)))
        .count();
    if quarantines.len() == expected_quarantines {
        Ok(())
    } else {
        Err(FederationHistoryAdmissionError::InvalidBatch)
    }
}

fn blocking<T: Send + 'static>(
    operation: impl FnOnce() -> Result<T, PublicationError> + Send + 'static,
) -> FederationHistoryReceiveFuture<'static, T> {
    Box::pin(async move {
        tokio::task::spawn_blocking(operation)
            .await
            .map_err(|_| FederationHistoryReceiveError::Unavailable)?
            .map_err(Into::into)
    })
}

/// Closed failures while classifying one complete signed history batch.
#[derive(Debug, Error)]
pub enum FederationHistoryAdmissionError {
    /// The blocking authority worker exited without a result.
    #[error("federation history admission authority is unavailable")]
    Unavailable,
    /// A remote record lacked the mandatory signed accepting-swarm acknowledgement.
    #[error("federated history mutation has no acceptance acknowledgement")]
    MissingAcknowledgement,
    /// An admission source omitted, duplicated or substituted a decision or quarantine item.
    #[error("federation history admission batch is inconsistent")]
    InvalidBatch,
    /// A canonical history record was malformed.
    #[error("federated history mutation record is invalid")]
    Record(#[from] meshspan_filesystem::NamespaceHistoryRecordError),
    /// The metadata partition could not be opened or verified.
    #[error("federation admission metadata is unavailable")]
    Metadata(#[from] MetadataStoreError),
    /// Signed mutation binding or authoritative classification failed closed.
    #[error("federation mutation admission failed")]
    Admission(#[from] FederatedHistoryMutationAdmissionError),
}

/// Closed failures from replicated quarantine retention.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum FederationQuarantineCommitError {
    /// No authoritative consensus leader could confirm retention.
    #[error("federation quarantine consensus is unavailable")]
    Unavailable,
    /// Consensus or the authoritative state machine rejected the exact retention request.
    #[error("federation quarantine retention was rejected")]
    Rejected,
}

/// Closed failures from receiver persistence, admission, quarantine or blocking workers.
#[derive(Debug, Error)]
pub enum FederationHistoryReceiveError {
    /// A blocking persistence worker exited without a result.
    #[error("federation history receiver is unavailable")]
    Unavailable,
    /// The durable filesystem receiver rejected or could not persist the transaction.
    #[error("federation history receiver rejected the transaction")]
    Publication(#[from] PublicationError),
    /// Metadata could not authoritatively classify every signed mutation.
    #[error("federation history admission failed")]
    Admission(#[from] FederationHistoryAdmissionError),
    /// A quarantined mutation was not durably retained by consensus.
    #[error("federation history quarantine retention failed")]
    Quarantine(#[from] FederationQuarantineCommitError),
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use meshspan_domain::{
        BranchId, ContentManifestId, FederatedMutationEvidence, FederatedPrincipal,
        FederationGrantId, FederationRelationshipId, FederationResourceScope, FileVersionId,
        MeshId, ObjectId, ObjectRevisionId, OperationId, PrincipalId, Rights, VolumeId,
    };
    use meshspan_filesystem::{
        FilePublication, ManifestPublication, NamespaceHistoryLimits, NamespaceLimits,
        NamespacePath, NamespacePublicationPath, RootFilePublication,
    };
    use tempfile::{TempDir, tempdir};

    use super::*;

    #[tokio::test]
    async fn quarantine_must_commit_before_filesystem_import_and_retry_is_exact()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = staged_quarantine_receive()?;
        let allow = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicUsize::new(0));
        let receiver = AdmittingFederationHistoryReceiver::new(
            FilesystemFederationHistorySource::new(fixture.target.path()),
            StaticAdmission(fixture.batch.clone()),
            GatedQuarantine {
                allow: Arc::clone(&allow),
                calls: Arc::clone(&calls),
            },
        );
        assert!(matches!(
            receiver.complete(fixture.session_id, fixture.now).await,
            Err(FederationHistoryReceiveError::Quarantine(
                FederationQuarantineCommitError::Unavailable
            ))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(!commit_exists(&fixture)?);

        allow.store(true, Ordering::SeqCst);
        assert_eq!(
            receiver
                .complete(fixture.session_id, fixture.now)
                .await?
                .disposition,
            meshspan_filesystem::PublicationDisposition::Applied
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(commit_exists(&fixture)?);
        Ok(())
    }

    #[test]
    fn admission_batch_rejects_every_omission_and_substitution()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = staged_quarantine_receive()?;
        let record = fixture.record.clone();
        validate_admission_batch(
            fixture.session_id,
            std::slice::from_ref(&record),
            &fixture.batch,
            fixture.now,
        )?;

        let invalid = [
            FederationHistoryAdmissionBatch::new(fixture.batch.decisions.clone(), Vec::new()),
            FederationHistoryAdmissionBatch::new(Vec::new(), fixture.batch.quarantines.clone()),
            substituted_session(&fixture),
            substituted_acknowledgement(&fixture),
            substituted_admission(&fixture),
        ];
        for batch in invalid {
            assert!(matches!(
                validate_admission_batch(
                    fixture.session_id,
                    std::slice::from_ref(&record),
                    &batch,
                    fixture.now
                ),
                Err(FederationHistoryAdmissionError::InvalidBatch)
            ));
        }
        Ok(())
    }

    struct StagedFixture {
        target: TempDir,
        session_id: [u8; 32],
        now: UnixMicros,
        publication: RootFilePublication,
        record: NamespaceHistoryCommitRecord,
        batch: FederationHistoryAdmissionBatch,
    }

    fn staged_quarantine_receive() -> Result<StagedFixture, Box<dyn std::error::Error>> {
        let source_directory = tempdir()?;
        let target = tempdir()?;
        let publication = publication()?;
        let acknowledgement = acknowledgement(&publication)?;
        let mut source =
            VersionPublicationStore::open(source_directory.path(), UnixMicros::new(1))?;
        source.publish_federated_root_file(&publication, &acknowledgement)?;
        let bundle = source.export_namespace_history(
            publication.file.volume_id,
            &[publication.namespace_commit_id],
            &[],
            NamespaceHistoryLimits::DEFAULT,
        )?;
        let record = bundle.commit_records()?.remove(0);
        let immutable = bundle.immutable_records()?;
        let session_id = [80; 32];
        let now = UnixMicros::new(100);
        stage_bundle(target.path(), &publication, session_id, &record, &immutable)?;
        let decision = NamespaceHistoryMutationDecision::new(
            publication.namespace_commit_id,
            FederatedMutationAdmission::Quarantined(QuarantineReason::Revoked),
            now,
        );
        let retention = FederationQuarantineRetention {
            session_id,
            commit_id: publication.namespace_commit_id,
            acknowledgement,
            reason: QuarantineReason::Revoked,
            retained_at: now,
        };
        Ok(StagedFixture {
            target,
            session_id,
            now,
            publication,
            record,
            batch: FederationHistoryAdmissionBatch::new(vec![decision], vec![retention]),
        })
    }

    fn stage_bundle(
        target: &std::path::Path,
        publication: &RootFilePublication,
        session_id: [u8; 32],
        record: &NamespaceHistoryCommitRecord,
        immutable: &[NamespaceHistoryImmutableRecord],
    ) -> Result<(), PublicationError> {
        let mut store = VersionPublicationStore::open(target, UnixMicros::new(1))?;
        store.begin_namespace_history_receive(&NamespaceHistoryReceiveRequest {
            session_id,
            scope_binding: [81; 32],
            volume_id: publication.file.volume_id,
            requested_heads: vec![publication.namespace_commit_id],
            limits: NamespaceHistoryLimits::DEFAULT,
            now: UnixMicros::new(50),
            expires_at: UnixMicros::new(200),
        })?;
        store.receive_namespace_history_page(
            session_id,
            &[],
            &NamespaceHistoryPage {
                export_token: [82; 32],
                commits: vec![record.clone()],
                immutable_object_digests: immutable
                    .iter()
                    .map(NamespaceHistoryImmutableRecord::digest)
                    .collect(),
                next_cursor: Vec::new(),
            },
            UnixMicros::new(60),
        )?;
        for immutable_record in immutable {
            store.receive_namespace_history_object(
                session_id,
                immutable_record,
                UnixMicros::new(70),
            )?;
        }
        Ok(())
    }

    fn commit_exists(fixture: &StagedFixture) -> Result<bool, PublicationError> {
        let store = VersionPublicationStore::open(fixture.target.path(), fixture.now)?;
        Ok(store
            .export_namespace_history(
                fixture.publication.file.volume_id,
                &[fixture.publication.namespace_commit_id],
                &[],
                NamespaceHistoryLimits::DEFAULT,
            )
            .is_ok())
    }

    fn substituted_session(fixture: &StagedFixture) -> FederationHistoryAdmissionBatch {
        let mut retention = fixture.batch.quarantines[0];
        retention.session_id[0] ^= 1;
        FederationHistoryAdmissionBatch::new(fixture.batch.decisions.clone(), vec![retention])
    }

    fn substituted_acknowledgement(fixture: &StagedFixture) -> FederationHistoryAdmissionBatch {
        let mut retention = fixture.batch.quarantines[0];
        retention.acknowledgement.signature[0] ^= 1;
        FederationHistoryAdmissionBatch::new(fixture.batch.decisions.clone(), vec![retention])
    }

    fn substituted_admission(fixture: &StagedFixture) -> FederationHistoryAdmissionBatch {
        let decision = NamespaceHistoryMutationDecision::new(
            fixture.publication.namespace_commit_id,
            FederatedMutationAdmission::Admitted,
            fixture.now,
        );
        FederationHistoryAdmissionBatch::new(vec![decision], fixture.batch.quarantines.clone())
    }

    #[derive(Clone)]
    struct StaticAdmission(FederationHistoryAdmissionBatch);

    impl FederationHistoryAdmissionSource for StaticAdmission {
        fn classify(
            &self,
            _session_id: [u8; 32],
            _records: Vec<NamespaceHistoryCommitRecord>,
            _now: UnixMicros,
        ) -> FederationHistoryAdmissionFuture<'_> {
            let batch = self.0.clone();
            Box::pin(async move { Ok(batch) })
        }
    }

    struct GatedQuarantine {
        allow: Arc<AtomicBool>,
        calls: Arc<AtomicUsize>,
    }

    impl FederationQuarantineCommitter for GatedQuarantine {
        fn retain(
            &self,
            _retention: FederationQuarantineRetention,
        ) -> FederationQuarantineCommitFuture<'_> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let allowed = self.allow.load(Ordering::SeqCst);
            Box::pin(async move {
                if allowed {
                    Ok(())
                } else {
                    Err(FederationQuarantineCommitError::Unavailable)
                }
            })
        }
    }

    fn acknowledgement(
        publication: &RootFilePublication,
    ) -> Result<FederatedMutationAcknowledgement, Box<dyn std::error::Error>> {
        Ok(FederatedMutationAcknowledgement {
            source_operation_id: publication.file.operation_id,
            evidence: FederatedMutationEvidence::new(
                FederationGrantId::from_bytes([40; 16])?,
                FederationRelationshipId::from_bytes([41; 16])?,
                FederatedPrincipal::new(MeshId::from_bytes([42; 16])?, publication.file.created_by),
                FederationResourceScope::Volume {
                    owner_mesh_id: MeshId::from_bytes([43; 16])?,
                    volume_id: publication.file.volume_id,
                },
                1,
                publication.file.created_at,
                Rights::TRAVERSE
                    .union(Rights::CREATE_CHILD)
                    .union(Rights::WRITE_DATA),
                0,
            ),
            payload_digest: VersionPublicationStore::root_file_federated_mutation_digest(
                publication,
            )?,
            signer_generation: 1,
            signature: [44; 64],
        })
    }

    fn publication() -> Result<RootFilePublication, Box<dyn std::error::Error>> {
        Ok(RootFilePublication {
            file: FilePublication {
                operation_id: OperationId::from_bytes([20; 16])?,
                branch_id: BranchId::from_bytes([21; 16])?,
                volume_id: VolumeId::from_bytes([22; 16])?,
                object_id: ObjectId::from_bytes([23; 16])?,
                expected_current_version_id: None,
                version_id: FileVersionId::from_bytes([24; 16])?,
                parent_version_id: None,
                retain_superseded_history: true,
                retention_policy_sequence: 1,
                manifest: ManifestPublication {
                    manifest_id: ContentManifestId::from_bytes([25; 16])?,
                    format_version: 1,
                    logical_length: 4,
                    content_digest: [26; 32],
                    root_digest: [27; 32],
                },
                created_by: PrincipalId::from_bytes([28; 16])?,
                created_at: UnixMicros::new(20),
            },
            root_object_id: ObjectId::from_bytes([29; 16])?,
            expected_namespace_commit_id: None,
            expected_file_object_revision_id: None,
            file_object_revision_id: ObjectRevisionId::from_bytes([30; 16])?,
            root_object_revision_id: ObjectRevisionId::from_bytes([31; 16])?,
            namespace_commit_id: NamespaceCommitId::from_bytes([32; 16])?,
            path: NamespacePublicationPath::new(
                NamespacePath::from_components(["report"], NamespaceLimits::PORTABLE)?,
                Vec::new(),
            )?,
            entry_generation: 1,
        })
    }
}
