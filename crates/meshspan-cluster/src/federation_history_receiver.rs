// SPDX-License-Identifier: GPL-2.0-only

//! Admission-gated durable receiver boundary for authenticated federation history.

use std::future::Future;
use std::pin::Pin;

use meshspan_domain::UnixMicros;
use meshspan_filesystem::{
    NamespaceHistoryImmutableRecord, NamespaceHistoryMutationDecision, NamespaceHistoryPage,
    NamespaceHistoryReceiveCompletion, NamespaceHistoryReceiveRequest,
    NamespaceHistoryReceiveStatus, PublicationError, VersionPublicationStore,
};
use thiserror::Error;

use crate::FilesystemFederationHistorySource;
use crate::federation_history_admission::{
    FederationHistoryAdmissionError, FederationHistoryAdmissionSource,
    FederationMutationAdmissionCommitError, FederationMutationAdmissionCommitter,
    validate_admission_batch,
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

    /// Classifies and consensus-commits every signed mutation before importing exact decisions.
    fn complete(
        &self,
        session_id: [u8; 32],
        now: UnixMicros,
    ) -> FederationHistoryReceiveFuture<'_, NamespaceHistoryReceiveCompletion>;
}

/// Filesystem receiver composed with mandatory metadata admission and quarantine consensus.
pub struct AdmittingFederationHistoryReceiver<A, C> {
    filesystem: FilesystemFederationHistorySource,
    admission: A,
    committer: C,
}

impl<A, C> AdmittingFederationHistoryReceiver<A, C> {
    /// Constructs the federation receiver composition.
    #[must_use]
    pub const fn new(
        filesystem: FilesystemFederationHistorySource,
        admission: A,
        committer: C,
    ) -> Self {
        Self {
            filesystem,
            admission,
            committer,
        }
    }
}

impl<A, C> FederationHistoryReceiver for AdmittingFederationHistoryReceiver<A, C>
where
    A: FederationHistoryAdmissionSource,
    C: FederationMutationAdmissionCommitter,
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
            let admission_at = preparation.admission_at();
            let admission = self
                .admission
                .classify(session_id, preparation.commits().to_vec(), admission_at)
                .await?;
            validate_admission_batch(preparation.commits(), &admission, admission_at)?;
            let mut decisions = Vec::with_capacity(admission.commits().len());
            for commit in admission.commits() {
                let authoritative = self.committer.commit(*commit).await?;
                decisions.push(NamespaceHistoryMutationDecision::new(
                    commit.commit_id,
                    authoritative,
                    commit.acknowledgement.evidence.accepted_at(),
                ));
            }
            blocking(move || {
                let mut store = VersionPublicationStore::open(&state_directory, now)?;
                store.complete_federated_namespace_history_receive(session_id, &decisions, now)
            })
            .await
        })
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
    /// A mutation decision was not durably admitted or retained by consensus.
    #[error("federation history admission commit failed")]
    AdmissionCommit(#[from] FederationMutationAdmissionCommitError),
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use meshspan_domain::{
        BranchId, ContentManifestId, FederatedMutationAcknowledgement, FederatedMutationAdmission,
        FederatedMutationEvidence, FederatedPrincipal, FederationGrantId, FederationRelationshipId,
        FederationResourceScope, FileVersionId, MeshId, NamespaceCommitId, ObjectId,
        ObjectRevisionId, OperationId, PrincipalId, QuarantineReason, Rights, VolumeId,
    };
    use meshspan_filesystem::{
        FilePublication, ManifestPublication, NamespaceHistoryCommitRecord, NamespaceHistoryLimits,
        NamespaceLimits, NamespacePath, NamespacePublicationPath, RootFilePublication,
    };
    use meshspan_metadata::{ApplyDisposition, CommandReceipt, EntityReference, LogPosition};
    use tempfile::{TempDir, tempdir};

    use super::*;
    use crate::federation_history_admission::{
        ConsensusFederationMutationAdmissionCommitter, FederationAuthoritativeCommandOutcome,
        FederationAuthoritativeCommandResolveFuture, FederationAuthoritativeCommandSubmission,
        FederationAuthoritativeCommandSubmitError, FederationAuthoritativeCommandSubmitFuture,
        FederationAuthoritativeCommandSubmitter, FederationHistoryAdmissionBatch,
        FederationHistoryAdmissionFuture, FederationMutationAdmissionCommit,
        FederationMutationAdmissionCommitFuture, admission_submission,
    };

    #[tokio::test]
    async fn decision_must_commit_before_filesystem_import_and_retry_is_exact()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = staged_quarantine_receive()?;
        let allow = Arc::new(AtomicBool::new(false));
        let calls = Arc::new(AtomicUsize::new(0));
        let receiver = AdmittingFederationHistoryReceiver::new(
            FilesystemFederationHistorySource::new(fixture.target.path()),
            StaticAdmission(fixture.batch.clone()),
            GatedCommit {
                allow: Arc::clone(&allow),
                calls: Arc::clone(&calls),
            },
        );
        assert!(matches!(
            receiver.complete(fixture.session_id, fixture.now).await,
            Err(FederationHistoryReceiveError::AdmissionCommit(
                FederationMutationAdmissionCommitError::Unavailable
            ))
        ));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert!(!commit_exists(&fixture)?);

        allow.store(true, Ordering::SeqCst);
        assert_eq!(
            receiver
                .complete(fixture.session_id, UnixMicros::new(110))
                .await?
                .disposition,
            meshspan_filesystem::PublicationDisposition::Applied
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        assert!(commit_exists(&fixture)?);
        Ok(())
    }

    #[tokio::test]
    async fn committed_admission_wins_over_a_changed_retry_classification()
    -> Result<(), Box<dyn std::error::Error>> {
        let publication = publication()?;
        let acknowledgement = acknowledgement(&publication)?;
        let admitted = FederationMutationAdmissionCommit {
            commit_id: publication.namespace_commit_id,
            acknowledgement,
            admission: FederatedMutationAdmission::Admitted,
        };
        let administrator = PrincipalId::from_bytes([101; 16])?;
        let (submission, expected_kind, expected_id) =
            admission_submission(&admitted, administrator)?;
        let submits = Arc::new(AtomicUsize::new(0));
        let submitter = ResolvedAdmission {
            outcome: FederationAuthoritativeCommandOutcome {
                receipt: CommandReceipt {
                    disposition: ApplyDisposition::Applied,
                    operation_id: submission.context.operation_id,
                    request_digest: submission.command.request_digest(submission.context),
                    result_digest: [102; 32],
                    committed_revision: meshspan_domain::Revision::new(9),
                    committed_position: LogPosition { index: 10, term: 2 },
                    applied_position: LogPosition { index: 10, term: 2 },
                    entity: EntityReference {
                        kind: expected_kind,
                        id: expected_id,
                    },
                },
                admission: FederatedMutationAdmission::Admitted,
            },
            submits: Arc::clone(&submits),
        };
        let committer =
            ConsensusFederationMutationAdmissionCommitter::new(submitter, administrator);
        let changed_retry = FederationMutationAdmissionCommit {
            admission: FederatedMutationAdmission::Quarantined(QuarantineReason::Revoked),
            ..admitted
        };
        assert_eq!(
            committer.commit(changed_retry).await?,
            FederatedMutationAdmission::Admitted
        );
        assert_eq!(submits.load(Ordering::SeqCst), 0);
        Ok(())
    }

    #[tokio::test]
    async fn same_mutation_imports_idempotently_in_a_later_receive_session()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = staged_quarantine_receive()?;
        let allow = Arc::new(AtomicBool::new(true));
        let calls = Arc::new(AtomicUsize::new(0));
        let receiver = AdmittingFederationHistoryReceiver::new(
            FilesystemFederationHistorySource::new(fixture.target.path()),
            StaticAdmission(fixture.batch.clone()),
            GatedCommit {
                allow,
                calls: Arc::clone(&calls),
            },
        );
        receiver.complete(fixture.session_id, fixture.now).await?;

        let second_session = [103; 32];
        restage_imported_bundle(&fixture, second_session)?;
        assert_eq!(
            receiver
                .complete(second_session, UnixMicros::new(120))
                .await?
                .disposition,
            meshspan_filesystem::PublicationDisposition::Applied
        );
        assert_eq!(calls.load(Ordering::SeqCst), 2);
        Ok(())
    }

    #[test]
    fn admission_batch_rejects_every_omission_and_substitution()
    -> Result<(), Box<dyn std::error::Error>> {
        let fixture = staged_quarantine_receive()?;
        let record = fixture.record.clone();
        validate_admission_batch(
            std::slice::from_ref(&record),
            &fixture.batch,
            UnixMicros::new(50),
        )?;

        let invalid = [
            FederationHistoryAdmissionBatch::new(Vec::new()),
            FederationHistoryAdmissionBatch::new(vec![
                fixture.batch.commits()[0],
                fixture.batch.commits()[0],
            ]),
            substituted_commit(&fixture)?,
            substituted_acknowledgement(&fixture),
        ];
        for batch in invalid {
            assert!(matches!(
                validate_admission_batch(
                    std::slice::from_ref(&record),
                    &batch,
                    UnixMicros::new(50)
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
        let admission = FederatedMutationAdmission::Quarantined(QuarantineReason::Revoked);
        let commit = FederationMutationAdmissionCommit {
            commit_id: publication.namespace_commit_id,
            acknowledgement,
            admission,
        };
        Ok(StagedFixture {
            target,
            session_id,
            now,
            publication,
            record,
            batch: FederationHistoryAdmissionBatch::new(vec![commit]),
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

    fn restage_imported_bundle(
        fixture: &StagedFixture,
        session_id: [u8; 32],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let store = VersionPublicationStore::open(fixture.target.path(), fixture.now)?;
        let bundle = store.export_namespace_history(
            fixture.publication.file.volume_id,
            &[fixture.publication.namespace_commit_id],
            &[],
            NamespaceHistoryLimits::DEFAULT,
        )?;
        let record = bundle
            .commit_records()?
            .into_iter()
            .next()
            .ok_or("restaged commit is missing")?;
        let immutable = bundle.immutable_records()?;
        drop(store);
        stage_bundle(
            fixture.target.path(),
            &fixture.publication,
            session_id,
            &record,
            &immutable,
        )?;
        Ok(())
    }

    fn substituted_commit(
        fixture: &StagedFixture,
    ) -> Result<FederationHistoryAdmissionBatch, Box<dyn std::error::Error>> {
        let mut commit = fixture.batch.commits()[0];
        commit.commit_id = NamespaceCommitId::from_bytes([99; 16])?;
        Ok(FederationHistoryAdmissionBatch::new(vec![commit]))
    }

    fn substituted_acknowledgement(fixture: &StagedFixture) -> FederationHistoryAdmissionBatch {
        let mut commit = fixture.batch.commits()[0];
        commit.acknowledgement.signature[0] ^= 1;
        FederationHistoryAdmissionBatch::new(vec![commit])
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

    struct GatedCommit {
        allow: Arc<AtomicBool>,
        calls: Arc<AtomicUsize>,
    }

    struct ResolvedAdmission {
        outcome: FederationAuthoritativeCommandOutcome,
        submits: Arc<AtomicUsize>,
    }

    impl FederationAuthoritativeCommandSubmitter for ResolvedAdmission {
        fn resolve(
            &self,
            _operation_id: OperationId,
        ) -> FederationAuthoritativeCommandResolveFuture<'_> {
            let outcome = self.outcome;
            Box::pin(async move { Ok(Some(outcome)) })
        }

        fn submit(
            &self,
            _submission: FederationAuthoritativeCommandSubmission,
        ) -> FederationAuthoritativeCommandSubmitFuture<'_> {
            self.submits.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Err(FederationAuthoritativeCommandSubmitError::Rejected) })
        }
    }

    impl FederationMutationAdmissionCommitter for GatedCommit {
        fn commit(
            &self,
            admission: FederationMutationAdmissionCommit,
        ) -> FederationMutationAdmissionCommitFuture<'_> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            let allowed = self.allow.load(Ordering::SeqCst);
            Box::pin(async move {
                if allowed {
                    Ok(admission.admission)
                } else {
                    Err(FederationMutationAdmissionCommitError::Unavailable)
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
