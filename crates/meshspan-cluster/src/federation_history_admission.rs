// SPDX-License-Identifier: GPL-2.0-only

//! Authoritative classification and consensus receipt boundary for federated history.

use std::collections::BTreeMap;
use std::future::Future;
use std::path::PathBuf;
use std::pin::Pin;

use meshspan_domain::{
    AuditEventId, FederatedMutationAcknowledgement, FederatedMutationAdmission, NamespaceCommitId,
    OperationId, PartitionId, PrincipalId, QuarantineId, UnixMicros,
};
use meshspan_filesystem::NamespaceHistoryCommitRecord;
use meshspan_metadata::{
    AdmitFederatedMutation, AuthoritativeCommand, AuthoritativeRepository, CommandContext,
    CommandReceipt, EntityKind, MetadataStoreError, PartitionDatabase,
    RetainFederatedMutationQuarantine,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::{FederatedHistoryMutationAdmissionError, classify_federated_history_mutation};

/// Complete owner-side classifications and mandatory consensus work for one receive session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationHistoryAdmissionBatch {
    commits: Vec<FederationMutationAdmissionCommit>,
}

impl FederationHistoryAdmissionBatch {
    /// Authentic mutations which must commit their exact owner classification before import.
    #[must_use]
    pub fn commits(&self) -> &[FederationMutationAdmissionCommit] {
        &self.commits
    }

    /// Constructs a batch only for admission sources which validated every exact record.
    #[must_use]
    pub fn new(commits: Vec<FederationMutationAdmissionCommit>) -> Self {
        Self { commits }
    }
}

/// One authentic mutation requiring a consensus-ordered owner classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationMutationAdmissionCommit {
    /// Exact immutable commit gated by the owner decision.
    pub commit_id: NamespaceCommitId,
    /// Signed accepting-swarm proof reclassified by the owner state machine.
    pub acknowledgement: FederatedMutationAcknowledgement,
    /// Proposed decision; the committed state machine must independently derive the same result.
    pub admission: FederatedMutationAdmission,
}

/// Asynchronous authority which verifies every signed mutation against replicated metadata.
pub trait FederationHistoryAdmissionSource: Send + Sync {
    /// Returns one exact proposed classification per validated record.
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

/// Consensus boundary which confirms an exact admission or quarantine decision before returning.
pub trait FederationMutationAdmissionCommitter: Send + Sync {
    /// Idempotently commits one decision and verifies its durable applied receipt.
    fn commit(
        &self,
        admission: FederationMutationAdmissionCommit,
    ) -> FederationMutationAdmissionCommitFuture<'_>;
}

/// Owned future for one replicated admission decision.
pub type FederationMutationAdmissionCommitFuture<'a> = Pin<
    Box<
        dyn Future<
                Output = Result<FederatedMutationAdmission, FederationMutationAdmissionCommitError>,
            > + Send
            + 'a,
    >,
>;

/// Exact state-machine submission which must pass through the owning partition's consensus log.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FederationAuthoritativeCommandSubmission {
    /// Stable idempotency, actor and event context proposed with the command.
    pub context: CommandContext,
    /// Closed command which reclassifies the mutation at its committed log position.
    pub command: AuthoritativeCommand,
}

/// Immutable authoritative admission outcome read with its consensus-applied receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FederationAuthoritativeCommandOutcome {
    /// Exact durable operation receipt.
    pub receipt: CommandReceipt,
    /// Admission decision persisted by the command's authoritative state transition.
    pub admission: FederatedMutationAdmission,
}

/// Runtime boundary which returns only a durably consensus-applied metadata receipt.
pub trait FederationAuthoritativeCommandSubmitter: Send + Sync {
    /// Resolves an earlier deterministic operation before any changed proposal can be submitted.
    fn resolve(&self, operation_id: OperationId)
    -> FederationAuthoritativeCommandResolveFuture<'_>;

    /// Proposes one command and reads its immutable authoritative admission outcome.
    fn submit(
        &self,
        submission: FederationAuthoritativeCommandSubmission,
    ) -> FederationAuthoritativeCommandSubmitFuture<'_>;
}

/// Owned future for one authoritative command submission.
pub type FederationAuthoritativeCommandSubmitFuture<'a> = Pin<
    Box<
        dyn Future<
                Output = Result<
                    FederationAuthoritativeCommandOutcome,
                    FederationAuthoritativeCommandSubmitError,
                >,
            > + Send
            + 'a,
    >,
>;

/// Owned future for resolving one deterministic authoritative operation.
pub type FederationAuthoritativeCommandResolveFuture<'a> = Pin<
    Box<
        dyn Future<
                Output = Result<
                    Option<FederationAuthoritativeCommandOutcome>,
                    FederationAuthoritativeCommandSubmitError,
                >,
            > + Send
            + 'a,
    >,
>;

/// Admission committer which derives stable command identities and validates the exact receipt.
pub struct ConsensusFederationMutationAdmissionCommitter<S> {
    submitter: S,
    actor_principal_id: PrincipalId,
}

impl<S> ConsensusFederationMutationAdmissionCommitter<S> {
    /// Binds command submission to the internal principal authorised for reconciliation.
    #[must_use]
    pub const fn new(submitter: S, actor_principal_id: PrincipalId) -> Self {
        Self {
            submitter,
            actor_principal_id,
        }
    }
}

impl<S> FederationMutationAdmissionCommitter for ConsensusFederationMutationAdmissionCommitter<S>
where
    S: FederationAuthoritativeCommandSubmitter,
{
    fn commit(
        &self,
        admission: FederationMutationAdmissionCommit,
    ) -> FederationMutationAdmissionCommitFuture<'_> {
        let identity = AdmissionIdentity::derive(&admission);
        Box::pin(async move {
            let identity = identity?;
            if let Some(outcome) = self.submitter.resolve(identity.operation).await? {
                return validate_committed_outcome(&admission, self.actor_principal_id, outcome);
            }
            let (submission, _, _) = admission_submission(&admission, self.actor_principal_id)?;
            let outcome = self.submitter.submit(submission).await?;
            validate_committed_outcome(&admission, self.actor_principal_id, outcome)
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
    _session_id: [u8; 32],
    records: &[NamespaceHistoryCommitRecord],
    now: UnixMicros,
) -> Result<FederationHistoryAdmissionBatch, FederationHistoryAdmissionError> {
    let mut commits = Vec::with_capacity(records.len());
    for record in records {
        let acknowledgement = record
            .federated_acknowledgement()?
            .ok_or(FederationHistoryAdmissionError::MissingAcknowledgement)?;
        let classified =
            classify_federated_history_mutation(repository, record, &acknowledgement, now)?;
        commits.push(FederationMutationAdmissionCommit {
            commit_id: classified.commit_id(),
            acknowledgement,
            admission: classified.admission(),
        });
    }
    Ok(FederationHistoryAdmissionBatch::new(commits))
}

pub(crate) fn validate_admission_batch(
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
    if expected.values().any(|(created_at, _)| now < *created_at)
        || batch.commits.len() != expected.len()
    {
        return Err(FederationHistoryAdmissionError::InvalidBatch);
    }
    let mut commits = BTreeMap::new();
    for commit in &batch.commits {
        let Some((_, acknowledgement)) = expected.get(&commit.commit_id) else {
            return Err(FederationHistoryAdmissionError::InvalidBatch);
        };
        if commit.acknowledgement != *acknowledgement
            || commits.insert(commit.commit_id, commit.admission).is_some()
        {
            return Err(FederationHistoryAdmissionError::InvalidBatch);
        }
    }
    if commits.len() == expected.len() {
        Ok(())
    } else {
        Err(FederationHistoryAdmissionError::InvalidBatch)
    }
}

pub(crate) fn admission_submission(
    admission: &FederationMutationAdmissionCommit,
    actor_principal_id: PrincipalId,
) -> Result<
    (
        FederationAuthoritativeCommandSubmission,
        EntityKind,
        [u8; 16],
    ),
    FederationMutationAdmissionCommitError,
> {
    let identity = AdmissionIdentity::derive(admission)?;
    let (command, expected_kind, expected_id) = match admission.admission {
        FederatedMutationAdmission::Admitted => (
            AuthoritativeCommand::AdmitFederatedMutation(AdmitFederatedMutation {
                namespace_commit_id: admission.commit_id,
                acknowledgement: admission.acknowledgement,
            }),
            EntityKind::FederationMutationAdmission,
            admission.commit_id.as_bytes(),
        ),
        FederatedMutationAdmission::Quarantined(_) => (
            AuthoritativeCommand::RetainFederatedMutationQuarantine(
                RetainFederatedMutationQuarantine {
                    quarantine_id: identity.quarantine,
                    acknowledgement: admission.acknowledgement,
                },
            ),
            EntityKind::FederationQuarantine,
            identity.quarantine.as_bytes(),
        ),
    };
    Ok((
        FederationAuthoritativeCommandSubmission {
            context: CommandContext {
                operation_id: identity.operation,
                actor_principal_id,
                audit_event_id: identity.audit_event,
                occurred_at: admission.acknowledgement.evidence.accepted_at(),
                expected_revision: None,
            },
            command,
        },
        expected_kind,
        expected_id,
    ))
}

fn validate_committed_outcome(
    proposed: &FederationMutationAdmissionCommit,
    actor_principal_id: PrincipalId,
    outcome: FederationAuthoritativeCommandOutcome,
) -> Result<FederatedMutationAdmission, FederationMutationAdmissionCommitError> {
    let actual = FederationMutationAdmissionCommit {
        admission: outcome.admission,
        ..*proposed
    };
    let (submission, expected_kind, expected_id) =
        admission_submission(&actual, actor_principal_id)?;
    let receipt = outcome.receipt;
    if receipt.operation_id != submission.context.operation_id
        || receipt.request_digest != submission.command.request_digest(submission.context)
        || receipt.entity.kind != expected_kind
        || receipt.entity.id != expected_id
    {
        return Err(FederationMutationAdmissionCommitError::Rejected);
    }
    Ok(outcome.admission)
}

struct AdmissionIdentity {
    operation: OperationId,
    audit_event: AuditEventId,
    quarantine: QuarantineId,
}

impl AdmissionIdentity {
    fn derive(
        admission: &FederationMutationAdmissionCommit,
    ) -> Result<Self, FederationMutationAdmissionCommitError> {
        let operation = OperationId::from_bytes(derived_identifier(
            b"meshspan.federation.mutation-admission.operation.v1",
            admission,
        ))
        .map_err(|_| FederationMutationAdmissionCommitError::Rejected)?;
        let audit_event = AuditEventId::from_bytes(derived_identifier(
            b"meshspan.federation.mutation-admission.audit-event.v1",
            admission,
        ))
        .map_err(|_| FederationMutationAdmissionCommitError::Rejected)?;
        let quarantine = QuarantineId::from_bytes(derived_identifier(
            b"meshspan.federation.mutation-admission.quarantine.v1",
            admission,
        ))
        .map_err(|_| FederationMutationAdmissionCommitError::Rejected)?;
        Ok(Self {
            operation,
            audit_event,
            quarantine,
        })
    }
}

fn derived_identifier(domain: &[u8], admission: &FederationMutationAdmissionCommit) -> [u8; 16] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(admission.commit_id.as_bytes());
    digest.update(admission.acknowledgement.signing_payload());
    digest.update(admission.acknowledgement.signature);
    let digest: [u8; 32] = digest.finalize().into();
    let mut identifier = [0; 16];
    identifier.copy_from_slice(&digest[..16]);
    identifier[0] |= 0x80;
    identifier
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

/// Closed failures while proposing one owner admission decision through consensus.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum FederationMutationAdmissionCommitError {
    /// No authoritative consensus leader could confirm the exact decision.
    #[error("federation mutation admission consensus is unavailable")]
    Unavailable,
    /// Consensus, the state machine or receipt verification rejected the exact decision.
    #[error("federation mutation admission commit was rejected")]
    Rejected,
}

/// Closed failures exposed by a concrete authoritative command submission runtime.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum FederationAuthoritativeCommandSubmitError {
    /// The owning partition had no reachable leader or lost the result before confirmation.
    #[error("authoritative federation command submission is unavailable")]
    Unavailable,
    /// Consensus or its state machine rejected the command.
    #[error("authoritative federation command was rejected")]
    Rejected,
}

impl From<FederationAuthoritativeCommandSubmitError> for FederationMutationAdmissionCommitError {
    fn from(value: FederationAuthoritativeCommandSubmitError) -> Self {
        match value {
            FederationAuthoritativeCommandSubmitError::Unavailable => Self::Unavailable,
            FederationAuthoritativeCommandSubmitError::Rejected => Self::Rejected,
        }
    }
}
