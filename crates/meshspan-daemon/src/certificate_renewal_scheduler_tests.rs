// SPDX-License-Identifier: GPL-2.0-only

use std::sync::Mutex;

use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_domain::{
    AcmeConfigurationId, CertificateOrderId, DurationMicros, PrincipalId, Revision, UnixMicros,
};
use meshspan_metadata::{
    ApplyDisposition, AuthoritativeCommand, CertificateOrderRecord, CertificateOrderState,
    CertificateRenewalCandidate, CommandContext, CommandReceipt, DueCertificateRenewalCursor,
    EntityKind, EntityReference, LogPosition, Page, PageLimit, RepositoryError,
};

use crate::{
    CertificateRenewalAuthority, CertificateRenewalScheduleError, CertificateRenewalScheduler,
};

#[test]
fn scheduler_commits_one_deterministic_immediately_actionable_replacement()
-> Result<(), Box<dyn std::error::Error>> {
    let candidate = candidate()?;
    let authority = RecordingAuthority::new(candidate);
    let scheduler = CertificateRenewalScheduler::new(&authority, PrincipalId::from_bytes([3; 16])?);

    let commit = scheduler
        .schedule_next(UnixMicros::new(500), DurationMicros::new(600), None, 10)?
        .ok_or("renewal was not scheduled")?;

    assert_eq!(commit.source_order_id, candidate.source_order_id);
    assert_eq!(commit.revision, Revision::new(20));
    let replacement = authority.order()?.ok_or("replacement missing")?;
    assert_eq!(replacement.order_id, commit.replacement_order_id);
    assert_eq!(replacement.config_id, candidate.config_id);
    assert_eq!(replacement.next_attempt_at, UnixMicros::new(500));
    assert_eq!(replacement.state, CertificateOrderState::Queued);
    assert_eq!(authority.commit_count(), 1);
    Ok(())
}

#[test]
fn scheduler_rejects_invalid_lead_before_reading_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let authority = RecordingAuthority::new(candidate()?);
    let result = CertificateRenewalScheduler::new(&authority, PrincipalId::from_bytes([3; 16])?)
        .schedule_next(UnixMicros::new(500), DurationMicros::new(0), None, 10);
    assert!(matches!(
        result,
        Err(CertificateRenewalScheduleError::InvalidInput)
    ));
    assert_eq!(authority.read_count(), 0);
    Ok(())
}

fn candidate() -> Result<CertificateRenewalCandidate, Box<dyn std::error::Error>> {
    Ok(CertificateRenewalCandidate {
        source_order_id: CertificateOrderId::from_bytes([1; 16])?,
        config_id: AcmeConfigurationId::from_bytes([2; 16])?,
        not_after: UnixMicros::new(1_000),
        revision: Revision::new(9),
    })
}

struct RecordingAuthority {
    candidate: CertificateRenewalCandidate,
    state: Mutex<AuthorityState>,
}

#[derive(Default)]
struct AuthorityState {
    replacement: Option<CertificateOrderRecord>,
    reads: usize,
    commits: usize,
}

impl RecordingAuthority {
    fn new(candidate: CertificateRenewalCandidate) -> Self {
        Self {
            candidate,
            state: Mutex::new(AuthorityState::default()),
        }
    }

    fn order(&self) -> Result<Option<CertificateOrderRecord>, Box<dyn std::error::Error>> {
        Ok(self
            .state
            .lock()
            .map_err(|_| "authority lock failed")?
            .replacement)
    }

    fn read_count(&self) -> usize {
        self.state.lock().map_or(0, |state| state.reads)
    }

    fn commit_count(&self) -> usize {
        self.state.lock().map_or(0, |state| state.commits)
    }
}

impl CertificateRenewalAuthority for RecordingAuthority {
    fn due_certificate_renewals(
        &self,
        renew_by: UnixMicros,
        _after: Option<&DueCertificateRenewalCursor>,
        _limit: PageLimit,
    ) -> Result<Page<CertificateRenewalCandidate, DueCertificateRenewalCursor>, RepositoryError>
    {
        let mut state = self
            .state
            .lock()
            .map_err(|_| RepositoryError::CorruptState)?;
        state.reads = state.reads.saturating_add(1);
        let items = if state.replacement.is_none() && self.candidate.not_after <= renew_by {
            vec![self.candidate]
        } else {
            Vec::new()
        };
        Ok(Page { items, next: None })
    }

    fn certificate_order(
        &self,
        order_id: CertificateOrderId,
    ) -> Result<Option<CertificateOrderRecord>, RepositoryError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| RepositoryError::CorruptState)?
            .replacement
            .filter(|order| order.order_id == order_id))
    }

    fn commit_certificate_renewal(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, MetadataAuthorityRequestError> {
        let AuthoritativeCommand::QueueCertificateOrder(value) = command else {
            return Err(MetadataAuthorityRequestError::Failed);
        };
        let replacement = CertificateOrderRecord {
            order_id: value.order_id,
            config_id: value.config_id,
            state: CertificateOrderState::Queued,
            next_attempt_at: value.next_attempt_at,
            attempt_count: 0,
            certificate: None,
            claim: None,
            revision: Revision::new(20),
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| MetadataAuthorityRequestError::Failed)?;
        state.replacement = Some(replacement);
        state.commits = state.commits.saturating_add(1);
        Ok(CommandReceipt {
            disposition: ApplyDisposition::Applied,
            operation_id: context.operation_id,
            request_digest: command.request_digest(context),
            result_digest: [8; 32],
            committed_revision: Revision::new(20),
            committed_position: LogPosition { index: 20, term: 2 },
            applied_position: LogPosition { index: 20, term: 2 },
            entity: EntityReference {
                kind: EntityKind::CertificateOrder,
                id: value.order_id.as_bytes(),
            },
        })
    }
}
