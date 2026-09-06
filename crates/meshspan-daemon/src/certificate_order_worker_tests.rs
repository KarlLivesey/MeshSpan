// SPDX-License-Identifier: GPL-2.0-only

use std::sync::Mutex;

use meshspan_cluster::MetadataAuthorityRequestError;
use meshspan_domain::{
    AcmeConfigurationId, CertificateOrderId, DurationMicros, EntropyError, NodeId, PrincipalId,
    RandomSource, Revision, UnixMicros,
};
use meshspan_metadata::{
    AcmeChallengeKind, AcmeConfigurationRecord, ApplyDisposition, AuthoritativeCommand,
    CertificateOrderCheckpointRecord, CertificateOrderClaim, CertificateOrderRecord,
    CertificateOrderState, CommandContext, CommandReceipt, DueCertificateOrderCursor, EntityKind,
    EntityReference, LogPosition, Page, PageLimit, RepositoryError, SecretGenerationReference,
};

use crate::{
    CertificateOrderDispatchError, CertificateOrderDispatcher, CertificateOrderWorkerAuthority,
};

#[test]
fn generated_claim_fences_fit_the_authoritative_sql_integer_range()
-> Result<(), Box<dyn std::error::Error>> {
    for seed in [1, 128, 200] {
        let authority = FakeAuthority::new(queued_order()?, None, CommitMode::Success)?;
        let mut random = IncrementingRandom(seed);
        let assignment = CertificateOrderDispatcher::new(
            &authority,
            &mut random,
            NodeId::from_bytes([21; 16])?,
            1,
        )
        .claim_next(UnixMicros::new(20), DurationMicros::new(1_000), None, 1)?
        .ok_or("assignment missing")?;
        let fence = assignment.order.claim.ok_or("claim missing")?.fence;
        assert!(
            i64::try_from(fence).is_ok(),
            "seed {seed} generated unpersistable fence {fence}"
        );
        assert_ne!(fence, 0);
    }
    Ok(())
}

#[test]
fn due_order_is_claimed_then_returned_with_exact_configuration_and_checkpoint()
-> Result<(), Box<dyn std::error::Error>> {
    let candidate = queued_order()?;
    let checkpoint = previous_checkpoint(candidate.order_id)?;
    let authority = FakeAuthority::new(candidate, Some(checkpoint.clone()), CommitMode::Success)?;
    let worker = NodeId::from_bytes([21; 16])?;
    let mut random = IncrementingRandom(1);
    let assignment = CertificateOrderDispatcher::new(&authority, &mut random, worker, 7)
        .claim_next(UnixMicros::new(20), DurationMicros::new(1_000), None, 8)?
        .ok_or("assignment missing")?;

    let claim = assignment.order.claim.ok_or("claim missing")?;
    assert_eq!(claim.worker_node_id, worker);
    assert_eq!(claim.worker_incarnation, 7);
    assert_eq!(claim.generation, 1);
    assert_eq!(claim.lease_expires_at, UnixMicros::new(1_020));
    assert_ne!(claim.fence, 0);
    assert_eq!(assignment.configuration.config_id, candidate.config_id);
    assert_eq!(assignment.checkpoint, Some(checkpoint));
    assert_eq!(authority.commit_count(), 1);
    Ok(())
}

#[test]
fn rejected_claim_is_skipped_only_after_another_live_claim_is_observed()
-> Result<(), Box<dyn std::error::Error>> {
    let candidate = queued_order()?;
    let authority = FakeAuthority::new(candidate, None, CommitMode::WonRace)?;
    let mut random = IncrementingRandom(1);
    let assignment =
        CertificateOrderDispatcher::new(&authority, &mut random, NodeId::from_bytes([23; 16])?, 1)
            .claim_next(UnixMicros::new(20), DurationMicros::new(1_000), None, 1)?;
    assert_eq!(assignment, None);
    assert_eq!(authority.commit_count(), 1);
    Ok(())
}

#[test]
fn unexplained_rejection_and_forged_receipt_fail_closed() -> Result<(), Box<dyn std::error::Error>>
{
    for (mode, expected_receipt_error) in [
        (CommitMode::RejectUnchanged, false),
        (CommitMode::BadReceipt, true),
    ] {
        let candidate = queued_order()?;
        let authority = FakeAuthority::new(candidate, None, mode)?;
        let mut random = IncrementingRandom(1);
        let result = CertificateOrderDispatcher::new(
            &authority,
            &mut random,
            NodeId::from_bytes([25; 16])?,
            1,
        )
        .claim_next(UnixMicros::new(20), DurationMicros::new(1_000), None, 1);
        let Err(error) = result else {
            return Err("claim should fail closed".into());
        };
        assert_eq!(
            matches!(error, CertificateOrderDispatchError::InvalidReceipt),
            expected_receipt_error
        );
        if !expected_receipt_error {
            assert!(matches!(
                error,
                CertificateOrderDispatchError::Authority(MetadataAuthorityRequestError::Rejected)
            ));
        }
    }
    Ok(())
}

fn queued_order() -> Result<CertificateOrderRecord, Box<dyn std::error::Error>> {
    Ok(CertificateOrderRecord {
        order_id: CertificateOrderId::from_bytes([31; 16])?,
        config_id: AcmeConfigurationId::from_bytes([32; 16])?,
        state: CertificateOrderState::Queued,
        next_attempt_at: UnixMicros::new(10),
        attempt_count: 0,
        certificate: None,
        claim: None,
        revision: Revision::new(3),
    })
}

fn configuration(
    config_id: AcmeConfigurationId,
) -> Result<AcmeConfigurationRecord, meshspan_domain::IdentifierError> {
    Ok(AcmeConfigurationRecord {
        provisioning_intent_digest: None,
        config_id,
        directory_url: "https://acme.example.test/directory".to_owned(),
        account_key: SecretGenerationReference {
            secret_id: [33; 16],
            generation: 1,
        },
        challenge_kind: AcmeChallengeKind::Http01,
        challenge_settings: None,
        certificate_names: vec!["files.example.test".to_owned()],
        configured_by: PrincipalId::from_bytes([22; 16])?,
        revision: Revision::new(2),
    })
}

fn previous_checkpoint(
    order_id: CertificateOrderId,
) -> Result<CertificateOrderCheckpointRecord, Box<dyn std::error::Error>> {
    Ok(CertificateOrderCheckpointRecord {
        legacy_lease_expiry_candidate: None,
        order_id,
        claim_generation: 1,
        worker_node_id: NodeId::from_bytes([34; 16])?,
        worker_incarnation: 2,
        fence: 35,
        certificate_key: SecretGenerationReference {
            secret_id: order_id.as_bytes(),
            generation: 1,
        },
        checkpoint: vec![1, 2, 3],
        checkpoint_digest: [36; 32],
        revision: Revision::new(4),
    })
}

#[derive(Clone, Copy)]
enum CommitMode {
    Success,
    WonRace,
    RejectUnchanged,
    BadReceipt,
}

struct FakeAuthority {
    configuration: AcmeConfigurationRecord,
    checkpoint: Option<CertificateOrderCheckpointRecord>,
    state: Mutex<FakeState>,
}

struct FakeState {
    order: CertificateOrderRecord,
    mode: CommitMode,
    commits: usize,
}

impl FakeAuthority {
    fn new(
        order: CertificateOrderRecord,
        checkpoint: Option<CertificateOrderCheckpointRecord>,
        mode: CommitMode,
    ) -> Result<Self, meshspan_domain::IdentifierError> {
        Ok(Self {
            configuration: configuration(order.config_id)?,
            checkpoint,
            state: Mutex::new(FakeState {
                order,
                mode,
                commits: 0,
            }),
        })
    }

    fn commit_count(&self) -> usize {
        self.state.lock().map_or(0, |state| state.commits)
    }
}

impl CertificateOrderWorkerAuthority for FakeAuthority {
    fn due_certificate_orders(
        &self,
        _now: UnixMicros,
        _after: Option<&DueCertificateOrderCursor>,
        _limit: PageLimit,
    ) -> Result<Page<CertificateOrderRecord, DueCertificateOrderCursor>, RepositoryError> {
        let order = self
            .state
            .lock()
            .map_err(|_| RepositoryError::CorruptState)?
            .order;
        Ok(Page {
            items: vec![order],
            next: None,
        })
    }

    fn certificate_order(
        &self,
        _order_id: CertificateOrderId,
    ) -> Result<Option<CertificateOrderRecord>, RepositoryError> {
        Ok(Some(
            self.state
                .lock()
                .map_err(|_| RepositoryError::CorruptState)?
                .order,
        ))
    }

    fn acme_configuration(
        &self,
        _config_id: AcmeConfigurationId,
    ) -> Result<Option<AcmeConfigurationRecord>, RepositoryError> {
        Ok(Some(self.configuration.clone()))
    }

    fn certificate_order_checkpoint(
        &self,
        _order_id: CertificateOrderId,
    ) -> Result<Option<CertificateOrderCheckpointRecord>, RepositoryError> {
        Ok(self.checkpoint.clone())
    }

    fn commit_certificate_order_claim(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, MetadataAuthorityRequestError> {
        let AuthoritativeCommand::ClaimCertificateOrder(claim) = command else {
            return Err(MetadataAuthorityRequestError::Failed);
        };
        if context.actor_principal_id != self.configuration.configured_by {
            return Err(MetadataAuthorityRequestError::Failed);
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| MetadataAuthorityRequestError::Failed)?;
        state.commits = state.commits.saturating_add(1);
        match state.mode {
            CommitMode::WonRace => {
                state.order.state = CertificateOrderState::Claimed;
                state.order.attempt_count = 1;
                state.order.claim = Some(CertificateOrderClaim {
                    generation: 1,
                    worker_node_id: NodeId::from_bytes([40; 16])
                        .map_err(|_| MetadataAuthorityRequestError::Failed)?,
                    worker_incarnation: 2,
                    fence: 41,
                    lease_expires_at: UnixMicros::new(2_000),
                });
                return Err(MetadataAuthorityRequestError::Rejected);
            }
            CommitMode::RejectUnchanged => return Err(MetadataAuthorityRequestError::Rejected),
            CommitMode::Success | CommitMode::BadReceipt => {}
        }
        state.order.state = CertificateOrderState::Claimed;
        state.order.attempt_count = claim.claim_generation;
        state.order.claim = Some(CertificateOrderClaim {
            generation: claim.claim_generation,
            worker_node_id: claim.worker_node_id,
            worker_incarnation: claim.worker_incarnation,
            fence: claim.fence,
            lease_expires_at: claim.lease_expires_at,
        });
        state.order.revision = Revision::new(9);
        Ok(CommandReceipt {
            disposition: ApplyDisposition::Applied,
            operation_id: context.operation_id,
            request_digest: command.request_digest(context),
            result_digest: if matches!(state.mode, CommitMode::BadReceipt) {
                [0; 32]
            } else {
                [42; 32]
            },
            committed_revision: Revision::new(9),
            committed_position: LogPosition { index: 9, term: 1 },
            applied_position: LogPosition { index: 9, term: 1 },
            entity: EntityReference {
                kind: EntityKind::CertificateOrder,
                id: claim.order_id.as_bytes(),
            },
        })
    }
}

struct IncrementingRandom(u8);

impl RandomSource for IncrementingRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        for byte in destination {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1).max(1);
        }
        Ok(())
    }
}
