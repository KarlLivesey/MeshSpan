// SPDX-License-Identifier: GPL-2.0-only

use std::error::Error;

use meshspan_domain::{AcmeConfigurationId, CertificateOrderId, NodeId, Revision, UnixMicros};

use super::{Fixture, manual_task};
use crate::{
    AdvanceManualDnsTask, AuthoritativeCommand, ManualDnsTaskPhase, QueueCertificateOrder,
    RepositoryError,
};

#[test]
fn manual_task_cannot_advance_at_the_exclusive_claim_expiry() -> Result<(), Box<dyn Error>> {
    let (mut fixture, mut task) = published_task()?;
    task.phase = ManualDnsTaskPhase::PublicationObserved;
    assert!(matches!(
        fixture.apply(7, 100, &AuthoritativeCommand::AdvanceManualDnsTask(task)),
        Err(RepositoryError::InvalidCommand)
    ));
    Ok(())
}

#[test]
fn repeated_phase_observation_never_advances_authoritative_state() -> Result<(), Box<dyn Error>> {
    let (mut fixture, task) = published_task()?;
    let original = fixture.repository.manual_dns_task(task.task_digest)?;
    for now in 12..90 {
        assert!(fixture.repository.manual_dns_task_transition_satisfied(
            UnixMicros::new(now),
            &task,
            task.fence
        )?);
    }
    assert_eq!(fixture.repository.current_revision()?, Revision::new(6));
    assert_eq!(
        fixture.repository.manual_dns_task(task.task_digest)?,
        original
    );
    let mut observed = task.clone();
    observed.phase = ManualDnsTaskPhase::PublicationObserved;
    assert!(!fixture.repository.manual_dns_task_transition_satisfied(
        UnixMicros::new(90),
        &observed,
        observed.fence
    )?);
    fixture.apply(
        7,
        90,
        &AuthoritativeCommand::AdvanceManualDnsTask(observed.clone()),
    )?;
    for candidate in [&task, &observed] {
        assert!(fixture.repository.manual_dns_task_transition_satisfied(
            UnixMicros::new(91),
            candidate,
            candidate.fence
        )?);
    }
    observed.phase = ManualDnsTaskPhase::AwaitingRemoval;
    assert!(!fixture.repository.manual_dns_task_transition_satisfied(
        UnixMicros::new(92),
        &observed,
        observed.fence
    )?);
    assert_eq!(fixture.repository.current_revision()?, Revision::new(7));
    Ok(())
}

#[test]
fn every_claim_and_publication_field_is_bound_before_skipping_a_transition()
-> Result<(), Box<dyn Error>> {
    let (fixture, task) = published_task()?;
    let mut changed = vec![task.clone(); 9];
    changed[0].order_id = CertificateOrderId::from_bytes([92; 16])?;
    changed[1].claim_generation += 1;
    changed[2].worker_node_id = NodeId::from_bytes([93; 16])?;
    changed[3].worker_incarnation += 1;
    changed[4].fence += 1;
    changed[5].record_name = "_acme-challenge.other.example.test".to_owned();
    changed[6].record_value = b"different-value".to_vec();
    changed[7].expires_at = UnixMicros::new(151);
    changed[8].task_digest = [0; 32];
    for candidate in changed {
        assert!(matches!(
            fixture.repository.manual_dns_task_transition_satisfied(
                UnixMicros::new(12),
                &candidate,
                candidate.fence
            ),
            Err(RepositoryError::InvalidCommand)
        ));
    }
    let mut absent = task;
    absent.task_digest = [2; 32];
    assert!(!fixture.repository.manual_dns_task_transition_satisfied(
        UnixMicros::new(12),
        &absent,
        absent.fence
    )?);
    assert_eq!(fixture.repository.current_revision()?, Revision::new(6));
    Ok(())
}

#[test]
fn phase_observation_rechecks_claim_and_publication_expiry() -> Result<(), Box<dyn Error>> {
    let (mut fixture, mut task) = published_task()?;
    assert!(fixture.repository.manual_dns_task_transition_satisfied(
        UnixMicros::new(99),
        &task,
        task.fence
    )?);
    for now in [100, 101] {
        assert!(matches!(
            fixture.repository.manual_dns_task_transition_satisfied(
                UnixMicros::new(now),
                &task,
                task.fence
            ),
            Err(RepositoryError::InvalidCommand)
        ));
    }
    fixture.apply(
        7,
        12,
        &AuthoritativeCommand::RenewCertificateOrder(fixture.renew(task.order_id, 1, 901, 300)),
    )?;
    task.phase = ManualDnsTaskPhase::PublicationObserved;
    fixture.apply(
        8,
        13,
        &AuthoritativeCommand::AdvanceManualDnsTask(task.clone()),
    )?;
    assert!(matches!(
        fixture.repository.manual_dns_task_transition_satisfied(
            UnixMicros::new(150),
            &task,
            task.fence
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    task.phase = ManualDnsTaskPhase::AwaitingRemoval;
    assert!(!fixture.repository.manual_dns_task_transition_satisfied(
        UnixMicros::new(150),
        &task,
        task.fence
    )?);
    fixture.apply(
        9,
        150,
        &AuthoritativeCommand::AdvanceManualDnsTask(task.clone()),
    )?;
    assert!(fixture.repository.manual_dns_task_transition_satisfied(
        UnixMicros::new(151),
        &task,
        task.fence
    )?);
    Ok(())
}

#[test]
fn superseded_state_is_not_a_later_successful_phase() -> Result<(), Box<dyn Error>> {
    let (fixture, task) = published_task()?;
    // Hostile retained state must not make the numerically larger terminal marker
    // count as proof of completion, even if the old claim row still appears active.
    fixture.repository.database.connection().execute(
        "UPDATE manual_dns_tasks SET phase = 5 WHERE task_digest = ?1",
        [task.task_digest.as_slice()],
    )?;
    assert!(matches!(
        fixture.repository.manual_dns_task_transition_satisfied(
            UnixMicros::new(12),
            &task,
            task.fence
        ),
        Err(RepositoryError::InvalidCommand)
    ));
    Ok(())
}

fn published_task() -> Result<(Fixture, AdvanceManualDnsTask), Box<dyn Error>> {
    let mut fixture = Fixture::new()?;
    let config_id = AcmeConfigurationId::from_bytes([90; 16])?;
    let order_id = CertificateOrderId::from_bytes([91; 16])?;
    let mut configuration = fixture.configuration(config_id)?;
    configuration.challenge_settings = None;
    fixture.apply(3, 2, &AuthoritativeCommand::ConfigureAcme(configuration))?;
    fixture.apply(
        4,
        10,
        &AuthoritativeCommand::QueueCertificateOrder(QueueCertificateOrder {
            order_id,
            config_id,
            next_attempt_at: UnixMicros::new(10),
        }),
    )?;
    fixture.apply(
        5,
        10,
        &AuthoritativeCommand::ClaimCertificateOrder(fixture.claim(order_id, 1, 901, 100)),
    )?;
    let task = manual_task(
        &fixture,
        order_id,
        1,
        901,
        [1; 32],
        ManualDnsTaskPhase::AwaitingPublication,
    );
    fixture.apply(
        6,
        11,
        &AuthoritativeCommand::AdvanceManualDnsTask(task.clone()),
    )?;
    Ok((fixture, task))
}
