// SPDX-License-Identifier: GPL-2.0-only

//! Real committed ACME events drive the notification outbox; no synthetic event kind changes.

use super::{Fixture, *};
use crate::{
    ClaimNotification, CompleteNotification, ConfigureNotificationChannel,
    NOTIFICATION_SETTINGS_SECRET_KIND, NotificationChannelKind, NotificationDeliveryOutcome,
    NotificationDeliveryState, NotificationEventKind, QueueNotification, notification_delivery_id,
};
use meshspan_domain::{ComponentInstanceId, WorkId};

#[test]
fn notification_outbox_deduplicates_and_retries_one_exact_committed_event()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut fixture, channel, event) = configured(std::path::Path::new(":memory:"))?;
    let queue = queue(channel, event);
    assert_eq!(fixture.repository.notification_channels()?.len(), 1);
    assert_eq!(
        fixture
            .repository
            .pending_notification_events(channel, PageLimit::new(1)?)?,
        vec![event]
    );
    fixture.apply(6, 20, &queue)?;
    assert!(
        fixture
            .repository
            .pending_notification_events(channel, PageLimit::new(1)?)?
            .is_empty()
    );
    fixture.apply(7, 21, &queue)?;
    let delivery = notification_delivery_id(channel, event)?;
    let queued = fixture
        .repository
        .notification_delivery(delivery)?
        .ok_or("missing outbox")?;
    assert_eq!(queued.attempt, 0);
    assert_eq!(
        queued.event_kind,
        NotificationEventKind::CertificateOrderQueued
    );
    assert_eq!(queued.occurred_at, UnixMicros::new(10));
    fixture.apply(8, 22, &claim(&fixture, delivery, 0))?;
    assert!(
        fixture
            .repository
            .ready_notification_deliveries(UnixMicros::new(23), PageLimit::new(1)?)?
            .is_empty()
    );
    assert!(matches!(
        fixture.apply(9, 23, &claim(&fixture, delivery, 0)),
        Err(RepositoryError::StaleRevision)
    ));
    fixture.apply(
        9,
        24,
        &complete(&fixture, delivery, 1, NotificationDeliveryOutcome::Retry),
    )?;
    let retried = fixture
        .repository
        .notification_delivery(delivery)?
        .ok_or("missing retry")?;
    let expected = 24 + 5_000_000 + i64::from(delivery.as_bytes()[0]) * 1000;
    assert_eq!(retried.next_attempt_at, UnixMicros::new(expected));
    assert_eq!(retried.state, NotificationDeliveryState::Queued);
    assert_eq!(
        fixture
            .repository
            .ready_notification_deliveries(UnixMicros::new(expected), PageLimit::new(1)?)?,
        vec![retried]
    );
    assert!(matches!(
        fixture.apply(10, expected - 1, &claim(&fixture, delivery, 1)),
        Err(RepositoryError::StaleRevision)
    ));
    fixture.apply(10, expected, &claim(&fixture, delivery, 1))?;
    assert!(matches!(
        fixture.apply(
            11,
            expected + 1,
            &complete(&fixture, delivery, 1, NotificationDeliveryOutcome::Accepted)
        ),
        Err(RepositoryError::StaleRevision)
    ));
    fixture.apply(
        11,
        expected + 1,
        &complete(&fixture, delivery, 2, NotificationDeliveryOutcome::Accepted),
    )?;
    fixture.apply(12, expected + 2, &queue)?;
    let accepted = fixture
        .repository
        .notification_delivery(delivery)?
        .ok_or("missing receipt")?;
    assert_eq!(accepted.state, NotificationDeliveryState::Accepted);
    assert_eq!(accepted.attempt, 2);
    let database = fixture.repository.into_database();
    assert_eq!(
        database.connection().query_row(
            "SELECT count(*) FROM notification_deliveries",
            [],
            |row| row.get::<_, i64>(0)
        )?,
        1
    );
    database.check_integrity()?;
    Ok(())
}

#[test]
fn notification_claim_survives_reopen_and_expired_worker_cannot_complete()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let file = directory.path().join("partition.sqlite3");
    let (mut fixture, channel, event) = configured(&file)?;
    fixture.apply(6, 20, &queue(channel, event))?;
    let delivery = notification_delivery_id(channel, event)?;
    fixture.apply(7, 21, &claim(&fixture, delivery, 0))?;
    drop(fixture.repository.into_database());
    fixture.repository = AuthoritativeRepository::new(PartitionDatabase::open(
        &file,
        PartitionId::from_bytes([1; 16])?,
        UnixMicros::new(22),
    )?);
    let retained = fixture
        .repository
        .notification_delivery(delivery)?
        .ok_or("lost claim")?;
    assert_eq!(retained.attempt, 1);
    assert_eq!(retained.next_attempt_at, UnixMicros::new(60_000_021));
    assert!(matches!(
        fixture.apply(
            8,
            60_000_021,
            &complete(&fixture, delivery, 1, NotificationDeliveryOutcome::Accepted)
        ),
        Err(RepositoryError::StaleRevision)
    ));
    fixture.apply(8, 60_000_021, &claim(&fixture, delivery, 1))?;
    fixture.apply(
        9,
        60_000_022,
        &complete(&fixture, delivery, 2, NotificationDeliveryOutcome::Rejected),
    )?;
    assert_eq!(
        fixture
            .repository
            .notification_delivery(delivery)?
            .ok_or("lost rejection")?
            .state,
        NotificationDeliveryState::Rejected
    );
    Ok(())
}

#[test]
fn notification_configuration_replacement_cancels_old_destination_and_rolls_back_atomically()
-> Result<(), Box<dyn std::error::Error>> {
    use crate::repository::apply::{ApplyFaultPoint, apply_committed_with_fault};
    let (mut fixture, channel, event) = configured(std::path::Path::new(":memory:"))?;
    fixture.apply(6, 20, &queue(channel, event))?;
    let delivery = notification_delivery_id(channel, event)?;
    fixture.apply(7, 21, &claim(&fixture, delivery, 0))?;
    let disabled = configuration(channel, 1, false)?;
    let context = CommandContext {
        operation_id: OperationId::from_bytes([8; 16])?,
        actor_principal_id: fixture.administrator,
        audit_event_id: AuditEventId::from_bytes([108; 16])?,
        occurred_at: UnixMicros::new(22),
        expected_revision: Some(Revision::new(7)),
    };
    for fault in [
        ApplyFaultPoint::AfterCommand,
        ApplyFaultPoint::AfterAudit,
        ApplyFaultPoint::BeforeCommit,
    ] {
        assert!(
            apply_committed_with_fault(
                &mut fixture.repository.database,
                LogPosition { index: 8, term: 1 },
                context,
                &disabled,
                fault
            )
            .is_err()
        );
        assert!(
            fixture
                .repository
                .notification_channel(channel)?
                .ok_or("lost channel")?
                .enabled
        );
        assert_eq!(
            fixture
                .repository
                .notification_delivery(delivery)?
                .ok_or("lost delivery")?
                .state,
            NotificationDeliveryState::Claimed
        );
    }
    fixture.apply(8, 22, &disabled)?;
    assert_eq!(
        fixture
            .repository
            .notification_delivery(delivery)?
            .ok_or("lost cancellation")?
            .state,
        NotificationDeliveryState::Cancelled
    );
    assert!(matches!(
        fixture.apply(
            9,
            23,
            &complete(&fixture, delivery, 1, NotificationDeliveryOutcome::Accepted)
        ),
        Err(RepositoryError::StaleRevision)
    ));
    assert!(matches!(
        fixture.apply(9, 23, &queue(channel, event)),
        Err(RepositoryError::StaleRevision)
    ));
    Ok(())
}

#[test]
fn notification_wire_round_trips_and_rejects_truncation_and_unknown_variants()
-> Result<(), Box<dyn std::error::Error>> {
    let (fixture, channel, event) = configured(std::path::Path::new(":memory:"))?;
    let delivery = notification_delivery_id(channel, event)?;
    let context = CommandContext {
        operation_id: OperationId::from_bytes([80; 16])?,
        actor_principal_id: fixture.administrator,
        audit_event_id: AuditEventId::from_bytes([81; 16])?,
        occurred_at: UnixMicros::new(20),
        expected_revision: None,
    };
    for command in [
        configuration(channel, 1, false)?,
        queue(channel, event),
        claim(&fixture, delivery, 0),
        complete(&fixture, delivery, 1, NotificationDeliveryOutcome::Retry),
    ] {
        let bytes = crate::encode_authoritative_command(context, &command)?;
        assert_eq!(
            crate::decode_authoritative_command(&bytes)?.command,
            command
        );
        for length in 0..bytes.len() {
            assert!(crate::decode_authoritative_command(&bytes[..length]).is_err());
        }
        let mut malformed = bytes.clone();
        malformed.push(0);
        assert!(crate::decode_authoritative_command(&malformed).is_err());
    }
    let mut bytes = crate::encode_authoritative_command(
        context,
        &complete(&fixture, delivery, 1, NotificationDeliveryOutcome::Accepted),
    )?;
    *bytes.last_mut().ok_or("empty encoding")? = 255;
    assert!(crate::decode_authoritative_command(&bytes).is_err());
    Ok(())
}

fn configured(
    file: &std::path::Path,
) -> Result<(Fixture, ComponentInstanceId, AuditEventId), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::at(file)?;
    let channel = ComponentInstanceId::from_bytes([70; 16])?;
    fixture.insert_secret(
        NOTIFICATION_SETTINGS_SECRET_KIND,
        SecretGenerationReference {
            secret_id: [71; 16],
            generation: 1,
        },
    )?;
    fixture.apply(3, 2, &configuration(channel, 0, true)?)?;
    let config = AcmeConfigurationId::from_bytes([72; 16])?;
    fixture.apply(
        4,
        3,
        &AuthoritativeCommand::ConfigureAcme(fixture.configuration(config)?),
    )?;
    fixture.apply(
        5,
        10,
        &AuthoritativeCommand::QueueCertificateOrder(QueueCertificateOrder {
            order_id: CertificateOrderId::from_bytes([73; 16])?,
            config_id: config,
            next_attempt_at: UnixMicros::new(10),
        }),
    )?;
    Ok((fixture, channel, AuditEventId::from_bytes([105; 16])?))
}

fn configuration(
    channel: ComponentInstanceId,
    expected_sequence: u64,
    enabled: bool,
) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
    Ok(AuthoritativeCommand::ConfigureNotificationChannel(
        ConfigureNotificationChannel {
            channel_id: channel,
            expected_sequence,
            display_name: RecordName::new("Operator notifications")?,
            kind: NotificationChannelKind::Webhook,
            settings: SecretGenerationReference {
                secret_id: [71; 16],
                generation: 1,
            },
            enabled,
            event_filter: 15,
        },
    ))
}

fn queue(channel: ComponentInstanceId, event: AuditEventId) -> AuthoritativeCommand {
    AuthoritativeCommand::QueueNotification(QueueNotification {
        channel_id: channel,
        event_id: event,
        channel_sequence: 1,
    })
}

fn claim(fixture: &Fixture, delivery: WorkId, expected_attempt: u64) -> AuthoritativeCommand {
    AuthoritativeCommand::ClaimNotification(ClaimNotification {
        delivery_id: delivery,
        expected_attempt,
        worker_node_id: fixture.node,
        worker_incarnation: 1,
    })
}

fn complete(
    fixture: &Fixture,
    delivery: WorkId,
    attempt: u64,
    outcome: NotificationDeliveryOutcome,
) -> AuthoritativeCommand {
    AuthoritativeCommand::CompleteNotification(CompleteNotification {
        delivery_id: delivery,
        attempt,
        worker_node_id: fixture.node,
        worker_incarnation: 1,
        outcome,
    })
}
