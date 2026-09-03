// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    AcmeConfigurationId, AuditEventId, CertificateOrderId, HostId, MeshId, NodeId, OperationId,
    PartitionId, PrincipalId, Revision, RoleId, UnixMicros,
};
use rusqlite::params;

use super::{
    AuthoritativeRepository, CertificateOrderState, EntityKind, LogPosition, RepositoryError,
};
use crate::{
    ACME_ACCOUNT_KEY_SECRET_KIND, ACME_CHALLENGE_SETTINGS_SECRET_KIND, AcmeChallengeKind,
    AuthoritativeCommand, BootstrapMesh, CertificateOrderCompletion, ClaimCertificateOrder,
    CommandContext, CompleteCertificateOrder, ConfigureAcme, PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND,
    PartitionDatabase, QueueCertificateOrder, RecordName, RenewCertificateOrder,
    SecretGenerationReference,
};

#[test]
fn certificate_order_is_retried_reclaimed_and_stale_workers_are_fenced()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let config_id = AcmeConfigurationId::from_bytes([10; 16])?;
    fixture.apply(
        2,
        2,
        &AuthoritativeCommand::ConfigureAcme(fixture.configuration(config_id)?),
    )?;
    let order_id = CertificateOrderId::from_bytes([11; 16])?;
    let queued = fixture.apply(
        3,
        10,
        &AuthoritativeCommand::QueueCertificateOrder(QueueCertificateOrder {
            order_id,
            config_id,
            next_attempt_at: UnixMicros::new(10),
        }),
    )?;
    assert_eq!(queued.entity.kind, EntityKind::CertificateOrder);

    fixture.apply(
        4,
        10,
        &AuthoritativeCommand::ClaimCertificateOrder(fixture.claim(order_id, 1, 101, 100)),
    )?;
    fixture.apply(
        5,
        20,
        &AuthoritativeCommand::RenewCertificateOrder(fixture.renew(order_id, 1, 101, 120)),
    )?;
    fixture.apply(
        6,
        121,
        &AuthoritativeCommand::ClaimCertificateOrder(fixture.claim(order_id, 2, 202, 180)),
    )?;
    let stale = fixture.apply(
        7,
        122,
        &AuthoritativeCommand::CompleteCertificateOrder(fixture.retry(order_id, 1, 101, 200)),
    );
    assert!(matches!(stale, Err(RepositoryError::InvalidCommand)));
    fixture.apply(
        7,
        122,
        &AuthoritativeCommand::CompleteCertificateOrder(fixture.retry(order_id, 2, 202, 200)),
    )?;
    let queued = fixture
        .repository
        .certificate_order(order_id)?
        .ok_or("queued order missing")?;
    assert_eq!(queued.state, CertificateOrderState::Queued);
    assert_eq!(queued.attempt_count, 2);
    assert!(queued.claim.is_none());

    fixture.apply(
        8,
        200,
        &AuthoritativeCommand::ClaimCertificateOrder(fixture.claim(order_id, 3, 303, 260)),
    )?;
    fixture.apply(
        9,
        201,
        &AuthoritativeCommand::CompleteCertificateOrder(CompleteCertificateOrder {
            order_id,
            claim_generation: 3,
            worker_node_id: fixture.node,
            worker_incarnation: 1,
            fence: 303,
            outcome: CertificateOrderCompletion::Issued {
                certificate: fixture.certificate,
                not_before: UnixMicros::new(190),
                not_after: UnixMicros::new(1_000),
                result_digest: [44; 32],
            },
        }),
    )?;
    let complete = fixture
        .repository
        .certificate_order(order_id)?
        .ok_or("complete order missing")?;
    assert_eq!(complete.state, CertificateOrderState::Complete);
    assert_eq!(complete.certificate, Some(fixture.certificate));
    assert!(complete.claim.is_none());
    Ok(())
}

#[test]
fn configuration_rejects_unsorted_names_and_http_publisher_secrets()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new()?;
    let mut invalid = fixture.configuration(AcmeConfigurationId::from_bytes([20; 16])?)?;
    invalid.certificate_names = BoundedItems::new(
        vec!["z.example.test".to_owned(), "a.example.test".to_owned()],
        256,
    )?;
    assert!(matches!(
        fixture.apply(2, 2, &AuthoritativeCommand::ConfigureAcme(invalid)),
        Err(RepositoryError::InvalidCommand)
    ));

    let mut invalid = fixture.configuration(AcmeConfigurationId::from_bytes([21; 16])?)?;
    invalid.challenge_kind = AcmeChallengeKind::Http01;
    assert!(matches!(
        fixture.apply(2, 2, &AuthoritativeCommand::ConfigureAcme(invalid)),
        Err(RepositoryError::InvalidCommand)
    ));
    Ok(())
}

struct Fixture {
    repository: AuthoritativeRepository,
    administrator: PrincipalId,
    node: NodeId,
    account_key: SecretGenerationReference,
    challenge_settings: SecretGenerationReference,
    certificate: SecretGenerationReference,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let administrator = PrincipalId::from_bytes([2; 16])?;
        let node = NodeId::from_bytes([6; 16])?;
        let database = PartitionDatabase::open(
            std::path::Path::new(":memory:"),
            PartitionId::from_bytes([1; 16])?,
            UnixMicros::new(1),
        )?;
        let mut fixture = Self {
            repository: AuthoritativeRepository::new(database),
            administrator,
            node,
            account_key: SecretGenerationReference {
                secret_id: [7; 16],
                generation: 1,
            },
            challenge_settings: SecretGenerationReference {
                secret_id: [8; 16],
                generation: 1,
            },
            certificate: SecretGenerationReference {
                secret_id: [9; 16],
                generation: 1,
            },
        };
        fixture.apply(
            1,
            1,
            &AuthoritativeCommand::BootstrapMesh(BootstrapMesh {
                mesh_id: MeshId::from_bytes([3; 16])?,
                mesh_name: RecordName::new("ACME proof")?,
                administrator_id: administrator,
                administrator_name: RecordName::new("Administrator")?,
                administrator_role_id: RoleId::from_bytes([4; 16])?,
                host_id: HostId::from_bytes([5; 16])?,
                host_name: RecordName::new("Host")?,
                node_id: node,
                node_name: RecordName::new("Gateway")?,
                partition_name: RecordName::new("Authority")?,
            }),
        )?;
        fixture.insert_secret(ACME_ACCOUNT_KEY_SECRET_KIND, fixture.account_key)?;
        fixture.insert_secret(
            ACME_CHALLENGE_SETTINGS_SECRET_KIND,
            fixture.challenge_settings,
        )?;
        fixture.insert_secret(PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND, fixture.certificate)?;
        Ok(fixture)
    }

    fn configuration(
        &self,
        config_id: AcmeConfigurationId,
    ) -> Result<ConfigureAcme, Box<dyn std::error::Error>> {
        Ok(ConfigureAcme {
            config_id,
            directory_url: "https://acme.example.test/directory".to_owned(),
            account_key: self.account_key,
            challenge_kind: AcmeChallengeKind::Dns01,
            challenge_settings: Some(self.challenge_settings),
            certificate_names: BoundedItems::new(
                vec![
                    "files.example.test".to_owned(),
                    "www.example.test".to_owned(),
                ],
                256,
            )?,
        })
    }

    fn claim(
        &self,
        order_id: CertificateOrderId,
        generation: u64,
        fence: u64,
        lease_expires_at: i64,
    ) -> ClaimCertificateOrder {
        ClaimCertificateOrder {
            order_id,
            claim_generation: generation,
            worker_node_id: self.node,
            worker_incarnation: 1,
            fence,
            lease_expires_at: UnixMicros::new(lease_expires_at),
        }
    }

    fn renew(
        &self,
        order_id: CertificateOrderId,
        generation: u64,
        fence: u64,
        lease_expires_at: i64,
    ) -> RenewCertificateOrder {
        RenewCertificateOrder {
            order_id,
            claim_generation: generation,
            worker_node_id: self.node,
            worker_incarnation: 1,
            fence,
            lease_expires_at: UnixMicros::new(lease_expires_at),
        }
    }

    fn retry(
        &self,
        order_id: CertificateOrderId,
        generation: u64,
        fence: u64,
        retry_at: i64,
    ) -> CompleteCertificateOrder {
        CompleteCertificateOrder {
            order_id,
            claim_generation: generation,
            worker_node_id: self.node,
            worker_incarnation: 1,
            fence,
            outcome: CertificateOrderCompletion::Retry {
                failure_digest: [33; 32],
                retry_at: UnixMicros::new(retry_at),
            },
        }
    }

    fn insert_secret(
        &self,
        kind: u16,
        secret: SecretGenerationReference,
    ) -> Result<(), rusqlite::Error> {
        self.repository.database.connection().execute(
            "INSERT INTO secret_generations(
                secret_kind, secret_id, generation, format_version, nonce, ciphertext,
                ciphertext_digest, created_at, revision
             ) VALUES (?1, ?2, ?3, 1, ?4, ?5, ?6, 1, 1)",
            params![
                i64::from(kind),
                secret.secret_id.as_slice(),
                i64::try_from(secret.generation).unwrap_or(i64::MAX),
                [1_u8; 24].as_slice(),
                [2_u8; 17].as_slice(),
                [3_u8; 32].as_slice(),
            ],
        )?;
        Ok(())
    }

    fn apply(
        &mut self,
        index: u64,
        occurred_at: i64,
        command: &AuthoritativeCommand,
    ) -> Result<super::CommandReceipt, RepositoryError> {
        self.repository.apply_committed(
            LogPosition { index, term: 1 },
            CommandContext {
                operation_id: OperationId::from_bytes([u8::try_from(index).unwrap_or(250); 16])
                    .map_err(|_| RepositoryError::InvalidCommand)?,
                actor_principal_id: self.administrator,
                audit_event_id: AuditEventId::from_bytes(
                    [u8::try_from(index + 100).unwrap_or(251); 16],
                )
                .map_err(|_| RepositoryError::InvalidCommand)?,
                occurred_at: UnixMicros::new(occurred_at),
                expected_revision: Some(Revision::new(index - 1)),
            },
            command,
        )
    }
}
