// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::{LocalDatabase, RecordFederationStorageSeal, RegisterCleanupAttestationKey};
use ed25519_dalek::Signer;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

struct Prepared {
    fixture: Fixture,
    allocation: FederationStorageAllocation,
    signed: RecordFederationStorageSeal,
    key: SigningKey,
}

impl Prepared {
    fn open() -> TestResult<Self> {
        let mut fixture = Fixture::open()?;
        prepare_storage_authority(&mut fixture.repository, fixture.ids)?;
        let allocation = allocation(fixture.ids, 30, 31, 1, 50, 10, 90)?;
        apply_allocation(&mut fixture.repository, 5, 32, fixture.ids, allocation)?;
        let key = SigningKey::from_bytes(&[91; 32]);
        apply(
            &mut fixture.repository,
            6,
            context(33, fixture.ids.administrator, 15, 5)?,
            &AuthoritativeCommand::RegisterCleanupAttestationKey(RegisterCleanupAttestationKey {
                node_id: fixture.ids.provider_node,
                generation: 1,
                verifying_key: key.verifying_key().to_bytes(),
            }),
        )?;
        let authority = fixture
            .repository
            .active_federation_storage_allocation_authority(authority_request(
                fixture.ids,
                allocation,
                20,
                15,
            ))?
            .ok_or("authority")?;
        let mut local = LocalDatabase::open(
            &fixture.file_path.with_file_name("sealed-local.sqlite3"),
            fixture.ids.provider_node,
            UnixMicros::new(15),
        )?;
        local.reserve_federated_backup_capacity(
            authority,
            meshspan_contracts::BackupObjectIdentity {
                destination_id: meshspan_domain::BackupDestinationId::from_bytes([92; 16])?,
                backup_id: meshspan_domain::BackupId::from_bytes([93; 16])?,
                provider_generation: 1,
                byte_length: 20,
                digest: [94; 32],
            },
        )?;
        let mut signed = RecordFederationStorageSeal {
            provider_mesh_id: fixture.ids.local_mesh,
            seal: local.seal_federated_storage_capacity(authority)?,
            node_incarnation: 1,
            key_generation: 1,
            signature: [0; 64],
        };
        signed.signature = key.sign(&signed.signing_payload()).to_bytes();
        Ok(Self {
            fixture,
            allocation,
            signed,
            key,
        })
    }

    fn record(&mut self, value: RecordFederationStorageSeal) -> Result<(), RepositoryError> {
        let revision = self.fixture.repository.current_revision()?.get();
        let marker = u8::try_from(150 + revision).map_err(|_| RepositoryError::InvalidCommand)?;
        apply(
            &mut self.fixture.repository,
            revision + 1,
            CommandContext {
                operation_id: OperationId::from_bytes([marker; 16])
                    .map_err(|_| RepositoryError::InvalidCommand)?,
                actor_principal_id: self.fixture.ids.administrator,
                audit_event_id: AuditEventId::from_bytes([marker; 16])
                    .map_err(|_| RepositoryError::InvalidCommand)?,
                occurred_at: UnixMicros::new(16),
                expected_revision: Some(Revision::new(revision)),
            },
            &AuthoritativeCommand::RecordFederationStorageSeal(value),
        )
    }
}

#[test]
fn signed_capacity_seal_reassigns_only_unused_allowance_and_preserves_read_authority() -> TestResult
{
    let mut prepared = Prepared::open()?;
    let ids = prepared.fixture.ids;
    let second = allocation(ids, 97, 98, 1, 30, 10, 90)?;
    assert!(matches!(
        prepared.fixture.repository.apply_committed(
            position(7),
            context(99, ids.administrator, 16, 6)?,
            &issue(second)
        ),
        Err(RepositoryError::CapacityExceeded)
    ));
    prepared.record(prepared.signed)?;
    apply_allocation(&mut prepared.fixture.repository, 8, 99, ids, second)?;
    let over = allocation(ids, 100, 101, 1, 1, 10, 90)?;
    assert!(matches!(
        prepared.fixture.repository.apply_committed(
            position(9),
            context(102, ids.administrator, 17, 8)?,
            &issue(over)
        ),
        Err(RepositoryError::CapacityExceeded)
    ));
    let authority = prepared
        .fixture
        .repository
        .active_federation_storage_allocation_authority(authority_request(
            ids,
            prepared.allocation,
            20,
            20,
        ))?
        .ok_or("retained read authority")?;
    assert_eq!(authority.write_limit_bytes(), 0);
    assert_eq!(authority.allocation(), prepared.allocation);
    let findings = prepared
        .fixture
        .repository
        .check_invariants(PageLimit::new(100)?)?;
    assert!(findings.findings.is_empty(), "{findings:?}");
    let reopened = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &prepared.fixture.file_path,
        UnixMicros::new(21),
    )?);
    assert_eq!(
        reopened
            .federation_storage_allocation(second.allocation_id())?
            .ok_or("reassigned allowance")?
            .allocation,
        second
    );
    let authority = reopened
        .active_federation_storage_allocation_authority(authority_request(
            ids,
            prepared.allocation,
            20,
            21,
        ))?
        .ok_or("reopened authority")?;
    assert_eq!(authority.write_limit_bytes(), 0);
    Ok(())
}

#[test]
fn signed_capacity_seal_rejects_forged_identity_incarnation_and_larger_credit() -> TestResult {
    let mut prepared = Prepared::open()?;
    for mutation in 0..7 {
        let mut forged = prepared.signed;
        match mutation {
            0 => forged.signature[0] ^= 1,
            1 => forged.provider_mesh_id = MeshId::from_bytes([103; 16])?,
            2 => forged.seal.target_generation += 1,
            3 => forged.node_incarnation += 1,
            4 => forged.key_generation += 1,
            5 => forged.seal.ceiling_bytes = 51,
            6 => forged.seal.sequence = 0,
            _ => unreachable!(),
        }
        if mutation != 0 {
            forged.signature = prepared.key.sign(&forged.signing_payload()).to_bytes();
        }
        assert!(matches!(
            prepared.record(forged),
            Err(RepositoryError::InvalidCommand)
        ));
        assert_eq!(
            prepared.fixture.repository.current_revision()?,
            Revision::new(6)
        );
    }
    prepared.record(prepared.signed)?;
    let mut raised = prepared.signed;
    raised.seal.ceiling_bytes = 30;
    raised.seal.sequence = 2;
    raised.signature = prepared.key.sign(&raised.signing_payload()).to_bytes();
    assert!(matches!(
        prepared.record(raised),
        Err(RepositoryError::InvalidCommand)
    ));
    Ok(())
}

#[test]
fn signed_capacity_seal_codec_binds_every_field_and_rejects_trailing_bytes() -> TestResult {
    let prepared = Prepared::open()?;
    let command = AuthoritativeCommand::RecordFederationStorageSeal(prepared.signed);
    let context = context(104, prepared.fixture.ids.administrator, 16, 6)?;
    let mut encoded = crate::encode_authoritative_command(context, &command)?;
    let decoded = crate::decode_authoritative_command(&encoded)?;
    assert_eq!(decoded.context, context);
    assert_eq!(decoded.command, command);
    encoded.push(0);
    assert!(crate::decode_authoritative_command(&encoded).is_err());
    let key = AuthoritativeCommand::RegisterCleanupAttestationKey(RegisterCleanupAttestationKey {
        node_id: prepared.fixture.ids.provider_node,
        generation: 1,
        verifying_key: prepared.key.verifying_key().to_bytes(),
    });
    let encoded = crate::encode_authoritative_command(context, &key)?;
    assert_eq!(crate::decode_authoritative_command(&encoded)?.command, key);
    Ok(())
}

#[test]
fn signed_capacity_seal_survives_renewal_and_reserves_retained_charges_first() -> TestResult {
    let mut prepared = Prepared::open()?;
    prepared.record(prepared.signed)?;
    let ids = prepared.fixture.ids;
    // The new allocation sorts before the retained seal; ordering must not lend its floor.
    let second = allocation(ids, 24, 25, 1, 30, 10, 90)?;
    apply_allocation(&mut prepared.fixture.repository, 8, 110, ids, second)?;
    let successor = super::renewal::renew(&mut prepared.fixture, 9, 40)?;
    for (allocation, expected_limit) in [(prepared.allocation, 0), (second, 20)] {
        let mut request = authority_request(ids, allocation, 1, 35);
        request.grant_id = successor;
        let authority = prepared
            .fixture
            .repository
            .active_federation_storage_allocation_authority(request)?
            .ok_or("renewed authority")?;
        assert_eq!(authority.write_limit_bytes(), expected_limit);
    }
    Ok(())
}

#[test]
fn signed_capacity_seal_retains_credit_after_key_rotation() -> TestResult {
    let mut prepared = Prepared::open()?;
    prepared.record(prepared.signed)?;
    let ids = prepared.fixture.ids;
    let next_key = SigningKey::from_bytes(&[117; 32]);
    apply(
        &mut prepared.fixture.repository,
        8,
        context(118, ids.administrator, 17, 7)?,
        &AuthoritativeCommand::RegisterCleanupAttestationKey(RegisterCleanupAttestationKey {
            node_id: ids.provider_node,
            generation: 2,
            verifying_key: next_key.verifying_key().to_bytes(),
        }),
    )?;
    let second = allocation(ids, 119, 120, 1, 30, 10, 90)?;
    apply_allocation(&mut prepared.fixture.repository, 9, 121, ids, second)?;
    super::renewal::renew(&mut prepared.fixture, 10, 50)?;
    let mut new_seal = prepared.signed;
    new_seal.seal.ceiling_bytes = 10;
    new_seal.seal.sequence = 2;
    new_seal.signature = prepared.key.sign(&new_seal.signing_payload()).to_bytes();
    assert!(matches!(
        prepared.record(new_seal),
        Err(RepositoryError::InvalidCommand)
    ));
    assert_eq!(
        prepared.fixture.repository.current_revision()?,
        Revision::new(10)
    );
    Ok(())
}

#[test]
fn signed_capacity_seal_maintenance_scan_is_node_scoped_and_indexed() -> TestResult {
    let mut prepared = Prepared::open()?;
    prepared.record(prepared.signed)?;
    let ids = prepared.fixture.ids;
    let page = prepared
        .fixture
        .repository
        .federation_storage_maintenance_page(ids.provider_node, None, UnixMicros::new(20))?;
    assert_eq!(page.items.len(), 1);
    assert!(page.next.is_none());
    let item = page.items.first().ok_or("maintenance item")?;
    assert_eq!(item.accepted_seal, Some((20, 1)));
    assert_eq!(item.authority.allocation(), prepared.allocation);
    assert!(
        prepared
            .fixture
            .repository
            .federation_storage_maintenance_page(
                NodeId::from_bytes([122; 16])?,
                None,
                UnixMicros::new(20)
            )?
            .items
            .is_empty()
    );
    let sql = format!(
        "EXPLAIN QUERY PLAN {}",
        super::super::federation_storage_maintenance::ALLOCATIONS_SQL
    );
    let mut query = prepared
        .fixture
        .repository
        .database
        .connection()
        .prepare(&sql)?;
    let plan = query
        .query_map(
            rusqlite::params![
                ids.provider_node.as_bytes().as_slice(),
                [0_u8; 16].as_slice(),
                0,
                0,
                [0_u8; 16].as_slice()
            ],
            |row| row.get::<_, String>(3),
        )?
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");
    assert!(
        plan.contains("INDEX federation_storage_allocations_maintenance"),
        "{plan}"
    );
    assert!(
        !plan.contains("SCAN ") && !plan.contains("TEMP B-TREE"),
        "{plan}"
    );
    Ok(())
}

#[test]
fn signed_capacity_seal_credit_lookup_is_indexed() -> TestResult {
    let mut prepared = Prepared::open()?;
    prepared.record(prepared.signed)?;
    let sql = format!(
        "EXPLAIN QUERY PLAN {}",
        super::super::federation_storage_seal::GRANT_SEALS_SQL
    );
    let mut query = prepared
        .fixture
        .repository
        .database
        .connection()
        .prepare(&sql)?;
    let plan = query
        .query_map([prepared.fixture.ids.grant.as_bytes().as_slice()], |row| {
            row.get::<_, String>(3)
        })?
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");
    assert!(
        plan.contains("SEARCH l USING COVERING INDEX federation_storage_authority_by_grant"),
        "{plan}"
    );
    assert!(!plan.contains("SCAN "), "{plan}");
    assert!(!plan.contains("TEMP B-TREE"), "{plan}");
    Ok(())
}

#[test]
fn signed_capacity_seal_corruption_cannot_release_allowance() -> TestResult {
    let mut prepared = Prepared::open()?;
    prepared.record(prepared.signed)?;
    prepared.fixture.repository.database.connection().execute(
        "UPDATE federation_storage_seals SET ceiling_bytes=10,sequence=2,revision=revision+1
         WHERE allocation_id=?1",
        [prepared.allocation.allocation_id().as_bytes().as_slice()],
    )?;
    let ids = prepared.fixture.ids;
    let second = allocation(ids, 114, 115, 1, 40, 10, 90)?;
    assert!(matches!(
        prepared.fixture.repository.apply_committed(
            position(8),
            context(116, ids.administrator, 17, 7)?,
            &issue(second)
        ),
        Err(RepositoryError::CorruptState)
    ));
    assert_eq!(
        prepared.fixture.repository.current_revision()?,
        Revision::new(7)
    );
    let error = super::renewal::renew(&mut prepared.fixture, 8, 50)
        .err()
        .ok_or("renewal accepted corrupt credit")?;
    assert!(matches!(
        error.downcast_ref::<RepositoryError>(),
        Some(RepositoryError::CorruptState)
    ));
    assert_eq!(
        prepared.fixture.repository.current_revision()?,
        Revision::new(7)
    );
    Ok(())
}

#[test]
fn signed_capacity_seal_commit_failure_cannot_release_allowance() -> TestResult {
    let mut prepared = Prepared::open()?;
    let ids = prepared.fixture.ids;
    prepared
        .fixture
        .repository
        .database
        .connection()
        .execute_batch(
            "CREATE TRIGGER inject_seal_failure BEFORE INSERT ON federation_storage_seals
         BEGIN SELECT RAISE(ABORT, 'injected authoritative seal failure'); END;",
        )?;
    assert!(prepared.record(prepared.signed).is_err());
    assert_eq!(
        prepared.fixture.repository.current_revision()?,
        Revision::new(6)
    );
    let second = allocation(ids, 111, 112, 1, 1, 10, 90)?;
    assert!(matches!(
        prepared.fixture.repository.apply_committed(
            position(7),
            context(113, ids.administrator, 16, 6)?,
            &issue(second)
        ),
        Err(RepositoryError::CapacityExceeded)
    ));
    prepared
        .fixture
        .repository
        .database
        .connection()
        .execute_batch("DROP TRIGGER inject_seal_failure")?;
    prepared.record(prepared.signed)?;
    apply_allocation(&mut prepared.fixture.repository, 8, 113, ids, second)?;
    Ok(())
}
