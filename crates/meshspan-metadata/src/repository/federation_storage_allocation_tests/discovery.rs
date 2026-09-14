// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::FederationAllocationQuery;

#[test]
fn allocation_discovery_is_indexed_paged_and_filtered() -> Result<(), Box<dyn std::error::Error>> {
    let (fixture, query) = prepared()?;
    let ids = fixture.ids;
    let repository = &fixture.repository;
    let first = allocation(ids, 30, 31, 1, 20, 10, 20)?;
    let second = allocation(ids, 32, 33, 1, 30, 10, 20)?;
    assert_index(repository, ids)?;
    let page = repository.federation_storage_allocations_page(query)?;
    assert_eq!(
        page.items
            .iter()
            .map(|item| item.allocation())
            .collect::<Vec<_>>(),
        vec![first]
    );
    let continuation = page.next.ok_or("continuation")?;
    assert_eq!(continuation.allocation_id, first.allocation_id());
    let next = repository.federation_storage_allocations_page(FederationAllocationQuery {
        after: Some(continuation),
        ..query
    })?;
    assert_eq!(
        next.items
            .iter()
            .map(|item| item.allocation())
            .collect::<Vec<_>>(),
        vec![second]
    );
    assert!(next.next.is_none());
    let filtered = repository.federation_storage_allocations_page(FederationAllocationQuery {
        required_bytes: 25,
        ..query
    })?;
    assert_eq!(
        filtered
            .items
            .iter()
            .map(|item| item.allocation())
            .collect::<Vec<_>>(),
        vec![second]
    );
    assert!(filtered.next.is_none());
    for exhausted in [
        FederationAllocationQuery {
            required_bytes: 31,
            ..query
        },
        FederationAllocationQuery {
            observed_at: UnixMicros::new(20),
            ..query
        },
    ] {
        let page = repository.federation_storage_allocations_page(exhausted)?;
        assert!(page.items.is_empty());
        assert!(page.next.is_none());
    }
    Ok(())
}

#[test]
fn allocation_discovery_rejects_wrong_authority_and_stale_continuation()
-> Result<(), Box<dyn std::error::Error>> {
    let (mut fixture, query) = prepared()?;
    let ids = fixture.ids;
    let repository = &mut fixture.repository;
    let first = allocation(ids, 30, 31, 1, 20, 10, 20)?;
    let second = allocation(ids, 32, 33, 1, 30, 10, 20)?;
    let continuation = repository
        .federation_storage_allocations_page(query)?
        .next
        .ok_or("continuation")?;
    for forbidden in [
        FederationAllocationQuery {
            remote_mesh_id: MeshId::from_bytes([98; 16])?,
            ..query
        },
        FederationAllocationQuery {
            grant_id: FederationGrantId::from_bytes([99; 16])?,
            ..query
        },
    ] {
        assert!(matches!(
            repository.federation_storage_allocations_page(forbidden),
            Err(RepositoryError::InvalidCommand)
        ));
    }
    apply(
        repository,
        7,
        context(43, ids.administrator, 15, 6)?,
        &AuthoritativeCommand::RevokeFederationStorageAllocation(
            RevokeFederationStorageAllocation {
                allocation_id: second.allocation_id(),
                expected_allocation_revision: Revision::new(6),
                reason: "Withdraw discovered allocation".into(),
            },
        ),
    )?;
    assert!(matches!(
        repository.federation_storage_allocations_page(FederationAllocationQuery {
            after: Some(continuation),
            ..query
        }),
        Err(RepositoryError::StaleRevision)
    ));
    let fresh = repository.federation_storage_allocations_page(FederationAllocationQuery {
        snapshot_revision: Revision::new(7),
        ..query
    })?;
    assert_eq!(
        fresh
            .items
            .iter()
            .map(|item| item.allocation())
            .collect::<Vec<_>>(),
        vec![first]
    );
    assert!(fresh.next.is_none());
    Ok(())
}

fn prepared() -> Result<(Fixture, FederationAllocationQuery), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::open()?;
    let ids = fixture.ids;
    prepare_storage_authority(&mut fixture.repository, ids)?;
    apply_allocation(
        &mut fixture.repository,
        5,
        34,
        ids,
        allocation(ids, 30, 31, 1, 20, 10, 20)?,
    )?;
    apply_allocation(
        &mut fixture.repository,
        6,
        35,
        ids,
        allocation(ids, 32, 33, 1, 30, 10, 20)?,
    )?;
    let query = FederationAllocationQuery {
        relationship_id: ids.relationship,
        remote_mesh_id: ids.remote_mesh,
        grant_id: ids.grant,
        required_bytes: 10,
        observed_at: UnixMicros::new(15),
        snapshot_revision: Revision::new(6),
        after: None,
        limit: PageLimit::new(1)?,
    };
    Ok((fixture, query))
}

fn assert_index(
    repository: &AuthoritativeRepository,
    ids: FixtureIds,
) -> Result<(), Box<dyn std::error::Error>> {
    let sql = format!(
        "EXPLAIN QUERY PLAN {}",
        super::super::federation_allocation_page::CANDIDATES_SQL
    );
    let mut statement = repository.database.connection().prepare(&sql)?;
    let plan = statement
        .query_map(
            rusqlite::params![
                ids.grant.as_bytes().as_slice(),
                15,
                10,
                0,
                0,
                [0_u8; 16].as_slice(),
                2
            ],
            |row| row.get::<_, String>(3),
        )?
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");
    assert!(
        plan.contains("SEARCH l USING COVERING INDEX federation_storage_authority_discovery"),
        "{plan}"
    );
    assert!(plan.contains("SEARCH a USING INDEX"), "{plan}");
    assert!(!plan.contains("TEMP B-TREE"), "{plan}");
    Ok(())
}
