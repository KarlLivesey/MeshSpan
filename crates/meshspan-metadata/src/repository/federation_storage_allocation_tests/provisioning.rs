// SPDX-License-Identifier: GPL-2.0-only

use super::*;

#[test]
fn provisioning_grant_scan_is_indexed_and_excludes_expired_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::open()?;
    prepare_storage_authority(&mut fixture.repository, fixture.ids)?;
    let page = fixture
        .repository
        .federation_storage_grants_for_provisioning(
            None,
            PageLimit::new(1)?,
            UnixMicros::new(20),
        )?;
    assert_eq!(page.items.len(), 1);
    assert_eq!(
        page.items.first().ok_or("storage grant")?.grant.grant_id(),
        fixture.ids.grant
    );
    assert!(page.next.is_none());
    for (after, now) in [(Some(fixture.ids.grant), 20), (None, 200)] {
        let page = fixture
            .repository
            .federation_storage_grants_for_provisioning(
                after,
                PageLimit::new(1)?,
                UnixMicros::new(now),
            )?;
        assert!(page.items.is_empty());
        assert!(page.next.is_none());
    }
    let sql = format!(
        "EXPLAIN QUERY PLAN {}",
        super::super::federation_storage_provisioning::GRANTS_SQL
    );
    let mut statement = fixture.repository.database.connection().prepare(&sql)?;
    let plan = statement
        .query_map(
            rusqlite::params![
                fixture.ids.local_mesh.as_bytes().as_slice(),
                [0_u8; 16].as_slice(),
                2,
            ],
            |row| row.get::<_, String>(3),
        )?
        .collect::<Result<Vec<_>, _>>()?
        .join("\n");
    assert!(
        plan.contains(
            "SEARCH federation_grants USING COVERING INDEX federation_grants_by_resource"
        ),
        "{plan}"
    );
    assert!(!plan.contains("TEMP B-TREE"), "{plan}");
    Ok(())
}
