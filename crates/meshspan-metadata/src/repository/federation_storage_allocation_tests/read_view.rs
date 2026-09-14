// SPDX-License-Identifier: GPL-2.0-only

//! Per-boundary backup permission reads must not combine different committed states.

use super::*;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

#[test]
fn backup_read_view_survives_an_unrelated_allocation_commit() -> TestResult {
    let mut fixture = Fixture::open()?;
    prepare_storage_authority(&mut fixture.repository, fixture.ids)?;
    let original = allocation(fixture.ids, 30, 31, 1, 20, 10, 100)?;
    apply_allocation(&mut fixture.repository, 5, 34, fixture.ids, original)?;
    let reader = open_reader(&fixture)?;
    reader.with_read_view(|view| -> TestResult {
        assert_eq!(view.current_revision()?, Revision::new(5));
        let other = allocation(fixture.ids, 32, 33, 1, 20, 10, 100)?;
        apply_allocation(&mut fixture.repository, 6, 35, fixture.ids, other)?;
        let authority = view
            .active_federation_storage_allocation_authority(authority_request(
                fixture.ids,
                original,
                20,
                20,
            ))?
            .ok_or("unrelated commit removed valid backup authority")?;
        assert_eq!(authority.allocation(), original);
        assert_eq!(view.current_revision()?, Revision::new(5));
        Ok(())
    })??;
    assert_eq!(reader.current_revision()?, Revision::new(6));
    Ok(())
}

#[test]
fn backup_read_view_ends_before_the_next_revocation_check() -> TestResult {
    let mut fixture = Fixture::open()?;
    prepare_storage_authority(&mut fixture.repository, fixture.ids)?;
    let original = allocation(fixture.ids, 30, 31, 1, 20, 10, 100)?;
    apply_allocation(&mut fixture.repository, 5, 34, fixture.ids, original)?;
    let reader = open_reader(&fixture)?;
    let request = authority_request(fixture.ids, original, 20, 20);
    reader.with_read_view(|view| -> TestResult {
        assert_eq!(view.current_revision()?, Revision::new(5));
        apply(
            &mut fixture.repository,
            6,
            context(35, fixture.ids.administrator, 20, 5)?,
            &AuthoritativeCommand::RevokeFederationGrant(crate::RevokeFederationGrant {
                grant_id: fixture.ids.grant,
                expected_authority_epoch: 1,
                reason: "Withdraw backup access".into(),
            }),
        )?;
        assert!(
            view.active_federation_storage_allocation_authority(request)?
                .is_some()
        );
        assert_eq!(view.current_revision()?, Revision::new(5));
        Ok(())
    })??;
    reader.with_read_view(|view| -> TestResult {
        assert_eq!(view.current_revision()?, Revision::new(6));
        assert!(
            view.active_federation_storage_allocation_authority(request)?
                .is_none()
        );
        Ok(())
    })??;
    Ok(())
}

fn open_reader(fixture: &Fixture) -> TestResult<AuthoritativeRepository> {
    Ok(AuthoritativeRepository::new(
        PartitionDatabase::open_existing(&fixture.file_path, UnixMicros::new(20))?,
    ))
}
