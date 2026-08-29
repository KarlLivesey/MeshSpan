// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::BoundedItems;
use meshspan_domain::{
    ActivationId, ActivationPolicyId, AssuranceLevel, DurationMicros, GrantId, GroupId, ObjectId,
    OwnerSetId, PrincipalId, Rights, SessionId, UnixMicros,
};

use super::access_evaluation_tests::{apply, build_fixture, issue_session};
use super::{PageLimit, RepositoryError};
use crate::{
    ActivateGrant, AuthoritativeCommand, GrantInheritance, GrantPermission, PermissionScope,
    ReplaceObjectOwners, RevokeAccessActivation, RevokePermissionGrant,
};

#[test]
fn owner_pages_bind_the_current_immutable_set_and_reject_stale_continuation()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = build_fixture(false)?;
    let administrator = fixture.administrator;
    let user = fixture.user;
    let second_user = fixture.second_user;
    let file = fixture.file;
    let initial = fixture
        .repository
        .object_owners(fixture.file, None, PageLimit::new(1)?)?
        .ok_or("file owner set was absent")?;
    assert_eq!(initial.items[0].owner_principal_id, fixture.second_user);
    assert!(initial.next.is_none());

    let owner_set_id = OwnerSetId::from_bytes([70; 16])?;
    apply(
        &mut fixture,
        administrator,
        200,
        AuthoritativeCommand::ReplaceObjectOwners(ReplaceObjectOwners {
            object_id: file,
            owner_set_id,
            owners: BoundedItems::new(vec![user, second_user], 1_024)?,
        }),
    )?;
    let first = fixture
        .repository
        .object_owners(fixture.file, None, PageLimit::new(1)?)?
        .ok_or("replacement owner set was absent")?;
    assert_eq!(first.items.len(), 1);
    let cursor = first.next.ok_or("owner page omitted continuation")?;
    let second = fixture
        .repository
        .object_owners(fixture.file, Some(cursor), PageLimit::new(1)?)?
        .ok_or("replacement owner set disappeared")?;
    assert_eq!(second.items.len(), 1);
    assert!(second.next.is_none());

    apply(
        &mut fixture,
        administrator,
        201,
        AuthoritativeCommand::ReplaceObjectOwners(ReplaceObjectOwners {
            object_id: file,
            owner_set_id: OwnerSetId::from_bytes([71; 16])?,
            owners: BoundedItems::new(vec![second_user], 1_024)?,
        }),
    )?;
    assert!(matches!(
        fixture
            .repository
            .object_owners(fixture.file, Some(cursor), PageLimit::new(1)?),
        Err(RepositoryError::StaleRevision)
    ));
    Ok(())
}

#[test]
fn active_grants_page_by_exact_scope_and_subject_and_hide_revoked_rows()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = build_fixture(false)?;
    let administrator = fixture.administrator;
    let user = fixture.user;
    let volume = fixture.volume;
    let file = fixture.file;
    let outer = GroupId::from_bytes([12; 16])?.principal_id();
    let scope = PermissionScope::Object {
        volume_id: fixture.volume,
        object_id: fixture.folder,
    };
    apply(
        &mut fixture,
        administrator,
        200,
        AuthoritativeCommand::GrantPermission(GrantPermission {
            grant_id: GrantId::from_bytes([26; 16])?,
            subject_principal_id: user,
            scope,
            rights: Rights::WRITE_DATA,
            inheritance: GrantInheritance::Object,
            valid_from: None,
            valid_until: None,
            activation_policy_id: None,
        }),
    )?;
    apply(
        &mut fixture,
        administrator,
        201,
        AuthoritativeCommand::GrantPermission(GrantPermission {
            grant_id: GrantId::from_bytes([27; 16])?,
            subject_principal_id: outer,
            scope: PermissionScope::Object {
                volume_id: volume,
                object_id: file,
            },
            rights: Rights::LIST,
            inheritance: GrantInheritance::ObjectAndDescendants,
            valid_from: None,
            valid_until: None,
            activation_policy_id: None,
        }),
    )?;

    let first = fixture
        .repository
        .permission_grants_for_scope(scope, None, PageLimit::new(1)?)?;
    assert_eq!(first.items.len(), 1);
    let cursor = first.next.ok_or("scope page omitted continuation")?;
    let second =
        fixture
            .repository
            .permission_grants_for_scope(scope, Some(cursor), PageLimit::new(1)?)?;
    assert_eq!(second.items.len(), 1);
    assert!(second.next.is_none());
    assert!(matches!(
        fixture.repository.permission_grants_for_scope(
            PermissionScope::Global,
            Some(cursor),
            PageLimit::new(1)?
        ),
        Err(RepositoryError::StaleRevision)
    ));

    let subject =
        fixture
            .repository
            .permission_grants_for_subject(outer, None, PageLimit::new(1)?)?;
    assert_eq!(subject.items.len(), 1);
    let subject_cursor = subject.next.ok_or("subject page omitted continuation")?;
    assert_eq!(
        fixture
            .repository
            .permission_grants_for_subject(outer, Some(subject_cursor), PageLimit::new(1)?,)?
            .items
            .len(),
        1
    );

    apply(
        &mut fixture,
        administrator,
        202,
        AuthoritativeCommand::RevokePermissionGrant(RevokePermissionGrant {
            grant_id: GrantId::from_bytes([26; 16])?,
            reason: "No longer required".to_owned(),
        }),
    )?;
    let remaining =
        fixture
            .repository
            .permission_grants_for_scope(scope, None, PageLimit::new(10)?)?;
    assert_eq!(remaining.items.len(), 1);
    assert_eq!(remaining.items[0].grant_id, GrantId::from_bytes([25; 16])?);
    Ok(())
}

#[test]
fn activation_pages_bind_principal_and_time_and_never_claim_access_authority()
-> Result<(), Box<dyn std::error::Error>> {
    let mut fixture = build_fixture(true)?;
    let token_digest = [73; 32];
    let user = fixture.user;
    issue_session(
        &mut fixture,
        user,
        SessionId::from_bytes([74; 16])?,
        token_digest,
    )?;
    for (identity, now) in [(75, 200), (76, 201)] {
        apply(
            &mut fixture,
            user,
            now,
            AuthoritativeCommand::ActivateGrant(ActivateGrant {
                activation_id: ActivationId::from_bytes([identity; 16])?,
                principal_id: user,
                grant_id: GrantId::from_bytes([25; 16])?,
                policy_id: ActivationPolicyId::from_bytes([24; 16])?,
                reason: "Temporary task".to_owned(),
                duration: DurationMicros::new(100),
                session_expires_at: UnixMicros::new(900),
                assurance: AssuranceLevel::MultiFactor,
                authentication_digest: token_digest,
            }),
        )?;
    }

    let first = fixture.repository.unrevoked_access_activations(
        user,
        UnixMicros::new(250),
        None,
        PageLimit::new(1)?,
    )?;
    assert_eq!(first.items.len(), 1);
    let cursor = first.next.ok_or("activation page omitted continuation")?;
    let second = fixture.repository.unrevoked_access_activations(
        user,
        UnixMicros::new(250),
        Some(cursor),
        PageLimit::new(1)?,
    )?;
    assert_eq!(second.items.len(), 1);
    assert!(second.next.is_none());
    assert!(matches!(
        fixture.repository.unrevoked_access_activations(
            user,
            UnixMicros::new(251),
            Some(cursor),
            PageLimit::new(1)?
        ),
        Err(RepositoryError::StaleRevision)
    ));
    assert!(matches!(
        fixture.repository.unrevoked_access_activations(
            PrincipalId::from_bytes([77; 16])?,
            UnixMicros::new(250),
            Some(cursor),
            PageLimit::new(1)?
        ),
        Err(RepositoryError::StaleRevision)
    ));

    apply(
        &mut fixture,
        user,
        260,
        AuthoritativeCommand::RevokeAccessActivation(RevokeAccessActivation {
            activation_id: ActivationId::from_bytes([75; 16])?,
            principal_id: user,
            reason: "Task complete".to_owned(),
        }),
    )?;
    assert_eq!(
        fixture
            .repository
            .unrevoked_access_activations(user, UnixMicros::new(261), None, PageLimit::new(10)?,)?
            .items
            .len(),
        1
    );
    assert!(
        fixture
            .repository
            .unrevoked_access_activations(user, UnixMicros::new(302), None, PageLimit::new(10)?,)?
            .items
            .is_empty()
    );
    Ok(())
}

#[test]
fn missing_object_is_distinct_from_a_stale_owner_continuation()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = build_fixture(false)?;
    assert!(
        fixture
            .repository
            .object_owners(ObjectId::from_bytes([99; 16])?, None, PageLimit::new(1)?,)?
            .is_none()
    );
    Ok(())
}
