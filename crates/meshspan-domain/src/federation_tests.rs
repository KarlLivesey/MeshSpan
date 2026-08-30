// SPDX-License-Identifier: GPL-2.0-only

use super::*;

#[test]
fn presets_expand_without_storing_ambiguous_authority() {
    let view = FederationAccess::from_preset(FederationPreset::View);
    assert!(view.rights().contains(Rights::READ_DATA));
    assert!(!view.rights().contains(Rights::WRITE_DATA));
    assert!(!view.allows_downstream_delegation());

    let edit = FederationAccess::from_preset(FederationPreset::Edit);
    assert!(edit.rights().contains(Rights::WRITE_DATA));
    assert!(!edit.rights().contains(Rights::CHANGE_PERMISSIONS));

    let manage = FederationAccess::from_preset(FederationPreset::Manage);
    assert_eq!(manage.rights(), Rights::ALL);
    assert!(manage.allows_downstream_delegation());
}

#[test]
fn every_side_can_only_narrow_effective_policy() -> Result<(), Box<dyn std::error::Error>> {
    let offered = FederationPolicy::Namespace(NamespaceFederationPolicy::new(
        FederationAccess::from_preset(FederationPreset::Manage),
        Some(DEFAULT_FEDERATION_OFFLINE_DURATION),
    ));
    let accepted = FederationPolicy::Namespace(NamespaceFederationPolicy::new(
        FederationAccess::from_preset(FederationPreset::Edit),
        Some(DurationMicros::new(7)),
    ));

    let effective = FederationPolicy::intersect(&[offered, accepted])?;
    assert_eq!(
        effective.maximum_offline_duration(),
        Some(DurationMicros::new(7))
    );
    let FederationPolicy::Namespace(effective) = effective else {
        return Err("namespace policies changed kind".into());
    };
    assert!(effective.access().rights().contains(Rights::WRITE_DATA));
    assert!(
        !effective
            .access()
            .rights()
            .contains(Rights::CHANGE_PERMISSIONS)
    );
    assert!(!effective.access().allows_downstream_delegation());

    let storage_offered = FederationPolicy::Storage(StorageFederationPolicy::new(
        100,
        StorageParticipation::new(true, true),
        true,
        None,
    )?);
    let storage_accepted = FederationPolicy::Storage(StorageFederationPolicy::new(
        50,
        StorageParticipation::new(true, false),
        false,
        None,
    )?);
    let storage = FederationPolicy::intersect(&[storage_offered, storage_accepted])?;
    let FederationPolicy::Storage(storage) = storage else {
        return Err("storage policies changed kind".into());
    };
    assert_eq!(storage.maximum_storage_bytes(), 50);
    assert!(storage.participation().counts_towards_protection());
    assert!(!storage.participation().serves_reads());
    Ok(())
}

#[test]
fn absent_and_contradictory_policy_fails_closed() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        FederationPolicy::intersect(&[]),
        Err(FederationPolicyError::MissingRestriction)
    );
    assert_eq!(
        StorageFederationPolicy::new(0, StorageParticipation::new(true, false), false, None),
        Err(FederationPolicyError::InvalidStorage)
    );
    let namespace = FederationPolicy::Namespace(NamespaceFederationPolicy::new(
        FederationAccess::from_preset(FederationPreset::View),
        None,
    ));
    let storage = FederationPolicy::Storage(StorageFederationPolicy::new(
        1,
        StorageParticipation::default(),
        false,
        None,
    )?);
    assert_eq!(
        FederationPolicy::intersect(&[namespace, storage]),
        Err(FederationPolicyError::IncompatibleKinds)
    );
    let mesh = MeshId::from_bytes([1; 16])?;
    let principal = PrincipalId::from_bytes([2; 16])?;
    assert_ne!(
        FederatedPrincipal::new(mesh, principal),
        FederatedPrincipal::new(MeshId::from_bytes([3; 16])?, principal)
    );
    Ok(())
}
