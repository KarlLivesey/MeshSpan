// SPDX-License-Identifier: GPL-2.0-only

//! Bounded encrypted spool separates key planning from root signing and authoritative staging.

use super::{RecoveryPreparationError as Error, selection::Selection};
use crate::protected_file::{self, ProtectedFileError, PublishMode};
use meshspan_domain::Clock as _;
use meshspan_metadata::{
    AuthoritativeRepository, PageLimit, RecoveryControlKeys, RecoverySecretInventory,
    RecoverySecretInventoryBuilder, read_prepared_recovery_secret, write_prepared_recovery_secret,
};
use meshspan_recovery_bundle::RecoveredAuthority;
use std::{fs::File, io::Read as _, path::Path};

pub(super) struct PreparedMaterials {
    pub(super) control: RecoveryControlKeys,
    pub(super) inventory: RecoverySecretInventory,
}

impl PreparedMaterials {
    pub(super) fn create(
        source: &AuthoritativeRepository,
        authority: &RecoveredAuthority,
        selection: &Selection,
        work: &Path,
    ) -> Result<Self, Error> {
        let recipients = selection.gateway_keys();
        let control = source.prepare_recovery_control_keys(
            authority,
            &recipients,
            &selection.storage_keys(),
            &mut crate::OperatingSystemRandom,
        )?;
        protected_file::publish(
            &work.join("control.bin"),
            &control.encode().map_err(|_| Error::Material)?,
            PublishMode::Create,
        )
        .map_err(|_| Error::Workspace)?;
        let mut inventory = None;
        protected_file::publish_checked(&work.join("secrets.bin"), PublishMode::Create, |output| {
            inventory = Some(
                spool(source, authority, selection, &control, output)
                    .map_err(|_| ProtectedFileError::Invalid)?,
            );
            Ok(())
        })
        .map_err(|_| Error::Material)?;
        Ok(Self {
            control,
            inventory: inventory.ok_or(Error::Material)?,
        })
    }

    pub(super) fn stage(
        &self,
        repo: &mut AuthoritativeRepository,
        authority: &RecoveredAuthority,
        work: &Path,
    ) -> Result<(), Error> {
        let encoded = protected_file::read_bounded(&work.join("control.bin"), 1, 1024 * 1024)
            .map_err(|_| Error::Material)?;
        let control = RecoveryControlKeys::decode(&encoded).map_err(|_| Error::Material)?;
        if control != self.control {
            return Err(Error::Material);
        }
        repo.stage_recovery_control_keys(authority, &control, crate::OperatingSystemClock.now())?;
        let mut input =
            protected_file::open_read(&work.join("secrets.bin")).map_err(|_| Error::Material)?;
        for _ in 0..self.inventory.generation_count {
            let material =
                read_prepared_recovery_secret(&mut input).map_err(|_| Error::Material)?;
            repo.stage_recovery_secret(authority, &material, crate::OperatingSystemClock.now())?;
        }
        let mut trailing = [0];
        if input.read(&mut trailing).map_err(|_| Error::Material)? != 0 {
            return Err(Error::Material);
        }
        if repo.seal_recovery_secret_inventory(authority, crate::OperatingSystemClock.now())?
            != self.inventory
        {
            return Err(Error::Material);
        }
        Ok(())
    }
}

fn spool(
    source: &AuthoritativeRepository,
    authority: &RecoveredAuthority,
    selection: &Selection,
    control: &RecoveryControlKeys,
    output: &mut File,
) -> Result<RecoverySecretInventory, Error> {
    let mut inventory = RecoverySecretInventoryBuilder::new(selection.recovery_id, control)?;
    let recipients = selection.gateway_keys();
    let mut after = None;
    loop {
        let page = source
            .secret_generation_contexts(after, PageLimit::new(128).map_err(|_| Error::Material)?)?;
        for context in page.items {
            let material = source.prepare_recovery_secret(
                authority,
                context,
                &recipients,
                &mut crate::OperatingSystemRandom,
            )?;
            inventory.push(&material)?;
            write_prepared_recovery_secret(output, &material).map_err(|_| Error::Material)?;
        }
        match page.next {
            Some(next) => after = Some(next),
            None => break,
        }
    }
    Ok(inventory.finish()?)
}
