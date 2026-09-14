// SPDX-License-Identifier: GPL-2.0-only

//! Complete retained-generation projection followed by successor operational heads.

use super::{Error, Projection};
use crate::repository::{apply::to_i64, secret_generation::recovery_projection};
use crate::{AuthoritativeRepository, PageLimit};
use meshspan_recovery_bundle::RecoveredAuthority;
use rusqlite::{Transaction, params};
use sha2::{Digest as _, Sha256};

pub(super) fn install(
    repository: &AuthoritativeRepository,
    transaction: &Transaction<'_>,
    authority: &RecoveredAuthority,
    projection: &Projection,
) -> Result<(), Error> {
    let mut after = None;
    loop {
        let page = repository.secret_generation_contexts(after, PageLimit::new(128)?)?;
        for context in page.items {
            let material = repository
                .load_retained_recovery_secret(
                    authority,
                    context,
                    &projection.control,
                    projection.plan.recovery_id,
                )?
                .ok_or(Error::CorruptState)?;
            recovery_projection::install(
                transaction,
                &material,
                projection.fence.fenced_at,
                projection.revision,
            )?;
        }
        match page.next {
            Some(next) => after = Some(next),
            None => break,
        }
    }
    // Insert only after enumerating the complete original inventory; these new heads are
    // not source generations and must not change the traversal or its source validations.
    for material in [
        &projection.control.online_authority_key,
        &projection.control.storage_permit_key,
    ] {
        recovery_projection::install(
            transaction,
            material,
            projection.fence.fenced_at,
            projection.revision,
        )?;
    }
    let mesh = projection.plan.mesh_id.as_bytes();
    let now = projection.fence.fenced_at.get();
    let revision = to_i64(projection.revision.get())?;
    transaction.execute(
        "UPDATE online_certificate_authorities SET state = 3, retired_at = ?1, revision = ?2
        WHERE mesh_id = ?3 AND state IN (1, 2)",
        params![now, revision, mesh.as_slice()],
    )?;
    transaction.execute("INSERT INTO online_certificate_authorities(mesh_id, generation, certificate_der,
        certificate_digest, state, created_at, retired_at, revision) VALUES (?1, ?2, ?3, ?4, 1, ?5, NULL, ?6)",
        params![mesh.as_slice(), to_i64(projection.fence.online_generation)?, &projection.control.online_certificate_der,
            Sha256::digest(&projection.control.online_certificate_der).as_slice(), now, revision])?;
    Ok(())
}
