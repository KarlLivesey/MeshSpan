// SPDX-License-Identifier: GPL-2.0-only

//! Indexed, bounded inventory of retained generations for offline recovery verification.

use meshspan_secret_envelope::SecretContext;
use rusqlite::params;

use super::{Page, PageLimit, RepositoryError};
use crate::PartitionDatabase;

pub(super) fn contexts(
    database: &PartitionDatabase,
    after: Option<SecretContext>,
    limit: PageLimit,
) -> Result<Page<SecretContext, SecretContext>, RepositoryError> {
    let (kind, id, generation) = after.map_or((0, [0; 16], 0), |context| {
        (context.kind(), context.id(), context.generation())
    });
    let generation = i64::try_from(generation).map_err(|_| RepositoryError::InvalidCommand)?;
    let requested =
        i64::try_from(limit.get() + 1).map_err(|_| RepositoryError::InvalidPageLimit)?;
    let mut statement = database.connection().prepare(
        "SELECT secret_kind, secret_id, generation FROM secret_generations
         WHERE (secret_kind, secret_id, generation) > (?1, ?2, ?3)
         ORDER BY secret_kind, secret_id, generation LIMIT ?4",
    )?;
    let rows = statement.query_map(params![kind, id.as_slice(), generation, requested], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, Vec<u8>>(1)?,
            row.get::<_, i64>(2)?,
        ))
    })?;
    let mut items = Vec::with_capacity(limit.get() + 1);
    for row in rows {
        let (kind, id, generation) = row?;
        items.push(
            SecretContext::new(
                u16::try_from(kind).map_err(|_| RepositoryError::CorruptState)?,
                id.try_into().map_err(|_| RepositoryError::CorruptState)?,
                u64::try_from(generation).map_err(|_| RepositoryError::CorruptState)?,
            )
            .map_err(|_| RepositoryError::CorruptState)?,
        );
    }
    let next = if items.len() > limit.get() {
        items.truncate(limit.get());
        items.last().copied()
    } else {
        None
    };
    Ok(Page { items, next })
}
