// SPDX-License-Identifier: GPL-2.0-only

//! Canonical logical paths retained by stable handles independently of provider paths.

use meshspan_domain::HandleId;
#[cfg(test)]
use rusqlite::Connection;
use rusqlite::{Transaction, params};

use super::HandleError;
#[cfg(test)]
use crate::NamespaceComponent;
use crate::NamespacePath;

pub(super) fn persist(
    transaction: &Transaction<'_>,
    handle_id: HandleId,
    path: &NamespacePath,
) -> Result<(), HandleError> {
    for (ordinal, component) in path.components().iter().enumerate() {
        transaction.execute(
            "INSERT INTO open_handle_path_components(
                handle_id, component_ordinal, display_name, canonical_name
             ) VALUES (?1, ?2, ?3, ?4)",
            params![
                handle_id.as_bytes().as_slice(),
                i64::try_from(ordinal).map_err(|_| HandleError::InvalidInput)?,
                component.display(),
                component.canonical(),
            ],
        )?;
    }
    Ok(())
}

#[cfg(test)]
pub(crate) fn load(
    connection: &Connection,
    handle_id: HandleId,
) -> Result<NamespacePath, HandleError> {
    let mut statement = connection.prepare(
        "SELECT component_ordinal, display_name, canonical_name
         FROM open_handle_path_components
         WHERE handle_id = ?1 ORDER BY component_ordinal",
    )?;
    let rows = statement.query_map([handle_id.as_bytes().as_slice()], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, String>(2)?,
        ))
    })?;
    let mut components = Vec::new();
    for row in rows {
        let (ordinal, display, canonical) = row?;
        if usize::try_from(ordinal) != Ok(components.len()) {
            return Err(HandleError::Corrupt);
        }
        components.push(
            NamespaceComponent::from_stored(&display, &canonical)
                .map_err(|_| HandleError::Corrupt)?,
        );
    }
    NamespacePath::from_stored_components(components).map_err(|_| HandleError::Corrupt)
}
