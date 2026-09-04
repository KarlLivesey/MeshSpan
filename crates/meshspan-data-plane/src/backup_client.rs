// SPDX-License-Identifier: GPL-2.0-only

//! Client side of exact remote metadata-backup provider streams.

mod mutation;
mod read;
mod store;

pub use mutation::{delete_backup, verify_backup};
pub use read::read_backup;
pub use store::store_backup;

use meshspan_contracts::RequestContext;
use meshspan_domain::Revision;
use meshspan_protocol::v1::RequestHeader;

use crate::BackupPlaneError;
use crate::backup_wire::request_context;

fn validate_invocation(
    header: &RequestHeader,
    context: RequestContext,
) -> Result<Revision, BackupPlaneError> {
    let revision = context
        .expected_revision
        .filter(|revision| revision.get() != 0)
        .ok_or(BackupPlaneError::InvalidMessage)?;
    if request_context(header, revision)? == context {
        Ok(revision)
    } else {
        Err(BackupPlaneError::InvalidMessage)
    }
}
