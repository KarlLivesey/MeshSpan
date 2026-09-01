// SPDX-License-Identifier: GPL-2.0-only

//! Permission-filtered volume inventory over replaceable authentication and metadata authority.

use axum::http::HeaderMap;
use meshspan_api_contract::{ListVolumesQuery, ListVolumesResponse, validate_list_volumes_query};
use meshspan_domain::{Rights, UnixMicros};
use meshspan_metadata::{PageLimit, VolumeInventoryCursor, VolumeInventoryRecord};

use super::model::{decode_cursor, list_response};
use super::{VolumeInventoryAuthority, VolumeInventoryAuthorityError, VolumeInventoryError};
use crate::{FileApiAuthenticationError, NativeFileApiAuthenticator, NativeFileRequestProtection};

const DEFAULT_PAGE_LIMIT: u16 = 100;
const CANDIDATE_BATCH_SIZE: usize = 256;
const MAXIMUM_CANDIDATES_SCANNED: usize = 65_536;

/// Complete volume inventory over replaceable authentication and replicated authority.
pub struct VolumeInventoryService<A, V> {
    authenticator: A,
    authority: V,
}

impl<A, V> VolumeInventoryService<A, V> {
    /// Composes authentication and candidate/permission authority.
    #[must_use]
    pub const fn new(authenticator: A, authority: V) -> Self {
        Self {
            authenticator,
            authority,
        }
    }
}

impl<A, V> VolumeInventoryService<A, V>
where
    A: NativeFileApiAuthenticator,
    V: VolumeInventoryAuthority,
{
    /// Authenticates the caller and returns one permission-filtered volume page.
    ///
    /// # Errors
    ///
    /// Rejects malformed input, authentication failures and untrustworthy committed authority.
    pub fn list(
        &self,
        headers: &HeaderMap,
        query: &ListVolumesQuery,
        now: UnixMicros,
    ) -> Result<ListVolumesResponse, VolumeInventoryError> {
        validate_list_volumes_query(query).map_err(|_| VolumeInventoryError::InvalidRequest)?;
        let context = self
            .authenticator
            .authenticate_file_request(headers, NativeFileRequestProtection::Read, now)
            .map_err(map_authentication_error)?;
        let after = query.cursor.as_ref().map(decode_cursor).transpose()?;
        let limit = query.limit.unwrap_or(DEFAULT_PAGE_LIMIT);
        let visible = self.permission_filtered(context, after, limit)?;
        list_response(limit, visible)
    }

    fn permission_filtered(
        &self,
        context: meshspan_filesystem::FilesystemAccessContext,
        mut after: Option<VolumeInventoryCursor>,
        limit: u16,
    ) -> Result<Vec<(VolumeInventoryRecord, Rights)>, VolumeInventoryError> {
        let mut visible = Vec::with_capacity(usize::from(limit).saturating_add(1));
        let mut scanned = 0_usize;
        loop {
            let page = self
                .authority
                .volume_candidates(
                    after.as_ref(),
                    PageLimit::new(CANDIDATE_BATCH_SIZE)
                        .map_err(|_| VolumeInventoryError::Failed)?,
                )
                .map_err(map_authority_error)?;
            for record in page.items {
                scanned = scanned.checked_add(1).ok_or(VolumeInventoryError::Failed)?;
                if scanned > MAXIMUM_CANDIDATES_SCANNED {
                    return Err(VolumeInventoryError::Unavailable);
                }
                if let Some(rights) = self
                    .authority
                    .volume_rights(context, &record)
                    .map_err(map_authority_error)?
                    .filter(|rights| {
                        rights.contains(Rights::TRAVERSE) && rights.contains(Rights::LIST)
                    })
                {
                    visible.push((record, rights));
                    if visible.len() > usize::from(limit) {
                        return Ok(visible);
                    }
                }
            }
            let Some(next) = page.next else {
                return Ok(visible);
            };
            after = Some(next);
        }
    }
}

const fn map_authority_error(error: VolumeInventoryAuthorityError) -> VolumeInventoryError {
    match error {
        VolumeInventoryAuthorityError::Unavailable => VolumeInventoryError::Unavailable,
        VolumeInventoryAuthorityError::Failed => VolumeInventoryError::Failed,
    }
}

const fn map_authentication_error(error: FileApiAuthenticationError) -> VolumeInventoryError {
    match error {
        FileApiAuthenticationError::Rejected => VolumeInventoryError::Rejected,
        FileApiAuthenticationError::AuthorityUnavailable => VolumeInventoryError::Unavailable,
        FileApiAuthenticationError::InvalidGateway
        | FileApiAuthenticationError::AuthorityFailed => VolumeInventoryError::Failed,
    }
}
