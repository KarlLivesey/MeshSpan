// SPDX-License-Identifier: GPL-2.0-only

//! Current consensus projection adapters for specialised filesystem APIs.

use meshspan_cluster::{MetadataFilesystemAuthority, MetadataFilesystemAuthorityError};
use meshspan_filesystem::{
    FilesystemAccessAuthority, FilesystemAuthorityGrant, FilesystemAuthorityRequest,
};
use meshspan_metadata::{Page, PageLimit, VolumeInventoryCursor, VolumeInventoryRecord};

use crate::{
    ConsensusAuthenticationAuthority, VolumeInventoryAuthority, VolumeInventoryAuthorityError,
};

impl FilesystemAccessAuthority for ConsensusAuthenticationAuthority {
    type Error = MetadataFilesystemAuthorityError;

    fn authorise(
        &self,
        request: FilesystemAuthorityRequest,
    ) -> Result<FilesystemAuthorityGrant, Self::Error> {
        MetadataFilesystemAuthority::new(self.reader()).authorise(request)
    }
}

impl VolumeInventoryAuthority for ConsensusAuthenticationAuthority {
    fn volume_candidates(
        &self,
        after: Option<&VolumeInventoryCursor>,
        limit: PageLimit,
    ) -> Result<Page<VolumeInventoryRecord, VolumeInventoryCursor>, VolumeInventoryAuthorityError>
    {
        VolumeInventoryAuthority::volume_candidates(self.reader(), after, limit)
    }

    fn volume_rights(
        &self,
        context: meshspan_filesystem::FilesystemAccessContext,
        volume: &VolumeInventoryRecord,
    ) -> Result<Option<meshspan_domain::Rights>, VolumeInventoryAuthorityError> {
        VolumeInventoryAuthority::volume_rights(self.reader(), context, volume)
    }
}
