// SPDX-License-Identifier: GPL-2.0-only

use axum::http::HeaderMap;
use meshspan_api_contract::{ListVolumesQuery, VolumeCursor};
use meshspan_domain::{
    AssuranceLevel, AuthenticationService, NodeId, ObjectId, Revision, Rights, UnixMicros, VolumeId,
};
use meshspan_filesystem::FilesystemAccessContext;
use meshspan_metadata::{Page, PageLimit, VolumeInventoryCursor, VolumeInventoryRecord};

use crate::{
    FileApiAuthenticationError, NativeFileApiAuthenticator, NativeFileRequestProtection,
    VolumeInventoryAuthority, VolumeInventoryAuthorityError, VolumeInventoryError,
    VolumeInventoryService,
};

#[test]
fn inventory_skips_inaccessible_candidates_and_continues_from_last_visible_volume()
-> Result<(), Box<dyn std::error::Error>> {
    let service = service(false)?;
    let first = service.list(
        &HeaderMap::new(),
        &ListVolumesQuery {
            cursor: None,
            limit: Some(1),
        },
        UnixMicros::new(100),
    )?;
    assert_eq!(first.volumes.len(), 1);
    assert_eq!(first.volumes[0].name, "Bravo");
    let next_url = first.next_page_url.ok_or("missing next page")?;
    let encoded = next_url
        .split("cursor=")
        .nth(1)
        .ok_or("missing cursor")?
        .to_owned();
    assert!(!encoded.contains("alpha"));

    let second = service.list(
        &HeaderMap::new(),
        &ListVolumesQuery {
            cursor: VolumeCursor::from_encoded(encoded),
            limit: Some(1),
        },
        UnixMicros::new(100),
    )?;
    assert_eq!(second.volumes.len(), 1);
    assert_eq!(second.volumes[0].name, "Charlie");
    assert!(second.next_page_url.is_none());
    Ok(())
}

#[test]
fn inventory_authenticates_before_candidate_or_permission_work()
-> Result<(), Box<dyn std::error::Error>> {
    let service = service(true)?;
    assert_eq!(
        service.list(
            &HeaderMap::new(),
            &ListVolumesQuery::default(),
            UnixMicros::new(100),
        ),
        Err(VolumeInventoryError::Rejected)
    );
    Ok(())
}

fn service(
    reject_authentication: bool,
) -> Result<VolumeInventoryService<FakeAuthenticator, FakeAuthority>, Box<dyn std::error::Error>> {
    Ok(VolumeInventoryService::new(
        FakeAuthenticator {
            reject: reject_authentication,
        },
        FakeAuthority {
            records: vec![
                record(10, "Alpha")?,
                record(11, "Bravo")?,
                record(12, "Charlie")?,
            ],
        },
    ))
}

struct FakeAuthenticator {
    reject: bool,
}

impl NativeFileApiAuthenticator for FakeAuthenticator {
    fn authenticate_file_request(
        &self,
        _headers: &HeaderMap,
        _protection: NativeFileRequestProtection,
        now: UnixMicros,
    ) -> Result<FilesystemAccessContext, FileApiAuthenticationError> {
        if self.reject {
            return Err(FileApiAuthenticationError::Rejected);
        }
        Ok(FilesystemAccessContext {
            authentication_service: AuthenticationService::Https,
            credential_digest: [1; 32],
            required_assurance: AssuranceLevel::SingleFactor,
            gateway_node_id: NodeId::from_bytes(versioned(2))
                .map_err(|_| FileApiAuthenticationError::InvalidGateway)?,
            gateway_incarnation: 1,
            now,
        })
    }
}

struct FakeAuthority {
    records: Vec<VolumeInventoryRecord>,
}

impl VolumeInventoryAuthority for FakeAuthority {
    fn volume_candidates(
        &self,
        after: Option<&VolumeInventoryCursor>,
        _limit: PageLimit,
    ) -> Result<Page<VolumeInventoryRecord, VolumeInventoryCursor>, VolumeInventoryAuthorityError>
    {
        let items = self
            .records
            .iter()
            .filter(|record| after.is_none_or(|cursor| comes_after(record, cursor)))
            .cloned()
            .collect();
        Ok(Page { items, next: None })
    }

    fn volume_rights(
        &self,
        _context: FilesystemAccessContext,
        volume: &VolumeInventoryRecord,
    ) -> Result<Option<Rights>, VolumeInventoryAuthorityError> {
        if volume.display_name == "Alpha" {
            return Ok(None);
        }
        Ok(Some(
            Rights::TRAVERSE
                .union(Rights::LIST)
                .union(Rights::READ_DATA),
        ))
    }
}

fn comes_after(record: &VolumeInventoryRecord, cursor: &VolumeInventoryCursor) -> bool {
    (record.canonical_name.as_str(), record.volume_id.as_bytes())
        > (cursor.canonical_name(), cursor.volume_id().as_bytes())
}

fn record(seed: u8, name: &str) -> Result<VolumeInventoryRecord, Box<dyn std::error::Error>> {
    Ok(VolumeInventoryRecord {
        volume_id: VolumeId::from_bytes(versioned(seed))?,
        root_object_id: ObjectId::from_bytes(versioned(seed.saturating_add(40)))?,
        display_name: name.to_owned(),
        canonical_name: name.to_lowercase(),
        state: 1,
        created_at: UnixMicros::new(10),
        revision: Revision::new(1),
    })
}

fn versioned(seed: u8) -> [u8; 16] {
    let mut value = [seed; 16];
    value[6] = 0x40;
    value[8] = 0x80;
    value
}
