// SPDX-License-Identifier: GPL-2.0-only

use super::*;

#[test]
fn active_open_renews_before_expiry() -> Result<(), Box<dyn std::error::Error>> {
    let mut adapter = adapter(64)?;
    let opened = adapter.create(context()?, &create_request(100, vec!["idle".to_owned()]))?;
    assert!(!adapter.maintain_lease(at(30)?)?);
    assert!(adapter.maintain_lease(at(31)?)?);
    assert!(adapter.maintain_lease(at(61)?)?);
    let read = adapter.read_file(
        at(66)?,
        ReadRequest {
            header: header(Smb2Command::Read, 101),
            file_id: opened.file_id,
            offset: 0,
            length: 4,
            minimum_count: 0,
        },
    )?;
    assert_eq!(&read.packet[80..], b"safe");
    adapter.write_file(
        at(66)?,
        &WriteRequest {
            header: header(Smb2Command::Write, 102),
            file_id: opened.file_id,
            offset: 0,
            bytes: b"next".to_vec(),
            write_through: false,
            unbuffered: false,
        },
    )?;
    adapter.flush_file(
        at(66)?,
        FlushRequest {
            header: header(Smb2Command::Flush, 103),
            file_id: opened.file_id,
        },
    )?;
    adapter.close_file(
        at(66)?,
        CloseRequest {
            header: header(Smb2Command::Close, 104),
            file_id: opened.file_id,
            postquery_attributes: false,
        },
    )?;
    assert!(
        !adapter.maintain_lease(at(92)?)?,
        "closed handles must not renew"
    );
    let renewals: Vec<_> = adapter
        .into_inner()
        .calls
        .into_iter()
        .filter_map(|call| {
            if let Call::Renew(request) = call {
                Some(request)
            } else {
                None
            }
        })
        .collect();
    assert_eq!(renewals.len(), 2);
    assert_eq!(renewals[0].lease_expires_at, UnixMicros::new(91_000_000));
    assert_eq!(renewals[1].lease_expires_at, UnixMicros::new(121_000_000));
    assert_ne!(renewals[0].operation_id, renewals[1].operation_id);
    assert!(
        renewals
            .iter()
            .all(|request| !request.takeover && request.expected_fence == 1)
    );
    Ok(())
}

#[test]
fn failed_renewal_fences_one_open_and_preserves_staging() -> Result<(), Box<dyn std::error::Error>>
{
    let mut adapter = adapter(64)?;
    adapter.create(context()?, &create_request(110, vec!["first".to_owned()]))?;
    adapter.create(context()?, &create_request(111, vec!["second".to_owned()]))?;
    let files: Vec<_> = adapter.handles.keys().copied().collect();
    for file in files {
        write_staging(&mut adapter, file)?;
    }
    let failed = adapter.renewals.first().ok_or("missing renewal")?.1;
    adapter.filesystem.renewal_failure = true;
    assert!(matches!(
        adapter.maintain_lease(at(31)?),
        Err(SmbFilesystemAdapterError::Filesystem(TestError))
    ));
    adapter.filesystem.renewal_failure = false;
    assert!(
        adapter.maintain_lease(at(31)?)?,
        "the next open must not be starved"
    );
    assert!(!adapter.maintain_lease(at(31)?)?);
    assert!(matches!(
        adapter.flush_file(
            at(32)?,
            FlushRequest {
                header: header(Smb2Command::Flush, 112),
                file_id: failed,
            }
        ),
        Err(SmbFilesystemAdapterError::UnknownFile)
    ));
    assert!(
        !adapter
            .filesystem
            .calls
            .iter()
            .any(|call| matches!(call, Call::Flush { .. } | Call::Close { .. }))
    );
    assert!(
        adapter
            .handles
            .get(&failed)
            .ok_or("lost fenced handle")?
            .dirty
    );
    Ok(())
}

#[test]
fn expired_or_mismatched_renewal_never_restores_authority() -> Result<(), Box<dyn std::error::Error>>
{
    let mut expired = adapter(64)?;
    expired.create(context()?, &create_request(120, vec!["expired".to_owned()]))?;
    assert!(matches!(
        expired.maintain_lease(at(61)?),
        Err(SmbFilesystemAdapterError::InvalidTime)
    ));
    assert!(
        !expired
            .filesystem
            .calls
            .iter()
            .any(|call| matches!(call, Call::Renew(_)))
    );
    assert!(!expired.maintain_lease(at(62)?)?);
    let mut invalid = adapter(64)?;
    let opened = invalid.create(context()?, &create_request(121, vec!["invalid".to_owned()]))?;
    invalid.filesystem.invalid_renewal_receipt = true;
    assert!(matches!(
        invalid.maintain_lease(at(31)?),
        Err(SmbFilesystemAdapterError::InvalidResponse)
    ));
    assert!(matches!(
        invalid.close_file(
            at(32)?,
            CloseRequest {
                header: header(Smb2Command::Close, 122),
                file_id: opened.file_id,
                postquery_attributes: false,
            }
        ),
        Err(SmbFilesystemAdapterError::UnknownFile)
    ));
    assert!(!invalid.maintain_lease(at(32)?)?);
    Ok(())
}

fn at(seconds: i64) -> Result<FilesystemAccessContext, TestError> {
    Ok(FilesystemAccessContext {
        now: UnixMicros::new(seconds * 1_000_000),
        ..context()?
    })
}

#[test]
fn disconnect_releases_clean_opens_without_publishing_dirty_stages()
-> Result<(), Box<dyn std::error::Error>> {
    let mut dirty = adapter(64)?;
    dirty.create(context()?, &create_request(130, vec!["dirty".to_owned()]))?;
    let file = *dirty.handles.keys().next().ok_or("missing open")?;
    write_staging(&mut dirty, file)?;
    assert!(dirty.detach_one(at(2)?)?);
    assert!(!dirty.maintain_lease(at(31)?)?);
    assert!(!dirty.detach_one(at(2)?)?);
    assert!(!dirty.filesystem.calls.iter().any(|call| matches!(
        call,
        Call::Flush { .. } | Call::Close { .. } | Call::Renew(_)
    )));
    let mut clean = adapter(64)?;
    let opened = clean.create(context()?, &create_request(131, vec!["clean".to_owned()]))?;
    clean.flush_file(
        at(2)?,
        FlushRequest {
            header: header(Smb2Command::Flush, 132),
            file_id: opened.file_id,
        },
    )?;
    assert!(clean.detach_one(at(3)?)?);
    assert!(matches!(
        clean.filesystem.calls.last(),
        Some(Call::Close { has_flush: false })
    ));
    assert!(!clean.maintain_lease(at(31)?)?);
    Ok(())
}

fn write_staging(
    adapter: &mut SmbFilesystemAdapter<TestFilesystem>,
    file_id: crate::SmbFileId,
) -> Result<(), Box<dyn std::error::Error>> {
    adapter.write_file(
        context()?,
        &WriteRequest {
            header: header(Smb2Command::Write, 200),
            file_id,
            offset: 0,
            bytes: b"dirty".to_vec(),
            write_through: false,
            unbuffered: false,
        },
    )?;
    Ok(())
}
