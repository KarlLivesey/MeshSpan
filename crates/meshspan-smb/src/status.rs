// SPDX-License-Identifier: GPL-2.0-only

//! Stable mapping from connector-neutral failures to SMB `NTSTATUS` values.

/// One connector-neutral outcome emitted by the shared appliance boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ConnectorFailure {
    /// The request completed successfully.
    Success,
    /// More directory entries exist than fit in this response.
    MoreEntries,
    /// A directory enumeration has no further entries.
    NoMoreEntries,
    /// A read began at or beyond the logical end of file.
    EndOfFile,
    /// Untrusted request fields or relationships are invalid.
    InvalidInput,
    /// The authenticated principal lacks required authority.
    AccessDenied,
    /// The selected logical object does not exist.
    NotFound,
    /// Creation selected an existing name.
    AlreadyExists,
    /// The selected object is a directory where a file was required.
    IsDirectory,
    /// The selected object is not a directory.
    NotDirectory,
    /// Another live handle has incompatible sharing rights.
    SharingViolation,
    /// A live byte-range lock conflicts with this request.
    LockConflict,
    /// The object is waiting for final-handle deletion.
    DeletePending,
    /// A directory must be empty before this operation.
    DirectoryNotEmpty,
    /// The supplied handle is closed, expired or fenced.
    HandleClosed,
    /// The authenticated session is absent, revoked or fenced.
    SessionDeleted,
    /// The selected published share is absent or withdrawn.
    ShareDeleted,
    /// Durable storage cannot accept the requested allocation.
    StorageFull,
    /// A bounded operation exceeded its deadline.
    TimedOut,
    /// A required protocol operation is outside the selected profile.
    Unsupported,
    /// Resource-aware admission cannot safely accept more work now.
    TemporarilyUnavailable,
    /// Internal state failed verification; no sensitive detail may cross the connector.
    InternalFailure,
}

impl ConnectorFailure {
    /// Maps this failure class to the exact SMB status returned on the wire.
    #[must_use]
    pub const fn nt_status(self) -> NtStatus {
        match self {
            Self::Success => NtStatus::Success,
            Self::MoreEntries => NtStatus::BufferOverflow,
            Self::NoMoreEntries => NtStatus::NoMoreFiles,
            Self::EndOfFile => NtStatus::EndOfFile,
            Self::InvalidInput => NtStatus::InvalidParameter,
            Self::AccessDenied => NtStatus::AccessDenied,
            Self::NotFound => NtStatus::ObjectNameNotFound,
            Self::AlreadyExists => NtStatus::ObjectNameCollision,
            Self::IsDirectory => NtStatus::FileIsDirectory,
            Self::NotDirectory => NtStatus::NotADirectory,
            Self::SharingViolation => NtStatus::SharingViolation,
            Self::LockConflict => NtStatus::LockNotGranted,
            Self::DeletePending => NtStatus::DeletePending,
            Self::DirectoryNotEmpty => NtStatus::DirectoryNotEmpty,
            Self::HandleClosed => NtStatus::FileClosed,
            Self::SessionDeleted => NtStatus::UserSessionDeleted,
            Self::ShareDeleted => NtStatus::NetworkNameDeleted,
            Self::StorageFull => NtStatus::DiskFull,
            Self::TimedOut => NtStatus::IoTimeout,
            Self::Unsupported => NtStatus::NotSupported,
            Self::TemporarilyUnavailable => NtStatus::InsufficientResources,
            Self::InternalFailure => NtStatus::InternalError,
        }
    }
}

/// SMB status values used by the initial embedded service profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum NtStatus {
    /// Operation succeeded.
    Success = 0x0000_0000,
    /// The response contains a valid partial result.
    BufferOverflow = 0x8000_0005,
    /// Directory enumeration is complete.
    NoMoreFiles = 0x8000_0006,
    /// A read started beyond the logical file length.
    EndOfFile = 0xc000_0011,
    /// Request fields or relationships are invalid.
    InvalidParameter = 0xc000_000d,
    /// Access is not authorised.
    AccessDenied = 0xc000_0022,
    /// The selected path does not exist.
    ObjectNameNotFound = 0xc000_0034,
    /// The selected creation name already exists.
    ObjectNameCollision = 0xc000_0035,
    /// Another live handle has incompatible sharing rights.
    SharingViolation = 0xc000_0043,
    /// A byte-range lock conflicts with the request.
    LockNotGranted = 0xc000_0055,
    /// The object is pending final deletion.
    DeletePending = 0xc000_0056,
    /// Durable storage has insufficient free capacity.
    DiskFull = 0xc000_007f,
    /// The appliance cannot currently admit required resources.
    InsufficientResources = 0xc000_009a,
    /// The selected path is a directory, not a file.
    FileIsDirectory = 0xc000_00ba,
    /// This operation is not supported by the initial profile.
    NotSupported = 0xc000_00bb,
    /// A bounded IO operation exceeded its deadline.
    IoTimeout = 0xc000_00b5,
    /// The published share is no longer available.
    NetworkNameDeleted = 0xc000_00c9,
    /// The selected directory is not empty.
    DirectoryNotEmpty = 0xc000_0101,
    /// The selected path is not a directory.
    NotADirectory = 0xc000_0103,
    /// The supplied file handle is closed or fenced.
    FileClosed = 0xc000_0128,
    /// The authenticated session was removed or fenced.
    UserSessionDeleted = 0xc000_0203,
    /// Verified internal state could not safely serve the request.
    InternalError = 0xc000_00e5,
}

impl NtStatus {
    /// Returns the exact 32-bit wire value.
    #[must_use]
    pub const fn wire_value(self) -> u32 {
        self as u32
    }
}

#[cfg(test)]
mod tests {
    use super::{ConnectorFailure, NtStatus};

    #[test]
    fn stable_failure_classes_map_to_exact_wire_statuses() {
        let cases = [
            (ConnectorFailure::Success, NtStatus::Success),
            (ConnectorFailure::AccessDenied, NtStatus::AccessDenied),
            (ConnectorFailure::NotFound, NtStatus::ObjectNameNotFound),
            (
                ConnectorFailure::SharingViolation,
                NtStatus::SharingViolation,
            ),
            (ConnectorFailure::HandleClosed, NtStatus::FileClosed),
            (ConnectorFailure::StorageFull, NtStatus::DiskFull),
            (ConnectorFailure::InternalFailure, NtStatus::InternalError),
        ];
        for (failure, expected) in cases {
            assert_eq!(failure.nt_status(), expected);
            assert_eq!(failure.nt_status().wire_value(), expected as u32);
        }
    }
}
