// SPDX-License-Identifier: GPL-2.0-only

//! Authenticated SMB command routing over the common logical filesystem.

use std::collections::BTreeMap;

use meshspan_domain::VolumeId;
use meshspan_filesystem::{FilesystemAccessContext, FilesystemFileAdapter, NamespaceLimits};

use crate::{
    CloseRequest, ConnectorFailure, CreateRequest, EchoRequest, FlushRequest, LockRequest,
    LogoffRequest, QueryDirectoryRequest, QueryInfoRequest, ReadRequest, SetInfoRequest,
    Smb2Command, Smb2Header, SmbErrorResponse, SmbFilesystemAdapter, SmbFilesystemAdapterError,
    SmbFilesystemLimits, SmbSecureChannel, SmbSecureChannelError, SmbTreeBinding,
    TreeConnectRequest, TreeConnectResponse, TreeConnectResponseConfig, TreeDisconnectRequest,
    WriteRequest,
};

const TRANSFORM_PROTOCOL: [u8; 4] = [0xfd, b'S', b'M', b'B'];
const MAXIMUM_PUBLISHED_SHARES: usize = 1_024;
const MAXIMUM_SHARE_NAME_UNITS: usize = 80;

/// One daemon-published logical SMB share.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SmbPublishedShare {
    name: String,
    volume_id: VolumeId,
    root_components: Vec<String>,
    namespace_limits: NamespaceLimits,
    maximal_access: u32,
    encryption_required: bool,
}

impl SmbPublishedShare {
    /// Validates one user-visible share route without opening provider storage.
    ///
    /// # Errors
    ///
    /// Rejects invalid names, empty access, or a root outside the common namespace profile.
    pub fn new(
        name: String,
        volume_id: VolumeId,
        root_components: Vec<String>,
        namespace_limits: NamespaceLimits,
        maximal_access: u32,
        encryption_required: bool,
    ) -> Result<Self, SmbCommandDispatcherConfigurationError> {
        let name_units = name.encode_utf16().count();
        if name != name.trim()
            || !(1..=MAXIMUM_SHARE_NAME_UNITS).contains(&name_units)
            || name
                .chars()
                .any(|character| character.is_control() || matches!(character, '\\' | '/'))
            || maximal_access == 0
        {
            return Err(SmbCommandDispatcherConfigurationError);
        }
        if !root_components.is_empty()
            && meshspan_filesystem::NamespacePath::from_components(
                root_components.iter().map(String::as_str),
                namespace_limits,
            )
            .is_err()
        {
            return Err(SmbCommandDispatcherConfigurationError);
        }
        Ok(Self {
            name,
            volume_id,
            root_components,
            namespace_limits,
            maximal_access,
            encryption_required,
        })
    }

    /// Returns the case-preserved name advertised to users.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }
}

/// Routes one established session's protected requests to independently authorised trees.
pub struct SmbCommandDispatcher<I, F, C, M> {
    channel: SmbSecureChannel<I>,
    filesystem: F,
    filesystem_limits: SmbFilesystemLimits,
    shares: Vec<SmbPublishedShare>,
    trees: BTreeMap<u32, ConnectedTree<F>>,
    next_tree_id: u32,
    make_context: C,
    classify_filesystem_error: M,
    active: bool,
}

struct ConnectedTree<F> {
    encryption_required: bool,
    adapter: SmbFilesystemAdapter<F>,
}

impl<I, F, C, M> SmbCommandDispatcher<I, F, C, M>
where
    F: FilesystemFileAdapter + Clone,
    C: FnMut(&I) -> Result<FilesystemAccessContext, ConnectorFailure>,
    M: Fn(&F::Error) -> ConnectorFailure,
{
    /// Composes one authenticated channel with published share and filesystem policy.
    ///
    /// # Errors
    ///
    /// Rejects an empty or excessive share catalogue and case-insensitive duplicate names.
    pub fn new(
        channel: SmbSecureChannel<I>,
        filesystem: F,
        filesystem_limits: SmbFilesystemLimits,
        shares: Vec<SmbPublishedShare>,
        make_context: C,
        classify_filesystem_error: M,
    ) -> Result<Self, SmbCommandDispatcherConfigurationError> {
        if shares.is_empty()
            || shares.len() > MAXIMUM_PUBLISHED_SHARES
            || shares.iter().enumerate().any(|(index, share)| {
                shares[..index]
                    .iter()
                    .any(|earlier| earlier.name.eq_ignore_ascii_case(&share.name))
            })
        {
            return Err(SmbCommandDispatcherConfigurationError);
        }
        Ok(Self {
            channel,
            filesystem,
            filesystem_limits,
            shares,
            trees: BTreeMap::new(),
            next_tree_id: 1,
            make_context,
            classify_filesystem_error,
            active: true,
        })
    }

    /// Authenticates, routes and protects one complete post-session SMB message.
    ///
    /// # Errors
    ///
    /// Returns only channel-integrity or response-construction failures. Hostile but authentic
    /// command input receives a bounded protocol error response instead.
    pub fn dispatch(&mut self, protected: &[u8]) -> Result<Vec<u8>, SmbCommandDispatchError> {
        let encrypted = protected.starts_with(&TRANSFORM_PROTOCOL);
        let packet = self.channel.decode_request(protected)?;
        let header = Smb2Header::parse_request(&packet)
            .map_err(|_| SmbCommandDispatchError::InvalidAuthenticatedHeader)?;
        if !self.active {
            return self.error(header, ConnectorFailure::SessionDeleted);
        }
        let response = match header.command {
            Smb2Command::TreeConnect => self.tree_connect(&packet),
            Smb2Command::TreeDisconnect => self.tree_disconnect(&packet, encrypted),
            Smb2Command::Echo => Self::echo(&packet),
            Smb2Command::Logoff => self.logoff(&packet),
            Smb2Command::Create
            | Smb2Command::Close
            | Smb2Command::Flush
            | Smb2Command::Read
            | Smb2Command::Write
            | Smb2Command::Lock
            | Smb2Command::QueryDirectory
            | Smb2Command::QueryInfo
            | Smb2Command::SetInfo => self.filesystem_command(&packet, header, encrypted),
            Smb2Command::Negotiate | Smb2Command::SessionSetup => {
                Err(ConnectorFailure::InvalidInput)
            }
            Smb2Command::Ioctl
            | Smb2Command::Cancel
            | Smb2Command::ChangeNotify
            | Smb2Command::OplockBreak => Err(ConnectorFailure::Unsupported),
        };
        match response {
            Ok(response) => self.protect(response),
            Err(failure) => self.error(header, failure),
        }
    }

    fn tree_connect(&mut self, packet: &[u8]) -> Result<Vec<u8>, ConnectorFailure> {
        let request =
            TreeConnectRequest::parse(packet).map_err(|_| ConnectorFailure::InvalidInput)?;
        let share = self
            .shares
            .iter()
            .find(|share| share.name.eq_ignore_ascii_case(&request.share_name))
            .cloned()
            .ok_or(ConnectorFailure::ShareDeleted)?;
        let tree_id = self.allocate_tree_id()?;
        let binding = SmbTreeBinding::new(
            self.channel.session_id(),
            tree_id,
            share.volume_id,
            share.root_components,
            share.namespace_limits,
        )
        .map_err(|_| ConnectorFailure::InternalFailure)?;
        let response = TreeConnectResponse::encode(
            &request,
            TreeConnectResponseConfig {
                tree_id,
                maximal_access: share.maximal_access,
                encryption_required: share.encryption_required,
            },
        )
        .map_err(|_| ConnectorFailure::InternalFailure)?;
        self.trees.insert(
            tree_id,
            ConnectedTree {
                encryption_required: share.encryption_required,
                adapter: SmbFilesystemAdapter::new(
                    self.filesystem.clone(),
                    binding,
                    self.filesystem_limits,
                ),
            },
        );
        Ok(response.packet)
    }

    fn tree_disconnect(
        &mut self,
        packet: &[u8],
        encrypted: bool,
    ) -> Result<Vec<u8>, ConnectorFailure> {
        let request =
            TreeDisconnectRequest::parse(packet).map_err(|_| ConnectorFailure::InvalidInput)?;
        let tree = self
            .trees
            .get(&request.header.tree_id)
            .ok_or(ConnectorFailure::ShareDeleted)?;
        if tree.encryption_required && !encrypted {
            return Err(ConnectorFailure::AccessDenied);
        }
        self.trees
            .remove(&request.header.tree_id)
            .ok_or(ConnectorFailure::InternalFailure)?;
        Ok(request.success_response().to_vec())
    }

    fn echo(packet: &[u8]) -> Result<Vec<u8>, ConnectorFailure> {
        EchoRequest::parse(packet)
            .map(EchoRequest::success_response)
            .map(|response| response.to_vec())
            .map_err(|_| ConnectorFailure::InvalidInput)
    }

    fn logoff(&mut self, packet: &[u8]) -> Result<Vec<u8>, ConnectorFailure> {
        let request = LogoffRequest::parse(packet).map_err(|_| ConnectorFailure::InvalidInput)?;
        let response = request.success_response().to_vec();
        self.trees.clear();
        self.active = false;
        Ok(response)
    }

    fn filesystem_command(
        &mut self,
        packet: &[u8],
        header: Smb2Header,
        encrypted: bool,
    ) -> Result<Vec<u8>, ConnectorFailure> {
        let context = (self.make_context)(self.channel.identity())?;
        let tree = self
            .trees
            .get_mut(&header.tree_id)
            .ok_or(ConnectorFailure::ShareDeleted)?;
        if tree.encryption_required && !encrypted {
            return Err(ConnectorFailure::AccessDenied);
        }
        dispatch_filesystem(&mut tree.adapter, context, header.command, packet).map_err(|error| {
            match error {
                FilesystemCommandError::InvalidRequest => ConnectorFailure::InvalidInput,
                FilesystemCommandError::Adapter(error) => {
                    classify_adapter_error(&self.classify_filesystem_error, &error)
                }
            }
        })
    }

    fn allocate_tree_id(&mut self) -> Result<u32, ConnectorFailure> {
        let starting = self.next_tree_id;
        loop {
            let candidate = self.next_tree_id;
            self.next_tree_id = self.next_tree_id.checked_add(1).unwrap_or(1);
            if candidate != 0 && !self.trees.contains_key(&candidate) {
                return Ok(candidate);
            }
            if self.next_tree_id == starting {
                return Err(ConnectorFailure::TemporarilyUnavailable);
            }
        }
    }

    fn protect(&self, response: Vec<u8>) -> Result<Vec<u8>, SmbCommandDispatchError> {
        self.channel.encode_response(response).map_err(Into::into)
    }

    fn error(
        &self,
        header: Smb2Header,
        failure: ConnectorFailure,
    ) -> Result<Vec<u8>, SmbCommandDispatchError> {
        let response = SmbErrorResponse::encode(header, failure.nt_status(), &[])
            .map_err(|_| SmbCommandDispatchError::InvalidErrorResponse)?;
        self.protect(response.packet)
    }
}

fn dispatch_filesystem<F: FilesystemFileAdapter>(
    adapter: &mut SmbFilesystemAdapter<F>,
    context: FilesystemAccessContext,
    command: Smb2Command,
    packet: &[u8],
) -> Result<Vec<u8>, FilesystemCommandError<F::Error>> {
    match command {
        Smb2Command::Create => {
            let request =
                CreateRequest::parse(packet).map_err(|_| FilesystemCommandError::InvalidRequest)?;
            Ok(adapter.create(context, &request)?.response.packet.to_vec())
        }
        Smb2Command::Close => {
            let request =
                CloseRequest::parse(packet).map_err(|_| FilesystemCommandError::InvalidRequest)?;
            Ok(adapter.close_file(context, request)?.packet.to_vec())
        }
        Smb2Command::Flush => {
            let request =
                FlushRequest::parse(packet).map_err(|_| FilesystemCommandError::InvalidRequest)?;
            Ok(adapter.flush_file(context, request)?.to_vec())
        }
        Smb2Command::Read => {
            let request =
                ReadRequest::parse(packet).map_err(|_| FilesystemCommandError::InvalidRequest)?;
            Ok(adapter.read_file(context, request)?.packet)
        }
        Smb2Command::Write => {
            let request =
                WriteRequest::parse(packet).map_err(|_| FilesystemCommandError::InvalidRequest)?;
            Ok(adapter.write_file(context, &request)?.packet.to_vec())
        }
        Smb2Command::Lock => {
            let request =
                LockRequest::parse(packet).map_err(|_| FilesystemCommandError::InvalidRequest)?;
            Ok(adapter.lock_ranges(context, &request)?.packet.to_vec())
        }
        Smb2Command::QueryDirectory => {
            let request = QueryDirectoryRequest::parse(packet)
                .map_err(|_| FilesystemCommandError::InvalidRequest)?;
            Ok(adapter.query_directory(context, &request)?.packet)
        }
        Smb2Command::QueryInfo => {
            let request = QueryInfoRequest::parse(packet)
                .map_err(|_| FilesystemCommandError::InvalidRequest)?;
            Ok(adapter.query_info(context, request)?.packet)
        }
        Smb2Command::SetInfo => {
            let request = SetInfoRequest::parse(packet)
                .map_err(|_| FilesystemCommandError::InvalidRequest)?;
            Ok(adapter.set_info(context, &request)?.to_vec())
        }
        _ => Err(FilesystemCommandError::InvalidRequest),
    }
}

enum FilesystemCommandError<E> {
    InvalidRequest,
    Adapter(SmbFilesystemAdapterError<E>),
}

impl<E> From<SmbFilesystemAdapterError<E>> for FilesystemCommandError<E> {
    fn from(error: SmbFilesystemAdapterError<E>) -> Self {
        Self::Adapter(error)
    }
}

fn classify_adapter_error<E>(
    classifier: &impl Fn(&E) -> ConnectorFailure,
    error: &SmbFilesystemAdapterError<E>,
) -> ConnectorFailure {
    match error {
        SmbFilesystemAdapterError::UnsupportedTarget
        | SmbFilesystemAdapterError::UnsupportedDisposition
        | SmbFilesystemAdapterError::UnsupportedSearchPattern
        | SmbFilesystemAdapterError::UnsupportedReplacement
        | SmbFilesystemAdapterError::UnsupportedMutation => ConnectorFailure::Unsupported,
        SmbFilesystemAdapterError::UnknownFile | SmbFilesystemAdapterError::UnknownDirectory => {
            ConnectorFailure::HandleClosed
        }
        SmbFilesystemAdapterError::NoMoreFiles => ConnectorFailure::NoMoreEntries,
        SmbFilesystemAdapterError::DuplicateLock => ConnectorFailure::LockConflict,
        SmbFilesystemAdapterError::LimitExceeded => ConnectorFailure::TemporarilyUnavailable,
        SmbFilesystemAdapterError::Filesystem(error) => classifier(error),
        SmbFilesystemAdapterError::InvalidConfiguration
        | SmbFilesystemAdapterError::InvalidIdentity
        | SmbFilesystemAdapterError::InvalidPath
        | SmbFilesystemAdapterError::InvalidAccess
        | SmbFilesystemAdapterError::InvalidRange
        | SmbFilesystemAdapterError::DuplicateFileIdentity
        | SmbFilesystemAdapterError::UnknownLock
        | SmbFilesystemAdapterError::InvalidTime
        | SmbFilesystemAdapterError::InvalidResponse => ConnectorFailure::InvalidInput,
    }
}

/// Invalid static dispatcher configuration.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("SMB command dispatcher configuration is invalid")]
pub struct SmbCommandDispatcherConfigurationError;

/// Failure that cannot safely be represented as an authenticated SMB command response.
#[derive(Debug, thiserror::Error)]
pub enum SmbCommandDispatchError {
    /// Session protection rejected the packet or response.
    #[error(transparent)]
    SecureChannel(#[from] SmbSecureChannelError),
    /// The secure channel returned a header which could not be parsed again.
    #[error("authenticated SMB header is invalid")]
    InvalidAuthenticatedHeader,
    /// A canonical error response could not be constructed.
    #[error("SMB error response could not be constructed")]
    InvalidErrorResponse,
}

#[cfg(test)]
#[path = "command_dispatcher_tests.rs"]
mod tests;
