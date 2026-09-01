// SPDX-License-Identifier: GPL-2.0-only

//! Strict bounded configuration for the headless appliance process.

use std::ffi::{OsStr, OsString};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use meshspan_domain::{JoinGrantBundle, JoinGrantBundleError};
use meshspan_storage::{HeadlessStorageConfig, StorageConfigError};
use thiserror::Error;

const DEFAULT_HTTPS_PORT: u16 = 8_443;
const MAXIMUM_STORAGE_PATHS: usize = 1_024;
const SINGLETON_FLAGS: usize = 4;
const MAXIMUM_ARGUMENTS: usize = (MAXIMUM_STORAGE_PATHS + SINGLETON_FLAGS) * 2;

/// Validated local process settings which never include replicated mesh configuration.
///
/// The type deliberately omits `Debug` because it may own a secret join grant.
pub struct HeadlessDaemonConfig {
    storage: HeadlessStorageConfig,
    https_listen: SocketAddr,
    claim_output: Option<PathBuf>,
    join_grant: Option<JoinGrantBundle>,
}

impl HeadlessDaemonConfig {
    /// Parses the complete supported headless flag set.
    ///
    /// The executable name must not be included. Every flag takes exactly one value and
    /// `--storage-path` is the only repeatable flag.
    ///
    /// # Errors
    ///
    /// Rejects unknown or duplicate singleton flags, missing/empty values, malformed join grants
    /// and listen addresses, unsafe path combinations and input beyond the compiled bound.
    pub fn parse(
        arguments: impl IntoIterator<Item = OsString>,
    ) -> Result<Self, HeadlessDaemonConfigError> {
        let values: Vec<OsString> = arguments.into_iter().take(MAXIMUM_ARGUMENTS + 1).collect();
        if values.is_empty() || values.len() > MAXIMUM_ARGUMENTS || !values.len().is_multiple_of(2)
        {
            return Err(HeadlessDaemonConfigError::InvalidArguments);
        }
        let mut state_directory = None;
        let mut storage_paths = Vec::new();
        let mut https_listen = None;
        let mut claim_output = None;
        let mut join_grant = None;
        for pair in values.as_chunks::<2>().0 {
            let flag = &pair[0];
            let value = &pair[1];
            if value.is_empty() {
                return Err(HeadlessDaemonConfigError::InvalidArguments);
            }
            match flag.as_os_str() {
                value if value == OsStr::new("--daemon-state-dir") => {
                    set_once(&mut state_directory, PathBuf::from(&pair[1]))?;
                }
                value if value == OsStr::new("--storage-path") => {
                    storage_paths.push(PathBuf::from(&pair[1]));
                }
                value if value == OsStr::new("--https-listen") => {
                    set_once(&mut https_listen, parse_address(&pair[1])?)?;
                }
                value if value == OsStr::new("--claim-output") => {
                    set_once(&mut claim_output, PathBuf::from(&pair[1]))?;
                }
                value if value == OsStr::new("--join-code") => {
                    set_once(&mut join_grant, parse_join_grant(&pair[1])?)?;
                }
                _ => return Err(HeadlessDaemonConfigError::InvalidArguments),
            }
        }
        let storage = HeadlessStorageConfig::new(
            state_directory.ok_or(HeadlessDaemonConfigError::MissingStateDirectory)?,
            storage_paths,
        )?;
        Ok(Self {
            storage,
            https_listen: https_listen.unwrap_or_else(default_https_address),
            claim_output,
            join_grant,
        })
    }

    /// Returns daemon-local state and provider-folder configuration.
    #[must_use]
    pub const fn storage(&self) -> &HeadlessStorageConfig {
        &self.storage
    }

    /// Returns the public HTTPS listener address.
    #[must_use]
    pub const fn https_listen(&self) -> SocketAddr {
        self.https_listen
    }

    /// Returns the optional owner-only claim automation destination.
    #[must_use]
    pub fn claim_output(&self) -> Option<&Path> {
        self.claim_output.as_deref()
    }

    /// Returns the optional administrator-issued join grant.
    #[must_use]
    pub const fn join_grant(&self) -> Option<&JoinGrantBundle> {
        self.join_grant.as_ref()
    }
}

fn default_https_address() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), DEFAULT_HTTPS_PORT)
}

fn parse_address(value: &OsStr) -> Result<SocketAddr, HeadlessDaemonConfigError> {
    value
        .to_str()
        .and_then(|text| text.parse().ok())
        .ok_or(HeadlessDaemonConfigError::InvalidHttpsAddress)
}

fn parse_join_grant(value: &OsStr) -> Result<JoinGrantBundle, HeadlessDaemonConfigError> {
    let text = value
        .to_str()
        .ok_or(HeadlessDaemonConfigError::InvalidJoinGrant)?;
    JoinGrantBundle::parse(text).map_err(Into::into)
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), HeadlessDaemonConfigError> {
    if slot.replace(value).is_some() {
        Err(HeadlessDaemonConfigError::InvalidArguments)
    } else {
        Ok(())
    }
}

/// Stable process-configuration rejection which never echoes secrets or paths.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum HeadlessDaemonConfigError {
    /// Flag/value structure, a flag or a value is invalid.
    #[error("daemon arguments are invalid")]
    InvalidArguments,
    /// Exactly one daemon state directory is required.
    #[error("daemon state directory is required")]
    MissingStateDirectory,
    /// The HTTPS listen address is not one exact socket address.
    #[error("HTTPS listen address is invalid")]
    InvalidHttpsAddress,
    /// The join grant is not the exact supported canonical encoding.
    #[error("join grant is invalid")]
    InvalidJoinGrant,
    /// Storage path configuration is invalid.
    #[error("storage configuration is invalid")]
    Storage(#[from] StorageConfigError),
}

impl From<JoinGrantBundleError> for HeadlessDaemonConfigError {
    fn from(_: JoinGrantBundleError) -> Self {
        Self::InvalidJoinGrant
    }
}
