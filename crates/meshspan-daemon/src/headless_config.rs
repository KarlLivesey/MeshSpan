// SPDX-License-Identifier: GPL-2.0-only

//! Strict bounded configuration for the headless appliance process.

use std::ffi::{OsStr, OsString};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};

use meshspan_domain::{JoinGrantBundle, JoinGrantBundleError};
use meshspan_storage::{HeadlessStorageConfig, StorageConfigError};
use thiserror::Error;

const DEFAULT_HTTPS_PORT: u16 = 8_443;
const DEFAULT_SMB_PORT: u16 = 445;
const DEFAULT_PRIVATE_PORT: u16 = 7_443;
const MAXIMUM_STORAGE_PATHS: usize = 1_024;
const SINGLETON_FLAGS: usize = 7;
const MAXIMUM_ARGUMENTS: usize = (MAXIMUM_STORAGE_PATHS + SINGLETON_FLAGS) * 2;

/// Validated local process settings which never include replicated mesh configuration.
///
/// The type deliberately omits `Debug` because it may own a secret join grant.
pub struct HeadlessDaemonConfig {
    storage: HeadlessStorageConfig,
    https_listen: SocketAddr,
    smb_listen: SocketAddr,
    private_listen: SocketAddr,
    private_endpoint: Option<String>,
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
        let mut smb_listen = None;
        let mut private_listen = None;
        let mut private_endpoint = None;
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
                    set_once(&mut https_listen, parse_https_address(&pair[1])?)?;
                }
                value if value == OsStr::new("--smb-listen") => {
                    set_once(&mut smb_listen, parse_smb_address(&pair[1])?)?;
                }
                value if value == OsStr::new("--private-listen") => {
                    set_once(&mut private_listen, parse_private_address(&pair[1])?)?;
                }
                value if value == OsStr::new("--private-endpoint") => {
                    set_once(&mut private_endpoint, parse_private_endpoint(&pair[1])?)?;
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
            smb_listen: smb_listen.unwrap_or_else(default_smb_address),
            private_listen: private_listen.unwrap_or_else(default_private_address),
            private_endpoint,
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

    /// Returns the embedded SMB Direct TCP listener address.
    #[must_use]
    pub const fn smb_listen(&self) -> SocketAddr {
        self.smb_listen
    }

    /// Returns the private Quinn/mTLS listener address.
    #[must_use]
    pub const fn private_listen(&self) -> SocketAddr {
        self.private_listen
    }

    /// Returns the explicitly advertised private endpoint, if supplied.
    #[must_use]
    pub fn private_endpoint(&self) -> Option<&str> {
        self.private_endpoint.as_deref()
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

fn default_smb_address() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), DEFAULT_SMB_PORT)
}

fn default_private_address() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), DEFAULT_PRIVATE_PORT)
}

fn parse_https_address(value: &OsStr) -> Result<SocketAddr, HeadlessDaemonConfigError> {
    value
        .to_str()
        .and_then(|text| text.parse().ok())
        .ok_or(HeadlessDaemonConfigError::InvalidHttpsAddress)
}

fn parse_smb_address(value: &OsStr) -> Result<SocketAddr, HeadlessDaemonConfigError> {
    value
        .to_str()
        .and_then(|text| text.parse().ok())
        .ok_or(HeadlessDaemonConfigError::InvalidSmbAddress)
}

fn parse_private_address(value: &OsStr) -> Result<SocketAddr, HeadlessDaemonConfigError> {
    value
        .to_str()
        .and_then(|text| text.parse().ok())
        .ok_or(HeadlessDaemonConfigError::InvalidPrivateAddress)
}

fn parse_private_endpoint(value: &OsStr) -> Result<String, HeadlessDaemonConfigError> {
    let value = value
        .to_str()
        .filter(|value| {
            (3..=512).contains(&value.len())
                && value.bytes().all(|byte| {
                    byte.is_ascii_lowercase()
                        || byte.is_ascii_digit()
                        || matches!(byte, b'.' | b':' | b'[' | b']' | b'-')
                })
        })
        .ok_or(HeadlessDaemonConfigError::InvalidPrivateEndpoint)?;
    Ok(value.to_owned())
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
    /// The embedded SMB listener is not one exact socket address.
    #[error("SMB listen address is invalid")]
    InvalidSmbAddress,
    /// The private Quinn listener is not one exact socket address.
    #[error("private listener address is invalid")]
    InvalidPrivateAddress,
    /// The advertised private endpoint is not a bounded DNS name or IP socket address.
    #[error("advertised private endpoint is invalid")]
    InvalidPrivateEndpoint,
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
