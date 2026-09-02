// SPDX-License-Identifier: GPL-2.0-only

//! Embedded SMB 3.1.1 protocol and service boundary.
//!
//! The crate owns the SMB wire contract. It does not own identities, permissions,
//! namespace semantics or provider paths; those remain behind `MeshSpan`'s shared
//! authentication and filesystem interfaces.

mod byte_range_lock;
mod close_flush;
mod command_dispatcher;
mod connection_control;
mod create;
mod direct_tcp;
mod file_id;
mod file_information;
mod file_io;
mod filesystem_adapter;
mod header;
mod negotiate;
mod negotiate_response;
mod ntlm_v2;
mod ntlm_wire;
mod protocol_connection;
mod query_directory;
mod secure_channel;
mod session_handshake;
mod session_keys;
mod session_setup;
mod signing;
mod spnego;
mod status;
mod transform;
mod tree_connect;

pub use byte_range_lock::{LockElement, LockKind, LockRequest, LockResponse, SmbLockError};
pub use close_flush::{
    CloseRequest, CloseResponse, CloseResponseAttributes, FlushRequest, SmbCloseFlushError,
};
pub use command_dispatcher::{
    SmbCommandDispatchError, SmbCommandDispatcher, SmbCommandDispatcherConfigurationError,
    SmbPublishedShare,
};
pub use connection_control::{
    EchoRequest, LogoffRequest, SmbConnectionControlError, SmbErrorResponse,
};
pub use create::{
    CreateAction, CreateDisposition, CreateOptions, CreateRequest, CreateResponse,
    CreateResponseValues, CreateTargetKind, SmbCreateError, SmbRequestedAccess, SmbShareAccess,
};
pub use direct_tcp::{
    DirectTcpFrame, DirectTcpFrameError, DirectTcpFrameHeader, encode_direct_tcp_header,
};
pub use file_id::SmbFileId;
pub use file_information::{
    FileInformationClass, FileInformationValues, QueryInfoRequest, QueryInfoResponse,
    SetFileInformation, SetInfoRequest, SmbFileInformationError,
};
pub use file_io::{ReadRequest, ReadResponse, SmbFileIoError, WriteRequest, WriteResponse};
pub use filesystem_adapter::{
    SmbCreateOutcome, SmbFilesystemAdapter, SmbFilesystemAdapterError, SmbFilesystemLimits,
    SmbTreeBinding,
};
pub use header::{Smb2Command, Smb2Header, Smb2HeaderError};
pub use negotiate::{
    NegotiateContext, NegotiateContextType, NegotiateRequest, NegotiateRequestError,
};
pub use negotiate_response::{
    EncryptionCipher, NegotiateResponse, NegotiateResponseConfig, NegotiateResponseError,
    NegotiateSelection, SigningAlgorithm,
};
pub use ntlm_v2::{NtlmPasswordVerifier, NtlmSessionBaseKey, NtlmVerificationError};
pub use ntlm_wire::{
    NtlmAuthenticate, NtlmChallenge, NtlmChallengeConfig, NtlmNegotiate, NtlmWireError,
};
pub use protocol_connection::{
    SmbConnectionHandshakeConfig, SmbEstablishedSessionServices, SmbProtocolConnection,
    SmbProtocolConnectionError,
};
pub use query_directory::{
    DirectoryInformationClass, DirectoryResponseEntry, QueryDirectoryRequest,
    QueryDirectoryResponse, SmbQueryDirectoryError,
};
pub use secure_channel::{SmbSecureChannel, SmbSecureChannelError};
pub use session_handshake::{
    AuthenticatedSmbSession, SmbSessionAuthenticator, SmbSessionEstablishmentError,
    SmbSessionHandshake, SmbSessionHandshakeError,
};
pub use session_keys::{Smb311PreauthHash, Smb311SessionKeys, SmbSessionKeyError};
pub use session_setup::{
    SessionSetupRequest, SessionSetupResponse, SessionSetupResponseConfig, SmbSessionSetupError,
};
pub use signing::{SmbPacketSender, SmbSigningError, sign_smb311, verify_smb311};
pub use spnego::{
    NtlmTokenKind, SpnegoClientToken, SpnegoTokenError, encode_spnego_challenge,
    encode_spnego_complete,
};
pub use status::{ConnectorFailure, NtStatus};
pub use transform::{Smb311Transform, SmbTransformError};
pub use tree_connect::{
    SmbTreeConnectError, TreeConnectRequest, TreeConnectResponse, TreeConnectResponseConfig,
    TreeDisconnectRequest,
};
