// SPDX-License-Identifier: GPL-2.0-only

//! Embedded SMB 3.1.1 protocol and service boundary.
//!
//! The crate owns the SMB wire contract. It does not own identities, permissions,
//! namespace semantics or provider paths; those remain behind `MeshSpan`'s shared
//! authentication and filesystem interfaces.

mod direct_tcp;
mod header;
mod negotiate;
mod negotiate_response;
mod ntlm_v2;
mod status;

pub use direct_tcp::{
    DirectTcpFrame, DirectTcpFrameError, DirectTcpFrameHeader, encode_direct_tcp_header,
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
pub use status::{ConnectorFailure, NtStatus};
