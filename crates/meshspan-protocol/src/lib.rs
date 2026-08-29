// SPDX-License-Identifier: GPL-2.0-only

//! Generated private wire messages plus strict bounded framing and validation.

mod framing;
mod validation;

pub use framing::{
    ValidatedControlEnvelope, ValidatedDataControlEnvelope, ValidatedDataFrame,
    ValidatedFederationEnvelope, WireContractError, WireLimits, decode_control_frame,
    decode_data_control_frame, decode_data_frame, decode_federation_frame, encode_control_frame,
    encode_data_control_frame, encode_data_frame, encode_federation_frame,
};

/// Generated version-one private wire messages.
#[allow(missing_docs, clippy::doc_markdown, clippy::must_use_candidate)]
pub mod v1 {
    include!(concat!(env!("OUT_DIR"), "/meshspan.private.v1.rs"));
}
