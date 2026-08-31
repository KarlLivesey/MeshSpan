// SPDX-License-Identifier: GPL-2.0-only

//! Provider-neutral Rustls integration for current stable Quinn.
//!
//! Quinn's public crypto traits are stable independently of its built-in Ring
//! and AWS-LC feature adapters. This crate binds a caller-supplied Rustls
//! configuration to those traits and supplies the endpoint/token keys needed to
//! construct Quinn without either built-in provider.

mod config;
mod endpoint_keys;
mod retry;
mod session;
mod version;

pub use config::{NoInitialCipherSuite, QuicClientConfig, QuicServerConfig};
pub use endpoint_keys::{EndpointKeyError, endpoint_config, server_config};
pub use session::HandshakeData;
