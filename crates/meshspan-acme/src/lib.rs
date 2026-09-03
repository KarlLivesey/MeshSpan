// SPDX-License-Identifier: GPL-2.0-only

//! In-process, bounded ACME challenge primitives with no external runtime service dependency.

mod challenge_payload;
mod component;
mod dns01;
mod http01;

pub use challenge_payload::{Dns01Payload, Http01Payload, PayloadError};
pub use dns01::{Dns01Challenge, DnsTxtProvider, DnsTxtReceipt};
pub use http01::Http01Challenge;

#[cfg(test)]
mod tests;
