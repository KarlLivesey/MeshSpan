// SPDX-License-Identifier: GPL-2.0-only

//! Authenticated logical-object metadata in the native specialised file API.

mod codec;
mod http;
mod service;

pub use http::{ObjectStatApiError, object_stat_api_router};
pub use service::{ObjectStatController, ObjectStatError, ObjectStatReader, ObjectStatService};
