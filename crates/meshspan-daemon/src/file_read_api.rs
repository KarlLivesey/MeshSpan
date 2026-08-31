// SPDX-License-Identifier: GPL-2.0-only

//! Authenticated bounded bytes in the native specialised file API.

mod codec;
mod http;
mod service;

pub use http::{FileReadApiError, file_read_api_router};
pub use service::{
    FileRangeReader, FileReadController, FileReadError, FileReadResult, FileReadService,
};
