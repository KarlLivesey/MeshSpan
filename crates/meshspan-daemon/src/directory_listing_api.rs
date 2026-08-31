// SPDX-License-Identifier: GPL-2.0-only

//! Authenticated directory pages in the native specialised file API.

mod codec;
mod http;
mod service;

pub use http::{DirectoryListingApiError, directory_listing_api_router};
pub use service::{
    DirectoryLister, DirectoryListingController, DirectoryListingError, DirectoryListingFailure,
    DirectoryListingService, FileApiAuthenticator,
};
