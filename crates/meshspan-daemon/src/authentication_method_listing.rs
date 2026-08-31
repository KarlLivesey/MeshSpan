// SPDX-License-Identifier: GPL-2.0-only

//! Current-user authentication-method inventory application and HTTP boundary.

mod api;
mod contract;
mod model;
mod service;

pub use api::{
    AuthenticationMethodListingApiError, AuthenticationMethodListingController,
    authentication_method_listing_api_router,
};
pub use contract::{
    AuthenticationMethodListingAuthority, AuthenticationMethodListingAuthorityError,
    AuthenticationMethodListingError,
};
pub use service::AuthenticationMethodListingService;
