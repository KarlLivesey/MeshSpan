// SPDX-License-Identifier: GPL-2.0-only

//! Permission-filtered logical-volume inventory application and HTTP boundary.

mod api;
mod contract;
mod model;
mod service;

pub use api::{VolumeInventoryApiError, VolumeInventoryController, volume_inventory_api_router};
pub use contract::{VolumeInventoryAuthority, VolumeInventoryAuthorityError, VolumeInventoryError};
pub use service::VolumeInventoryService;
