// SPDX-License-Identifier: GPL-2.0-only

//! Evict uncertain connections when a control future fails or is cancelled by its caller.

use std::collections::BTreeMap;
use std::sync::Mutex;

use meshspan_domain::NodeId;

pub(super) struct ControlConnectionUse<'a> {
    cache: &'a Mutex<BTreeMap<NodeId, quinn::Connection>>,
    peer: NodeId,
    connection_id: usize,
    confirmed: bool,
}

impl<'a> ControlConnectionUse<'a> {
    pub(super) const fn new(
        cache: &'a Mutex<BTreeMap<NodeId, quinn::Connection>>,
        peer: NodeId,
        connection_id: usize,
    ) -> Self {
        Self {
            cache,
            peer,
            connection_id,
            confirmed: false,
        }
    }

    pub(super) const fn confirm_response(&mut self) {
        self.confirmed = true;
    }
}

impl Drop for ControlConnectionUse<'_> {
    fn drop(&mut self) {
        if self.confirmed {
            return;
        }
        // No lock spans IO. Poison already makes the cache unavailable to all callers;
        // Drop cannot report a second error. Never remove a newer replacement connection.
        if let Ok(mut cache) = self.cache.lock()
            && cache
                .get(&self.peer)
                .is_some_and(|entry| entry.stable_id() == self.connection_id)
        {
            cache.remove(&self.peer);
        }
        // Eviction does not close other in-flight streams, retry an operation or imply that
        // remote work was undone. Their owners retain their own connection references.
    }
}
