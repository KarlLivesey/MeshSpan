-- SPDX-License-Identifier: GPL-2.0-only

-- Existing pre-alpha inventories have no authenticated target-owner binding and therefore cannot
-- safely authorise completion. They remain readable only as corrupt/fail-closed state; every new
-- inventory item supplies the exact storage node explicitly.
ALTER TABLE version_cleanup_items
ADD COLUMN storage_node_id BLOB
    CHECK (storage_node_id IS NULL OR length(storage_node_id) = 16);
