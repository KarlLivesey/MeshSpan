-- SPDX-License-Identifier: GPL-2.0-only

-- Active-only keyset scans must not sort all allocations inside each target.
CREATE INDEX federation_storage_allocations_maintenance
ON federation_storage_allocations(provider_node_id, target_id, target_generation,
    valid_until, allocation_id) WHERE state = 1;
