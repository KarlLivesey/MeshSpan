-- SPDX-License-Identifier: GPL-2.0-only

CREATE INDEX maintenance_repair_effects_scope_order
    ON maintenance_repair_effects(volume_id, manifest_id, revision, effect_operation_id);
