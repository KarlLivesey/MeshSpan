-- SPDX-License-Identifier: GPL-2.0-only

-- Stable system classes let policy records refer to ordinary machine and storage-device failures
-- without manufacturing one administrator-defined class per mesh.
INSERT INTO fault_group_classes(
    class_id, canonical_name, revision, display_name, class_kind, system_managed
) VALUES (
    X'6d6573687370816ead6d616368696e65',
    'machine',
    1,
    'Machine',
    1,
    1
);

INSERT INTO fault_group_classes(
    class_id, canonical_name, revision, display_name, class_kind, system_managed
) VALUES (
    X'6d6573687370826eae64657669636521',
    'storage device',
    1,
    'Storage device',
    2,
    1
);
