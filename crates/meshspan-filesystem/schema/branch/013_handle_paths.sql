-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE open_handle_path_components (
    handle_id BLOB NOT NULL REFERENCES open_handles(handle_id)
        CHECK (length(handle_id) = 16),
    component_ordinal INTEGER NOT NULL CHECK (component_ordinal BETWEEN 0 AND 1023),
    display_name TEXT NOT NULL CHECK (length(display_name) BETWEEN 1 AND 16384),
    canonical_name TEXT NOT NULL CHECK (length(canonical_name) BETWEEN 1 AND 16384),
    PRIMARY KEY (handle_id, component_ordinal)
) STRICT;
