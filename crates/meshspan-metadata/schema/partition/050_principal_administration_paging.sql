-- SPDX-License-Identifier: GPL-2.0-only

CREATE INDEX principals_by_kind_and_name
ON principals(principal_kind, canonical_name, principal_id);
