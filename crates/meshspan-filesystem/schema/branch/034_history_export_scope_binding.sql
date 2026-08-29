-- SPDX-License-Identifier: GPL-2.0-only

-- Active export sessions are transient capabilities. Discard pre-binding sessions rather than
-- guessing which external authority created them.
DELETE FROM namespace_history_exports;

ALTER TABLE namespace_history_exports
ADD COLUMN scope_binding BLOB NOT NULL
    DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000'
    CHECK (length(scope_binding) = 32);
