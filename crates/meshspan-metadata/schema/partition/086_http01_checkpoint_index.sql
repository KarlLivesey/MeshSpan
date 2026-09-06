-- SPDX-License-Identifier: GPL-2.0-only

-- This is a derived lookup, not a second certificate or publication authority.
ALTER TABLE certificate_order_checkpoints ADD COLUMN http01_token TEXT;
CREATE INDEX certificate_order_checkpoints_http01_token
    ON certificate_order_checkpoints(http01_token);
