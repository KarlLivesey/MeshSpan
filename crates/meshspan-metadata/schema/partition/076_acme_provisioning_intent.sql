-- SPDX-License-Identifier: GPL-2.0-only

-- Exact public retries must be comparable without retaining plaintext provider credentials or
-- depending on randomized encrypted command bytes.
ALTER TABLE acme_configurations
ADD COLUMN provisioning_intent_digest BLOB
CHECK (
    provisioning_intent_digest IS NULL
    OR length(provisioning_intent_digest) = 32
);
