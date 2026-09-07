-- SPDX-License-Identifier: GPL-2.0-only

-- A random nonce inside the encrypted plaintext makes this commitment unsuitable
-- for guessing destination credentials. Recipient redistribution preserves it.
-- Pre-API configurations have no binding and cannot be delivered until replaced.
ALTER TABLE notification_channel_configurations ADD COLUMN settings_commitment BLOB
    NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000'
    CHECK(length(settings_commitment) = 32);
