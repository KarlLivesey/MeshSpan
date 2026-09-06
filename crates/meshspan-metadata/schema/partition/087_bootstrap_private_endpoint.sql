-- SPDX-License-Identifier: GPL-2.0-only

-- Founding nodes are already active: do not invent a staged enrolment/activation for them.
ALTER TABLE nodes ADD COLUMN bootstrap_private_endpoint TEXT
    CHECK (bootstrap_private_endpoint IS NULL OR length(bootstrap_private_endpoint) BETWEEN 3 AND 512);

CREATE UNIQUE INDEX nodes_bootstrap_private_endpoint ON nodes(bootstrap_private_endpoint);

CREATE TRIGGER node_activation_rejects_bootstrap_endpoint
BEFORE INSERT ON node_activations
WHEN EXISTS (SELECT 1 FROM nodes WHERE bootstrap_private_endpoint = NEW.private_endpoint)
BEGIN
    SELECT RAISE(ABORT, 'private endpoint already belongs to a founding node');
END;
