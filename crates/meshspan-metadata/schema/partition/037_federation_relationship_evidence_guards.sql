-- SPDX-License-Identifier: GPL-2.0-only

-- Current relationship, trust and governance rows are updated only by their
-- typed lifecycle transitions. They must never disappear and sever retained
-- evidence from the relationship identity which produced it.
CREATE TRIGGER federation_relationships_reject_delete
BEFORE DELETE ON federation_relationships
BEGIN
    SELECT RAISE(ABORT, 'federation relationship identity is retained');
END;

CREATE TRIGGER federation_trust_identities_reject_delete
BEFORE DELETE ON federation_trust_identities
BEGIN
    SELECT RAISE(ABORT, 'federation trust identity history is retained');
END;

CREATE TRIGGER federation_governance_edges_reject_delete
BEFORE DELETE ON federation_governance_edges
BEGIN
    SELECT RAISE(ABORT, 'federation governance edge history is retained');
END;
