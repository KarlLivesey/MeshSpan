-- SPDX-License-Identifier: GPL-2.0-only

-- Federation authority exchange seeks by the latest grant revision and stable
-- grant identity. This index keeps every page bounded to one relationship.
CREATE INDEX federation_grants_by_relationship_revision
ON federation_grants(relationship_id, revision, grant_id);
