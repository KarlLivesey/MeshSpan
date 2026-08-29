-- SPDX-License-Identifier: GPL-2.0-only

-- Administration views page by stable identities. These partial indexes keep
-- current configuration queries bounded without scanning revoked history.
CREATE INDEX permission_grants_active_by_subject_seek
ON permission_grants(subject_principal_id, grant_id)
WHERE state = 1;

CREATE INDEX permission_grants_active_by_scope_seek
ON permission_grants(scope_kind, volume_id, object_id, grant_id)
WHERE state = 1;

CREATE INDEX access_activations_live_by_principal_seek
ON access_activations(principal_id, activation_id)
WHERE revoked_at IS NULL;
