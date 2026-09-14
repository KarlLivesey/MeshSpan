-- SPDX-License-Identifier: GPL-2.0-only

-- Only durable local publications or fully accepted remote publications enter this frontier.
CREATE TABLE namespace_convergence_frontier (
    volume_id BLOB NOT NULL CHECK (length(volume_id) = 16),
    namespace_commit_id BLOB NOT NULL REFERENCES namespace_commits(namespace_commit_id),
    PRIMARY KEY (volume_id, namespace_commit_id)
) STRICT;

CREATE TRIGGER namespace_convergence_enqueue AFTER INSERT ON namespace_delivery_journal
BEGIN
    INSERT OR IGNORE INTO namespace_convergence_frontier(volume_id, namespace_commit_id)
    SELECT volume_id, namespace_commit_id FROM namespace_commits
    WHERE namespace_commit_id = NEW.namespace_commit_id;
END;

INSERT INTO namespace_convergence_frontier(volume_id, namespace_commit_id)
SELECT DISTINCT c.volume_id, c.namespace_commit_id FROM namespace_commits c
JOIN namespace_delivery_journal j USING(namespace_commit_id);

-- Persist the application and authority-attempt identity before either side effect.
CREATE TABLE namespace_convergence_jobs (
    volume_id BLOB PRIMARY KEY CHECK (length(volume_id) = 16),
    expected_commit_id BLOB REFERENCES namespace_commits(namespace_commit_id),
    selected_commit_id BLOB NOT NULL CHECK (length(selected_commit_id) = 16),
    merge_required INTEGER NOT NULL CHECK (merge_required IN (0, 1)),
    operation_id BLOB NOT NULL UNIQUE CHECK (length(operation_id) = 16),
    merge_commit_id BLOB NOT NULL UNIQUE CHECK (length(merge_commit_id) = 16),
    actor_principal_id BLOB NOT NULL CHECK (length(actor_principal_id) = 16),
    retain_history INTEGER NOT NULL CHECK (retain_history IN (0, 1)),
    retention_policy_sequence INTEGER NOT NULL CHECK (retention_policy_sequence > 0),
    created_at INTEGER NOT NULL,
    CHECK (merge_required = 0 OR expected_commit_id IS NOT NULL)
) STRICT;

CREATE TABLE namespace_convergence_job_heads (
    volume_id BLOB NOT NULL REFERENCES namespace_convergence_jobs(volume_id) ON DELETE CASCADE,
    namespace_commit_id BLOB NOT NULL REFERENCES namespace_commits(namespace_commit_id),
    PRIMARY KEY (volume_id, namespace_commit_id)
) STRICT;
