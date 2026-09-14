-- SPDX-License-Identifier: GPL-2.0-only

-- References only: content and history remain in their existing immutable owners.
CREATE TABLE namespace_delivery_journal (
    delivery_sequence INTEGER PRIMARY KEY AUTOINCREMENT,
    namespace_commit_id BLOB NOT NULL UNIQUE REFERENCES namespace_commits(namespace_commit_id),
    branch_id BLOB NOT NULL CHECK (length(branch_id) = 16)
) STRICT;

CREATE INDEX namespace_delivery_by_branch
ON namespace_delivery_journal(branch_id, delivery_sequence);

CREATE TABLE namespace_delivery_cursors (
    branch_id BLOB NOT NULL CHECK (length(branch_id) = 16),
    peer_node_id BLOB NOT NULL CHECK (length(peer_node_id) = 16),
    delivery_sequence INTEGER NOT NULL REFERENCES namespace_delivery_journal(delivery_sequence),
    PRIMARY KEY (branch_id, peer_node_id)
) STRICT;

-- Capture only published heads, in the same transaction as the head change. Imported
-- heads keep their original branch: adopting another node's head is not a local write.
CREATE TRIGGER namespace_delivery_insert AFTER INSERT ON branch_namespace_heads
BEGIN
    INSERT OR IGNORE INTO namespace_delivery_journal(namespace_commit_id, branch_id)
    SELECT namespace_commit_id, branch_id FROM namespace_commits
    WHERE namespace_commit_id = NEW.namespace_commit_id AND branch_id = NEW.branch_id;
END;

CREATE TRIGGER namespace_delivery_advance AFTER UPDATE OF namespace_commit_id ON branch_namespace_heads
BEGIN
    INSERT OR IGNORE INTO namespace_delivery_journal(namespace_commit_id, branch_id)
    SELECT namespace_commit_id, branch_id FROM namespace_commits
    WHERE namespace_commit_id = NEW.namespace_commit_id AND branch_id = NEW.branch_id;
END;

-- Existing reachable history is replayable too. Sequence is delivery order, never
-- consensus/causal order; the receiver independently verifies ancestry and cannot rewind.
WITH RECURSIVE published(namespace_commit_id) AS (
    SELECT namespace_commit_id FROM branch_namespace_heads
    UNION
    SELECT parents.parent_commit_id FROM namespace_commit_parents AS parents
    JOIN published ON published.namespace_commit_id = parents.namespace_commit_id
)
INSERT INTO namespace_delivery_journal(namespace_commit_id, branch_id)
SELECT commits.namespace_commit_id, commits.branch_id FROM namespace_commits AS commits
JOIN published ON published.namespace_commit_id = commits.namespace_commit_id
ORDER BY commits.namespace_commit_id;
