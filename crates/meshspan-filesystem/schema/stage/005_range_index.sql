-- SPDX-License-Identifier: GPL-2.0-only

CREATE TABLE stage_ranges (
    stage_id BLOB NOT NULL REFERENCES stages(stage_id) ON DELETE CASCADE
        CHECK (length(stage_id) = 16),
    range_start INTEGER NOT NULL CHECK (range_start >= 0),
    range_end INTEGER NOT NULL CHECK (range_end > range_start),
    PRIMARY KEY (stage_id, range_start)
) STRICT;

WITH ordered AS (
    SELECT
        stage_id,
        byte_offset AS range_start,
        byte_offset + byte_length AS range_end,
        MAX(byte_offset + byte_length) OVER (
            PARTITION BY stage_id
            ORDER BY byte_offset, mutation_sequence
            ROWS BETWEEN UNBOUNDED PRECEDING AND 1 PRECEDING
        ) AS previous_end
    FROM stage_writes
), islands AS (
    SELECT
        stage_id,
        range_start,
        range_end,
        SUM(CASE
            WHEN previous_end IS NULL OR range_start > previous_end THEN 1
            ELSE 0
        END) OVER (
            PARTITION BY stage_id
            ORDER BY range_start, range_end
            ROWS UNBOUNDED PRECEDING
        ) AS island
    FROM ordered
)
INSERT INTO stage_ranges(stage_id, range_start, range_end)
SELECT stage_id, MIN(range_start), MAX(range_end)
FROM islands
GROUP BY stage_id, island;

CREATE TRIGGER stage_ranges_reject_overlap
BEFORE INSERT ON stage_ranges
WHEN EXISTS (
    SELECT 1 FROM stage_ranges
    WHERE stage_id = NEW.stage_id
      AND range_start <= NEW.range_end
      AND range_end >= NEW.range_start
)
BEGIN
    SELECT RAISE(ABORT, 'stage range overlaps or adjoins existing coverage');
END;
