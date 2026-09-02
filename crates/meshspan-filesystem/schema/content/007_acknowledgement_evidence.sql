-- SPDX-License-Identifier: GPL-2.0-only

ALTER TABLE content_publications
ADD COLUMN acknowledgement_class INTEGER NOT NULL DEFAULT 1
CHECK (acknowledgement_class IN (1, 2));

ALTER TABLE content_publications
ADD COLUMN acknowledgement_scope INTEGER NOT NULL DEFAULT 1
CHECK (acknowledgement_scope IN (1, 2));
