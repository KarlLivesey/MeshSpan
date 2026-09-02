-- SPDX-License-Identifier: GPL-2.0-only

-- Old pre-alpha jobs did not record their bounded execution footprint. NULL makes those rows
-- ineligible until fresh evidence coalesces an exact positive demand into the job.
ALTER TABLE maintenance_work_jobs
ADD COLUMN in_flight_bytes INTEGER NULL
CHECK (in_flight_bytes IS NULL OR in_flight_bytes > 0);
