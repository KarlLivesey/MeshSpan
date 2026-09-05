// SPDX-License-Identifier: GPL-2.0-only

import type { JSX } from "@solidjs/web";
import type { ConfigureBackupScheduleRequest } from "../../generated";

export function BackupScheduleFields(
  props: Readonly<{
    policy: ConfigureBackupScheduleRequest["policy"] | undefined;
    disabled: boolean;
  }>,
): JSX.Element {
  return (
    <fieldset class="backup-fields" disabled={props.disabled}>
      <legend>Backup policy</legend>
      <label class="backup-checkbox">
        <input
          type="checkbox"
          name="enabled"
          checked={props.policy?.enabled ?? true}
        />
        Enable scheduled backups
      </label>
      <label>
        <span>Interval in seconds</span>
        <input
          name="interval_seconds"
          type="number"
          min="1"
          max="4294967295"
          step="1"
          required
          value={props.policy?.interval_seconds ?? 86400}
        />
      </label>
      <label>
        <span>Generations to retain</span>
        <input
          name="retained_generations"
          type="number"
          min="1"
          max="1024"
          step="1"
          required
          value={props.policy?.retained_generations ?? 3}
        />
      </label>
      <label>
        <span>Required verified copies</span>
        <input
          name="minimum_verified_copies"
          type="number"
          min="1"
          max="255"
          step="1"
          required
          value={props.policy?.minimum_verified_copies ?? 1}
        />
      </label>
      <label>
        <span>Required independent copies</span>
        <input
          name="minimum_independent_copies"
          type="number"
          min="0"
          max="255"
          step="1"
          required
          value={props.policy?.minimum_independent_copies ?? 0}
        />
        <small>
          Unknown or overlapping destinations do not meet this requirement.
        </small>
      </label>
    </fieldset>
  );
}
