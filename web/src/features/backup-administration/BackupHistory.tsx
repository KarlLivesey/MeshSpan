// SPDX-License-Identifier: GPL-2.0-only

import { For, Show, untrack } from "solid-js";
import type { JSX } from "@solidjs/web";
import { instantFromEpochMicroseconds } from "../../domain/instant";
import type { ListBackupRunsResponse } from "../../generated";
import { createBackupHistory, type BackupHistoryClient } from "./history";

type BackupRunSummary = ListBackupRunsResponse["runs"][number];

export function BackupHistory(
  props: Readonly<{ client: BackupHistoryClient }>,
): JSX.Element {
  const model = createBackupHistory(() => props.client);
  untrack(() => void model.load());
  return (
    <section class="topology-section" aria-labelledby="backup-history-heading">
      <div class="section-heading">
        <h2 id="backup-history-heading">Backup history</h2>
        <button
          type="button"
          class="quiet-action"
          disabled={model.loading()}
          onClick={() => void model.load()}
        >
          Refresh history
        </button>
      </div>
      <p>
        Newest attempts first. Completed protection describes that moment; it
        does not prove a backup is recoverable now.
      </p>
      <div aria-live="polite">
        <Show when={model.loading()}>
          <p>Reading backup history…</p>
        </Show>
        <Show when={model.error()}>
          {(error) => <p class="error">{error()}</p>}
        </Show>
      </div>
      <Show when={model.page()}>
        {(page) => (
          <>
            <Show
              when={page().runs.length > 0}
              fallback={
                <p>
                  No backup attempts have been recorded yet. An enabled schedule
                  starts attempts automatically.
                </p>
              }
            >
              <ol class="backup-destinations" aria-label="Backup attempts">
                <For each={page().runs}>
                  {(run) => <BackupHistoryEntry run={run} />}
                </For>
              </ol>
            </Show>
            <Show when={page().next_page_url}>
              {(next) => (
                <button
                  type="button"
                  disabled={model.loading()}
                  onClick={() => void model.load(next())}
                >
                  Older attempts
                </button>
              )}
            </Show>
          </>
        )}
      </Show>
    </section>
  );
}

function BackupHistoryEntry(
  props: Readonly<{ run: BackupRunSummary }>,
): JSX.Element {
  return (
    <li>
      <div>
        <h3>Attempt {props.run.run_sequence}</h3>
        <p>{outcome(props.run.state)}</p>
        <p>Scheduled: {formatInstant(props.run.scheduled_for_epoch_micros)}</p>
        <Show when={props.run.completed_at_epoch_micros !== null}>
          <p>Completed: {formatInstant(props.run.completed_at_epoch_micros)}</p>
        </Show>
        <small>
          Required copies: {props.run.minimum_verified_copies}, including{" "}
          {props.run.minimum_independent_copies} independent.
        </small>
        <details>
          <summary>Backup identity</summary>
          <p>{props.run.backup_id}</p>
          <p>Policy revision {props.run.schedule_sequence}</p>
        </details>
      </div>
    </li>
  );
}

function outcome(state: BackupRunSummary["state"]): string {
  switch (state) {
    case "queued":
      return "Queued";
    case "claimed":
      return "Assigned to a worker";
    case "recorded":
      return "Copy recorded; protection not yet confirmed";
    case "protected":
      return "Required protection met at completion";
    case "incomplete":
      return "Incomplete — required protection was not met";
  }
}

function formatInstant(value: number | null): string {
  return value === null
    ? "Not completed"
    : instantFromEpochMicroseconds(value).toString();
}
