// SPDX-License-Identifier: GPL-2.0-only

import { Show, createSignal } from "solid-js";
import type { JSX } from "@solidjs/web";

import { instantFromEpochMicroseconds } from "../../domain/instant";
import type { BackupScheduleResponse } from "../../generated";
import type { BackupAdministration } from "./model";
import { scheduleRequest } from "./requests";
import { BackupScheduleFields } from "./BackupScheduleFields";

export function BackupScheduleForm(
  props: Readonly<{
    schedule: BackupScheduleResponse["schedule"];
    model: BackupAdministration;
  }>,
): JSX.Element {
  const [error, setError] = createSignal<string>();
  const submit = (event: SubmitEvent): void => {
    event.preventDefault();
    if (
      props.model.locked() ||
      !(event.currentTarget instanceof HTMLFormElement)
    )
      return;
    setError();
    try {
      const request = scheduleRequest(
        new FormData(event.currentTarget),
        props.schedule?.sequence ?? 0,
      );
      void props.model.save({ kind: "schedule", request });
    } catch {
      setError(
        "Check the whole-number limits. Independent copies must not exceed verified copies.",
      );
    }
  };
  return (
    <section class="topology-section" aria-labelledby="backup-schedule-heading">
      <BackupScheduleSummary schedule={props.schedule} />
      <details class="backup-settings">
        <summary>Customise schedule</summary>
        <form onSubmit={submit}>
          <p>
            Saving makes this an explicit policy; future topology changes will
            not replace it.
          </p>
          <BackupScheduleFields
            policy={props.schedule?.policy}
            disabled={props.model.locked()}
          />
          <button
            class="primary-action"
            type="submit"
            disabled={props.model.locked()}
          >
            Save backup schedule
          </button>
          <Show when={error()}>
            {(message) => (
              <p class="error" role="alert">
                {message()}
              </p>
            )}
          </Show>
        </form>
      </details>
    </section>
  );
}

function BackupScheduleSummary(
  props: Readonly<{ schedule: BackupScheduleResponse["schedule"] }>,
): JSX.Element {
  const state = (): string => {
    if (props.schedule === null) return "Not configured";
    return props.schedule.policy.enabled ? "Enabled" : "Paused";
  };
  return (
    <>
      <div class="section-heading">
        <h2 id="backup-schedule-heading">Schedule and retention</h2>
        <span class="state-pill">{state()}</span>
      </div>
      <Show
        when={props.schedule}
        fallback={
          <p>
            Defaults appear after storage is registered. You can also set a
            policy below.
          </p>
        }
      >
        {(schedule) => (
          <>
            <p>
              Keep {schedule().policy.retained_generations} usable generations;
              require {schedule().policy.minimum_verified_copies} verified
              copies.
            </p>
            <p>
              Interval: {schedule().policy.interval_seconds} seconds. Next
              eligible attempt:{" "}
              {formatTime(schedule().next_due_at_epoch_micros)}.
            </p>
          </>
        )}
      </Show>
      <p class="backup-caution">
        An enabled schedule is not proof of a completed or recoverable backup.
      </p>
    </>
  );
}

function formatTime(value: number): string {
  return instantFromEpochMicroseconds(value).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}
