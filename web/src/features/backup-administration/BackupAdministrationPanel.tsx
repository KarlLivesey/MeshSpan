// SPDX-License-Identifier: GPL-2.0-only

import { Show, untrack } from "solid-js";
import type { JSX } from "@solidjs/web";

import { AdministrationNavigation } from "../administration/AdministrationNavigation";
import { BackupScheduleForm } from "./BackupScheduleForm";
import { BackupDestinations } from "./BackupDestinations";
import { AddBackupDestination } from "./AddBackupDestination";
import {
  createBackupAdministration,
  type BackupAdministrationClient,
} from "./model";

export function BackupAdministrationPanel(
  props: Readonly<{
    client: BackupAdministrationClient;
    csrfToken: string;
  }>,
): JSX.Element {
  const model = createBackupAdministration(
    () => props.client,
    () => props.csrfToken,
  );
  untrack(() => void model.load());
  return (
    <div class="backup-administration">
      <header class="page-intro">
        <p class="eyebrow">Administration / Recovery</p>
        <h1>Metadata backups</h1>
        <p>
          Encrypted recovery copies of mesh settings and metadata. File content
          is protected separately by your volume policies.
        </p>
      </header>
      <AdministrationNavigation current="backups" />
      <div class="section-heading">
        <p>
          MeshSpan chooses defaults automatically. Change them only when you
          need a different policy.
        </p>
        <button
          type="button"
          class="quiet-action"
          disabled={model.locked()}
          onClick={() => void model.load()}
        >
          Refresh settings
        </button>
      </div>
      <div aria-live="polite">
        <Show when={model.error()}>
          {(message) => <p class="error">{message()}</p>}
        </Show>
        <Show when={model.notice()}>
          {(message) => <p class="success">{message()}</p>}
        </Show>
        <Show when={model.phase() === "loading"}>
          <p>Reading backup settings…</p>
        </Show>
        <Show when={model.phase() === "saving"}>
          <p>Confirming the change…</p>
        </Show>
        <Show when={model.pending() && model.phase() === "idle"}>
          <button type="button" onClick={() => void model.retry()}>
            Retry pending change
          </button>
        </Show>
      </div>
      <Show when={model.view()}>
        {(view) => (
          <>
            <BackupScheduleForm
              schedule={view().schedule.schedule}
              model={model}
            />
            <BackupDestinations
              model={model}
              destinations={view().destinations}
            />
            <AddBackupDestination model={model} targets={view().targets} />
          </>
        )}
      </Show>
    </div>
  );
}
