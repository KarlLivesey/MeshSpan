// SPDX-License-Identifier: GPL-2.0-only

import { For, Show, createSignal } from "solid-js";
import type { JSX } from "@solidjs/web";
import type { ListTopologyTargetsResponse } from "../../generated";
import type { BackupAdministration } from "./model";
import { destinationRequest } from "./requests";

export function AddBackupDestination(
  props: Readonly<{
    model: BackupAdministration;
    targets: ListTopologyTargetsResponse;
  }>,
): JSX.Element {
  const [error, setError] = createSignal<string>();
  const submit = async (event: SubmitEvent): Promise<void> => {
    event.preventDefault();
    if (
      props.model.locked() ||
      !(event.currentTarget instanceof HTMLFormElement)
    )
      return;
    setError();
    try {
      const form = event.currentTarget;
      const request = destinationRequest(
        new FormData(form),
        props.targets.targets,
      );
      if (await props.model.save({ kind: "destination", request }))
        form.reset();
    } catch {
      setError(
        "Enter a destination name and choose an active registered folder.",
      );
    }
  };
  return (
    <details class="backup-settings">
      <summary>Add a registered-folder destination</summary>
      <form onSubmit={(event) => void submit(event)}>
        <p>
          Use an existing storage folder anywhere in this mesh. No new folder
          path or credentials are needed.
        </p>
        <label>
          <span>Destination name</span>
          <input
            name="name"
            maxlength="128"
            required
            disabled={props.model.locked()}
          />
        </label>
        <BackupTargetPicker model={props.model} targets={props.targets} />
        <button
          class="primary-action"
          type="submit"
          disabled={props.model.locked()}
        >
          Add backup destination
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
  );
}

function BackupTargetPicker(
  props: Readonly<{
    model: BackupAdministration;
    targets: ListTopologyTargetsResponse;
  }>,
): JSX.Element {
  return (
    <>
      <label>
        <span>Registered storage folder</span>
        <select name="target_id" required disabled={props.model.locked()}>
          <option value="">Choose a folder</option>
          <For
            each={props.targets.targets.filter(
              (target) => target.state === "active",
            )}
          >
            {(target) => (
              <option value={target.target_id}>
                {target.display_name} · machine {target.host_id}
              </option>
            )}
          </For>
        </select>
      </label>
      <Show when={props.targets.next_page_url !== null}>
        <button
          type="button"
          disabled={props.model.locked()}
          onClick={() => void props.model.loadMore("targets")}
        >
          Show more storage folders
        </button>
      </Show>
    </>
  );
}
