// SPDX-License-Identifier: GPL-2.0-only

import { Show, createSignal } from "solid-js";
import type { JSX } from "@solidjs/web";

import type { RegisterStorageFolderRequest } from "../../generated";
import { StorageCapacityFields } from "./StorageCapacityFields";
import { createStorageCapacitySelection } from "./storage-capacity";

type UsageLimit = RegisterStorageFolderRequest["usage_limit"];

export function RegisterStorageFolderForm(
  props: Readonly<{
    register: (path: string, usageLimit: UsageLimit) => Promise<void>;
  }>,
): JSX.Element {
  const [path, setPath] = createSignal("");
  const [pending, setPending] = createSignal(false);
  const [error, setError] = createSignal<string>();
  const [success, setSuccess] = createSignal<string>();
  const capacity = createStorageCapacitySelection();

  const submit = async (event: SubmitEvent): Promise<void> => {
    event.preventDefault();
    if (pending()) return;
    const folderPath = path().trim();
    const usageLimit = capacity.value();
    if (!folderPath.startsWith("/") || usageLimit === undefined) {
      setError(invalidMessage(folderPath, usageLimit));
      return;
    }
    setPending(true);
    setError();
    setSuccess();
    try {
      await props.register(folderPath, usageLimit);
      setPath("");
      setSuccess("The folder is registered and serving storage work.");
    } catch {
      setError(
        "MeshSpan could not register that folder. Confirm it exists, is writable and is not already owned by another target.",
      );
    } finally {
      setPending(false);
    }
  };

  return (
    <form class="volume-create" onSubmit={(event) => void submit(event)}>
      <div class="section-heading">
        <p class="eyebrow">This node</p>
        <h2>Add a storage folder</h2>
      </div>
      <StorageFolderPathField
        disabled={pending()}
        path={path()}
        setPath={setPath}
      />
      <StorageCapacityFields disabled={pending()} selection={capacity} />
      <button class="primary-action" disabled={pending()} type="submit">
        {pending() ? "Opening folder…" : "Add storage folder"}
      </button>
      <div class="form-message" aria-live="polite">
        <Show when={error()}>
          {(message) => <p class="error">{message()}</p>}
        </Show>
        <Show when={success()}>
          {(message) => <p class="success">{message()}</p>}
        </Show>
      </div>
    </form>
  );
}

function StorageFolderPathField(
  props: Readonly<{
    disabled: boolean;
    path: string;
    setPath: (value: string) => void;
  }>,
): JSX.Element {
  return (
    <label class="volume-name-field">
      <span>Existing absolute path</span>
      <input
        autocomplete="off"
        disabled={props.disabled}
        maxlength="16384"
        onInput={(event) => {
          props.setPath(event.currentTarget.value);
        }}
        placeholder="/srv/meshspan-storage"
        value={props.path}
      />
      <small>
        MeshSpan owns only a private hidden subdirectory and does not read or
        expose sibling files.
      </small>
    </label>
  );
}

function invalidMessage(path: string, usageLimit: UsageLimit | undefined) {
  return path.startsWith("/") && usageLimit === undefined
    ? "Enter a valid positive capacity limit."
    : "Enter an absolute path on this node.";
}
