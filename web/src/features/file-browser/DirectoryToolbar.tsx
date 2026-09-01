// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, Show } from "solid-js";
import type { JSX } from "@solidjs/web";

import type { FileBrowserModel, VolumeSummary } from "./model";

export function DirectoryToolbar(
  props: Readonly<{ model: FileBrowserModel }>,
): JSX.Element {
  const path = () => props.model.directory()?.path ?? "";
  const writable = () =>
    props.model.mutationsAvailable() && canCreate(props.model.selectedVolume());
  return (
    <div class="directory-tools">
      <div class="directory-location">
        <button
          class="quiet-button"
          disabled={path() === "" || props.model.phase() !== "idle"}
          onClick={() => {
            void props.model.openParent().catch(() => undefined);
          }}
          type="button"
        >
          Up one folder
        </button>
        <p aria-label="Current folder" class="current-path">
          <span>{props.model.selectedVolume()?.name}</span>
          {path() === "" ? " /" : ` / ${path()}`}
        </p>
      </div>
      <Show
        when={writable()}
        fallback={
          <p class="field-note-reset">
            This volume is available to browse but not change in this session.
          </p>
        }
      >
        <div class="directory-mutations">
          <CreateDirectoryForm model={props.model} />
          <UploadControl model={props.model} />
        </div>
      </Show>
      <Show when={props.model.progress()}>
        {(progress) => (
          <progress
            aria-label="Upload progress"
            max={progress().total}
            value={progress().complete}
          />
        )}
      </Show>
    </div>
  );
}

function CreateDirectoryForm(
  props: Readonly<{ model: FileBrowserModel }>,
): JSX.Element {
  const [name, setName] = createSignal("");
  const submit: JSX.EventHandler<HTMLFormElement, SubmitEvent> = (event) => {
    event.preventDefault();
    const value = name();
    void props.model
      .createDirectory(value)
      .then(() => setName(""))
      .catch(() => undefined);
  };
  return (
    <form class="compact-action" onSubmit={submit}>
      <label>
        New folder name
        <input
          autocomplete="off"
          disabled={props.model.phase() !== "idle"}
          maxlength="255"
          onInput={(event) => setName(event.currentTarget.value)}
          required
          value={name()}
        />
      </label>
      <button
        class="quiet-button"
        disabled={props.model.phase() !== "idle"}
        type="submit"
      >
        Create folder
      </button>
    </form>
  );
}

function UploadControl(
  props: Readonly<{ model: FileBrowserModel }>,
): JSX.Element {
  const upload: JSX.EventHandler<HTMLInputElement, Event> = (event) => {
    const file = event.currentTarget.files?.[0];
    event.currentTarget.value = "";
    if (file !== undefined) {
      void props.model.uploadFile(file).catch(() => undefined);
    }
  };
  return (
    <label class="file-input-action">
      Upload a file
      <input
        disabled={props.model.phase() !== "idle"}
        onChange={upload}
        type="file"
      />
    </label>
  );
}

function canCreate(volume: VolumeSummary | undefined): boolean {
  return (
    volume?.state === "active" &&
    volume.effective_rights.includes("create_child")
  );
}
