// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, Show } from "solid-js";
import type { JSX } from "@solidjs/web";

import { EntryConfirmation } from "./EntryConfirmation";
import type { DirectoryEntry, FileBrowserModel } from "./model";

type EntryActionsProps = Readonly<{
  entry: DirectoryEntry;
  model: FileBrowserModel;
}>;

export function EntryActions(props: EntryActionsProps): JSX.Element {
  const [mode, setMode] = createSignal<"closed" | "rename" | "delete">(
    "closed",
  );
  const [name, setName] = createSignal("");
  const volume = () => props.model.selectedVolume();
  const canRename = () =>
    props.model.mutationsAvailable() &&
    volume()?.effective_rights.includes("rename") === true;
  const canDelete = () =>
    props.model.mutationsAvailable() &&
    volume()?.effective_rights.includes("delete") === true;
  const submitRename: JSX.EventHandler<HTMLFormElement, SubmitEvent> = (
    event,
  ) => {
    event.preventDefault();
    void props.model
      .renameEntry(props.entry, name())
      .then(() => setMode("closed"))
      .catch(() => undefined);
  };
  const remove = (): void => {
    void props.model
      .deleteEntry(props.entry)
      .then(() => setMode("closed"))
      .catch(() => undefined);
  };
  const beginRename = (): void => {
    setName(props.entry.name);
    setMode("rename");
  };
  return (
    <>
      <Show when={canRename()}>
        <button
          class="quiet-action table-action"
          onClick={beginRename}
          type="button"
        >
          Rename
        </button>
      </Show>
      <Show when={canDelete()}>
        <button
          class="quiet-action danger-action table-action"
          onClick={() => setMode("delete")}
          type="button"
        >
          Delete
        </button>
      </Show>
      <EntryConfirmation
        entry={props.entry}
        mode={mode()}
        name={name()}
        onCancel={() => setMode("closed")}
        onDelete={remove}
        onName={setName}
        onRename={submitRename}
      />
    </>
  );
}
