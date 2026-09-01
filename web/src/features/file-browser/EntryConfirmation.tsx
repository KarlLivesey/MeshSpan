// SPDX-License-Identifier: GPL-2.0-only

import { Show } from "solid-js";
import type { JSX } from "@solidjs/web";

import type { DirectoryEntry } from "./model";

type EntryConfirmationProps = Readonly<{
  entry: DirectoryEntry;
  mode: "closed" | "rename" | "delete";
  name: string;
  onCancel: () => void;
  onDelete: () => void;
  onName: (name: string) => void;
  onRename: JSX.EventHandler<HTMLFormElement, SubmitEvent>;
}>;

export function EntryConfirmation(props: EntryConfirmationProps): JSX.Element {
  return (
    <>
      <Show when={props.mode === "rename"}>
        <form
          class="row-confirmation"
          onSubmit={(event) => {
            props.onRename(event);
          }}
        >
          <label>
            New name for {props.entry.name}
            <input
              maxlength="255"
              onInput={(event) => {
                props.onName(event.currentTarget.value);
              }}
              required
              value={props.name}
            />
          </label>
          <button class="quiet-button" type="submit">
            Save name
          </button>
          <button
            class="quiet-action"
            onClick={() => {
              props.onCancel();
            }}
            type="button"
          >
            Cancel
          </button>
        </form>
      </Show>
      <Show when={props.mode === "delete"}>
        <div class="row-confirmation">
          <p>
            Delete {props.entry.name}? This removes it from the current
            namespace.
          </p>
          <button
            class="quiet-button danger-action"
            onClick={() => {
              props.onDelete();
            }}
            type="button"
          >
            Confirm delete
          </button>
          <button
            class="quiet-action"
            onClick={() => {
              props.onCancel();
            }}
            type="button"
          >
            Cancel
          </button>
        </div>
      </Show>
    </>
  );
}
