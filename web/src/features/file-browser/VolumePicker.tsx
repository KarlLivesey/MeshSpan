// SPDX-License-Identifier: GPL-2.0-only

import { For, Show } from "solid-js";
import type { JSX } from "@solidjs/web";

import type { FileBrowserModel } from "./model";

export function VolumePicker(
  props: Readonly<{ model: FileBrowserModel }>,
): JSX.Element {
  const select: JSX.EventHandler<HTMLSelectElement, Event> = (event) => {
    void props.model
      .selectVolume(event.currentTarget.value)
      .catch(() => undefined);
  };
  return (
    <label class="volume-picker">
      Volume
      <select
        aria-label="Volume"
        disabled={props.model.phase() !== "idle"}
        onChange={select}
        value={props.model.selectedVolume()?.volume_id}
      >
        <For each={props.model.volumes()}>
          {(volume) => (
            <option value={volume.volume_id}>
              {volume.name} · {volume.state}
            </option>
          )}
        </For>
      </select>
      <Show when={props.model.volumeNextPageUrl() !== null}>
        <button
          class="quiet-action"
          disabled={props.model.phase() !== "idle"}
          onClick={() => {
            void props.model.loadMoreVolumes();
          }}
          type="button"
        >
          Load more volumes
        </button>
      </Show>
    </label>
  );
}
