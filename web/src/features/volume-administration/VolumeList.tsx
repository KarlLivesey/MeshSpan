// SPDX-License-Identifier: GPL-2.0-only

import { For, Show } from "solid-js";
import type { JSX } from "@solidjs/web";

import { instantFromEpochMicroseconds } from "../../domain/instant";
import type { AdminVolume, VolumeDirectory } from "./model";

export function VolumeList(
  props: Readonly<{
    directory: VolumeDirectory;
    onSelect: (volume: AdminVolume) => void;
    selectedVolumeId: string | undefined;
  }>,
): JSX.Element {
  return (
    <section class="volume-list" aria-labelledby="volume-list-heading">
      <div class="principal-list-heading">
        <div>
          <p class="eyebrow">Current storage</p>
          <h2 id="volume-list-heading">Volumes</h2>
        </div>
        <span class="record-count">{props.directory.items().length}</span>
      </div>
      <Show
        when={props.directory.phase() !== "loading"}
        fallback={<p class="skeleton-line">Reading committed volumes…</p>}
      >
        <Show
          when={props.directory.items().length > 0}
          fallback={
            <p class="empty-state">No volumes have been created yet.</p>
          }
        >
          <div class="principal-table-wrap">
            <table>
              <thead>
                <tr>
                  <th scope="col">Name</th>
                  <th scope="col">State</th>
                  <th scope="col">Revision</th>
                  <th scope="col">Created</th>
                  <th scope="col">Access</th>
                </tr>
              </thead>
              <tbody>
                <For each={props.directory.items()}>
                  {(volume) => <VolumeRow {...props} volume={volume} />}
                </For>
              </tbody>
            </table>
          </div>
        </Show>
      </Show>
      <div class="list-footer" aria-live="polite">
        <Show when={props.directory.error()}>
          {(message) => <p class="error">{message()}</p>}
        </Show>
        <Show when={props.directory.nextPageUrl() !== null}>
          <button
            class="quiet-action"
            disabled={props.directory.phase() !== "idle"}
            onClick={() => {
              void props.directory.loadNext();
            }}
            type="button"
          >
            {props.directory.phase() === "loading_more"
              ? "Loading more volumes…"
              : "Load more volumes"}
          </button>
        </Show>
      </div>
    </section>
  );
}

function VolumeRow(
  props: Readonly<{
    onSelect: (volume: AdminVolume) => void;
    selectedVolumeId: string | undefined;
    volume: AdminVolume;
  }>,
): JSX.Element {
  const selected = () => props.selectedVolumeId === props.volume.volumeId;
  return (
    <tr>
      <th data-label="Name" scope="row">
        {props.volume.name}
      </th>
      <td data-label="State">
        <span class={`state state-${props.volume.state}`}>
          {props.volume.state}
        </span>
      </td>
      <td data-label="Revision">{props.volume.revision}</td>
      <td data-label="Created" class="timestamp">
        {instantFromEpochMicroseconds(
          props.volume.createdAtEpochMicros,
        ).toLocaleString(undefined, {
          dateStyle: "medium",
          timeStyle: "short",
        })}
      </td>
      <td data-label="Access">
        <button
          aria-pressed={selected() ? "true" : "false"}
          class="quiet-action table-action"
          onClick={() => {
            props.onSelect(props.volume);
          }}
          type="button"
        >
          {selected() ? "Managing" : "Manage access"}
        </button>
      </td>
    </tr>
  );
}
