// SPDX-License-Identifier: GPL-2.0-only

import { For, Show } from "solid-js";
import type { JSX } from "@solidjs/web";

import type { StorageFolder, StorageFolderDirectory } from "./model";

export function StorageFolderList(
  props: Readonly<{ directory: StorageFolderDirectory }>,
): JSX.Element {
  return (
    <section aria-labelledby="storage-folder-list-heading">
      <div class="principal-list-heading">
        <div>
          <p class="eyebrow">Local capacity</p>
          <h2 id="storage-folder-list-heading">Storage folders</h2>
        </div>
        <span class="record-count">{props.directory.items().length}</span>
      </div>
      <Show
        when={props.directory.phase() !== "loading"}
        fallback={<p class="skeleton-line">Reading storage folders…</p>}
      >
        <Show
          when={props.directory.items().length > 0}
          fallback={
            <p class="empty-state">This node has no storage folders yet.</p>
          }
        >
          <FolderTable folders={props.directory.items()} />
        </Show>
      </Show>
      <div class="list-footer" aria-live="polite">
        <Show when={props.directory.error()}>
          {(message) => <p class="error">{message()}</p>}
        </Show>
        <button
          class="quiet-action"
          disabled={props.directory.phase() !== "idle"}
          onClick={() => void props.directory.loadInitial()}
          type="button"
        >
          Refresh
        </button>
        <Show when={props.directory.nextPageUrl() !== null}>
          <button
            class="quiet-action"
            disabled={props.directory.phase() !== "idle"}
            onClick={() => void props.directory.loadNext()}
            type="button"
          >
            Load more folders
          </button>
        </Show>
      </div>
    </section>
  );
}

function FolderTable(
  props: Readonly<{ folders: readonly StorageFolder[] }>,
): JSX.Element {
  return (
    <div class="principal-table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">Path</th>
            <th scope="col">State</th>
            <th scope="col">Capacity limit</th>
            <th scope="col">Target</th>
          </tr>
        </thead>
        <tbody>
          <For each={props.folders}>
            {(folder) => (
              <tr>
                <th data-label="Path" scope="row">
                  <code>{folder.path ?? "Non-UTF-8 headless path"}</code>
                </th>
                <td data-label="State">
                  <span class={`state state-${folder.state}`}>
                    {folder.state}
                  </span>
                </td>
                <td data-label="Capacity limit">
                  {formatUsageLimit(folder.usage_limit)}
                </td>
                <td data-label="Target">
                  <code>{folder.target_id}</code>
                </td>
              </tr>
            )}
          </For>
        </tbody>
      </table>
    </div>
  );
}

function formatUsageLimit(value: StorageFolder["usage_limit"]): string {
  return value.kind === "percent"
    ? `${String(value.percent)}%`
    : `${formatBytes(BigInt(value.bytes))} maximum`;
}

function formatBytes(bytes: bigint): string {
  const units = [
    [1024n ** 4n, "TiB"],
    [1024n ** 3n, "GiB"],
    [1024n ** 2n, "MiB"],
  ] as const;
  const unit = units.find(([size]) => bytes >= size);
  return unit === undefined
    ? `${bytes.toString()} bytes`
    : `${(bytes / unit[0]).toString()} ${unit[1]}`;
}
