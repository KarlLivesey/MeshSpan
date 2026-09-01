// SPDX-License-Identifier: GPL-2.0-only

import { For, Show } from "solid-js";
import type { JSX } from "@solidjs/web";

import { DirectoryEntryRow } from "./DirectoryEntryRow";
import type { BrowserDownloadClient } from "./download";
import type { FileBrowserModel } from "./model";

type DirectoryListingProps = Readonly<{
  client: BrowserDownloadClient;
  model: FileBrowserModel;
}>;

export function DirectoryListing(props: DirectoryListingProps): JSX.Element {
  const entries = () => props.model.directory()?.entries ?? [];
  const hasNextPage = () => {
    const nextPageUrl = props.model.directory()?.next_page_url;
    return nextPageUrl !== undefined && nextPageUrl !== null;
  };
  return (
    <div class="directory-listing">
      <Show
        when={entries().length > 0}
        fallback={
          <div
            class={
              props.model.phase() === "loading"
                ? "skeleton-line"
                : "empty-state"
            }
          >
            {props.model.phase() === "loading"
              ? "Loading this folder…"
              : "This folder is empty."}
          </div>
        }
      >
        <div class="directory-table-wrap">
          <table>
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Kind</th>
                <th scope="col">Size</th>
                <th scope="col">Actions</th>
              </tr>
            </thead>
            <tbody>
              <For each={entries()}>
                {(entry) => (
                  <DirectoryEntryRow
                    client={props.client}
                    entry={entry}
                    model={props.model}
                  />
                )}
              </For>
            </tbody>
          </table>
        </div>
      </Show>
      <Show when={hasNextPage()}>
        <div class="list-footer">
          <button
            class="quiet-button"
            disabled={props.model.phase() !== "idle"}
            onClick={() => {
              void props.model.loadMore();
            }}
            type="button"
          >
            Load more files
          </button>
        </div>
      </Show>
    </div>
  );
}
