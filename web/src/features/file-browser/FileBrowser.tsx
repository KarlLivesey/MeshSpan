// SPDX-License-Identifier: GPL-2.0-only

import { Show, untrack } from "solid-js";
import type { JSX } from "@solidjs/web";

import type { MeshSpanFetchClient } from "../../generated/fetch.gen";
import { DirectoryListing } from "./DirectoryListing";
import { DirectoryToolbar } from "./DirectoryToolbar";
import { createFileBrowserModel } from "./model";
import { VolumePicker } from "./VolumePicker";

type FileBrowserProps = Readonly<{
  client: MeshSpanFetchClient;
  csrfToken: () => string | undefined;
}>;

export function FileBrowser(props: FileBrowserProps): JSX.Element {
  const model = createFileBrowserModel(
    () => props.client,
    () => props.csrfToken(),
  );
  untrack(() => void model.loadInitial());

  return (
    <section class="file-browser">
      <header class="file-browser-heading">
        <div>
          <p class="eyebrow">Your swarm</p>
          <h1>Files</h1>
        </div>
        <Show when={model.volumes().length > 0}>
          <VolumePicker model={model} />
        </Show>
      </header>
      <Show when={model.error()}>
        {(message) => <p class="error">{message()}</p>}
      </Show>
      <Show
        when={model.selectedVolume()}
        fallback={<FileBrowserEmpty loading={model.phase() === "loading"} />}
      >
        <DirectoryToolbar model={model} />
        <DirectoryListing client={props.client} model={model} />
      </Show>
    </section>
  );
}

function FileBrowserEmpty(props: Readonly<{ loading: boolean }>): JSX.Element {
  return (
    <div class={props.loading ? "skeleton-line" : "empty-state"}>
      {props.loading
        ? "Loading the files available to you…"
        : "No volumes are currently available to this account."}
    </div>
  );
}
