// SPDX-License-Identifier: GPL-2.0-only

import { Show } from "solid-js";
import type { JSX } from "@solidjs/web";
import {
  createDiagnosticsDownload,
  type DiagnosticsClient,
} from "./diagnostics-download";

export function DiagnosticsDownload(
  props: Readonly<{ client: DiagnosticsClient }>,
): JSX.Element {
  const download = createDiagnosticsDownload(() => props.client);
  return (
    <section aria-labelledby="diagnostics-heading">
      <h2 id="diagnostics-heading">Diagnostics</h2>
      <p>
        Download this node’s configuration summary, storage-check observations
        and recent activity. File content, credentials and storage paths are
        excluded.
      </p>
      <p>
        Observations may be incomplete or out of date. This is not a backup or
        proof that your files are protected.
      </p>
      <button
        type="button"
        class="quiet-action"
        disabled={download.pending()}
        onClick={() => void download.run()}
      >
        {download.pending()
          ? "Collecting diagnostics…"
          : "Download diagnostics"}
      </button>
      <Show when={download.pending()}>
        <button type="button" class="quiet-action" onClick={download.cancel}>
          Cancel collection
        </button>
      </Show>
      <div aria-live="polite">
        <Show when={download.message()}>{(message) => <p>{message()}</p>}</Show>
        <Show when={download.error()}>
          {(error) => <p class="error">{error()}</p>}
        </Show>
      </div>
    </section>
  );
}
