// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, Show } from "solid-js";
import type { JSX } from "@solidjs/web";

import { downloadFileBlob, type BrowserDownloadClient } from "./download";
import { EntryActions } from "./EntryActions";
import type { DirectoryEntry, FileBrowserModel } from "./model";

type DirectoryEntryRowProps = Readonly<{
  client: BrowserDownloadClient;
  entry: DirectoryEntry;
  model: FileBrowserModel;
}>;

export function DirectoryEntryRow(props: DirectoryEntryRowProps): JSX.Element {
  const [downloadError, setDownloadError] = createSignal<string>();
  const [downloading, setDownloading] = createSignal(false);
  const open = (): void => {
    if (props.entry.kind === "directory") {
      void props.model.openDirectory(props.entry).catch(() => undefined);
    }
  };
  const download = async (): Promise<void> => {
    const versionId = props.entry.file_version_id;
    const length = props.entry.logical_length;
    if (versionId === null || length === null)
      throw new TypeError("file metadata is incomplete");
    setDownloading(true);
    setDownloadError(undefined);
    try {
      const directory = props.model.directory()?.path ?? "";
      const blob = await downloadFileBlob({
        client: props.client,
        expectedVersionId: versionId,
        length,
        onProgress: () => undefined,
        path:
          directory === ""
            ? props.entry.name
            : `${directory}/${props.entry.name}`,
        volumeId: props.model.selectedVolume()?.volume_id ?? "",
      });
      saveDownload(blob, props.entry.name);
    } catch {
      setDownloadError("Download failed.");
    } finally {
      setDownloading(false);
    }
  };
  return (
    <tr>
      <th scope="row">
        <Show
          when={props.entry.kind === "directory"}
          fallback={props.entry.name}
        >
          <button class="entry-link" onClick={open} type="button">
            {props.entry.name}
          </button>
        </Show>
        <Show when={downloadError()}>
          {(message) => <span class="error row-error">{message()}</span>}
        </Show>
      </th>
      <td>{props.entry.kind === "directory" ? "Folder" : "File"}</td>
      <td>{formatByteLength(props.entry.logical_length)}</td>
      <td>
        <div class="entry-actions">
          <Show when={props.entry.kind === "file"}>
            <button
              class="quiet-action table-action"
              disabled={downloading()}
              onClick={() => void download()}
              type="button"
            >
              {downloading() ? "Downloading…" : "Download"}
            </button>
          </Show>
          <EntryActions entry={props.entry} model={props.model} />
        </div>
      </td>
    </tr>
  );
}

function saveDownload(blob: Blob, name: string): void {
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.download = name;
  anchor.href = url;
  anchor.click();
  URL.revokeObjectURL(url);
}

function formatByteLength(length: number | null): string {
  if (length === null) return "—";
  if (length < 1_024) return `${String(length)} B`;
  if (length < 1_048_576) return `${(length / 1_024).toFixed(1)} KiB`;
  if (length < 1_073_741_824) return `${(length / 1_048_576).toFixed(1)} MiB`;
  return `${(length / 1_073_741_824).toFixed(1)} GiB`;
}
