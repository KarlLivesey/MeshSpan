// SPDX-License-Identifier: GPL-2.0-only

import { createMemo, Show } from "solid-js";
import type { JSX } from "@solidjs/web";
import type { BackupHistoryClient } from "./history";

/** Leaves byte storage and completion to the browser, without a whole-backup Blob. */
export function BackupExportLink(
  props: Readonly<{
    backupId: string;
    downloadUrl: BackupHistoryClient["metadataBackupDownloadUrl"];
  }>,
): JSX.Element {
  const url = createMemo(() => {
    try {
      return props.downloadUrl(props.backupId);
    } catch {
      return undefined;
    }
  });
  return (
    <p>
      <Show
        when={url()}
        fallback={
          <span>
            Download unavailable. Refresh history or sign in again to retry.
          </span>
        }
      >
        {(href) => (
          <a href={href()} target="_blank" rel="noopener noreferrer">
            Download encrypted backup (opens in a new tab)
          </a>
        )}
      </Show>
    </p>
  );
}
