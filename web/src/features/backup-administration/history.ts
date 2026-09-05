// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, onCleanup, type Accessor } from "solid-js";
import type {
  ListBackupRunsResponse,
  MeshSpanFetchClient,
} from "../../generated";

export type BackupHistoryClient = Pick<
  MeshSpanFetchClient,
  "listBackupRuns" | "listNextBackupRuns" | "metadataBackupDownloadUrl"
>;
type History = Readonly<{
  page: Accessor<ListBackupRunsResponse | undefined>;
  loading: Accessor<boolean>;
  error: Accessor<string | undefined>;
  load: (nextPageUrl?: string) => Promise<void>;
}>;

/** Keeps one bounded page and never retains private history after a failed read. */
export function createBackupHistory(
  client: Accessor<BackupHistoryClient>,
): History {
  const [page, setPage] = createSignal<ListBackupRunsResponse | undefined>(
    undefined,
    { ownedWrite: true },
  );
  const [loading, setLoading] = createSignal(false, { ownedWrite: true });
  const [error, setError] = createSignal<string | undefined>(undefined, {
    ownedWrite: true,
  });
  let inFlight = false;
  let disposed = false;
  const isActive = (): boolean => !disposed;
  onCleanup(() => {
    disposed = true;
  });
  const load = async (nextPageUrl?: string): Promise<void> => {
    if (inFlight || !isActive()) return;
    inFlight = true;
    setLoading(true);
    setPage();
    setError();
    const current = client();
    try {
      const result =
        nextPageUrl === undefined
          ? await current.listBackupRuns({ limit: 25 })
          : await current.listNextBackupRuns(nextPageUrl);
      if (isActive() && current === client()) setPage(result);
    } catch {
      if (isActive())
        setError(
          "Backup history could not be read. Check your connection and access, then refresh history.",
        );
    } finally {
      inFlight = false;
      if (isActive()) setLoading(false);
    }
  };
  return { page, loading, error, load };
}
