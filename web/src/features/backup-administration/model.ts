// SPDX-License-Identifier: GPL-2.0-only

import type { Accessor } from "solid-js";
import { createBackupInventory } from "./inventory";
import { createBackupChanges } from "./changes";
import type {
  BackupAdministrationClient,
  BackupChange,
  BackupView,
} from "./types";

export type {
  BackupAdministrationClient,
  BackupChange,
  BackupDestination,
  BackupTarget,
} from "./types";
export type BackupAdministration = Readonly<{
  view: Accessor<BackupView | undefined>;
  phase: Accessor<"idle" | "loading" | "saving">;
  locked: Accessor<boolean>;
  error: Accessor<string | undefined>;
  notice: Accessor<string | undefined>;
  pending: Accessor<BackupChange | undefined>;
  load: () => Promise<void>;
  loadMore: (kind: "destinations" | "targets") => Promise<void>;
  save: (change: BackupChange) => Promise<boolean>;
  retry: () => Promise<void>;
}>;

/** Coordinates reads and one exact-retry mutation without racing a stale refresh. */
export function createBackupAdministration(
  client: Accessor<BackupAdministrationClient>,
  csrfToken: Accessor<string>,
): BackupAdministration {
  const inventory = createBackupInventory(client);
  const changes = createBackupChanges(client, csrfToken, inventory.load);
  const load = async (kind?: "destinations" | "targets"): Promise<void> => {
    if (changes.locked()) return;
    changes.clearError();
    await inventory.load(kind);
  };
  const phase = (): "idle" | "loading" | "saving" => {
    if (changes.saving()) return "saving";
    return inventory.loading() ? "loading" : "idle";
  };
  return {
    view: inventory.view,
    phase,
    locked: () => changes.locked() || inventory.loading(),
    error: () => changes.error() ?? inventory.error(),
    notice: changes.notice,
    pending: changes.pending,
    load: async () => load(),
    loadMore: load,
    save: async (change) => {
      return inventory.loading() ? false : changes.save(change);
    },
    retry: changes.retry,
  };
}
