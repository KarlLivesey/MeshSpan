// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, onCleanup, type Accessor } from "solid-js";
import type {
  BackupReadinessResponse,
  MeshSpanFetchClient,
} from "../../generated";
import { zBackupReadinessResponse } from "../../generated/zod.gen";

export type RestoreCheckClient = Pick<
  MeshSpanFetchClient,
  "checkMetadataBackupReadiness"
>;
type RestoreCheck = Readonly<{
  pending: Accessor<boolean>;
  evidence: Accessor<BackupReadinessResponse | undefined>;
  error: Accessor<string | undefined>;
  run: () => Promise<void>;
  cancel: () => void;
}>;

/** One explicit check; no optimistic readiness, background retry or retained stale result. */
export function createRestoreCheck(
  client: Accessor<RestoreCheckClient>,
  backupId: Accessor<string>,
): RestoreCheck {
  const [pending, setPending] = createSignal(false, { ownedWrite: true });
  const [evidence, setEvidence] = createSignal<
    BackupReadinessResponse | undefined
  >(undefined, { ownedWrite: true });
  const [error, setError] = createSignal<string | undefined>(undefined, {
    ownedWrite: true,
  });
  let active: AbortController | undefined;
  let confirmedClient: RestoreCheckClient | undefined;
  let disposed = false;
  const isActive = (): boolean => !disposed;
  onCleanup(() => {
    disposed = true;
    active?.abort();
  });
  const run = async (): Promise<void> => {
    if (active || !isActive()) return;
    const controller = new AbortController();
    active = controller;
    const current = client();
    const selected = backupId();
    setPending(true);
    setEvidence();
    setError();
    try {
      const result = zBackupReadinessResponse.parse(
        await current.checkMetadataBackupReadiness(selected, controller.signal),
      );
      if (result.backup_id !== selected)
        throw new TypeError("restore check names another generation");
      if (
        !controller.signal.aborted &&
        current === client() &&
        selected === backupId()
      ) {
        confirmedClient = current;
        setEvidence(result);
      }
    } catch {
      if (!controller.signal.aborted)
        setError(
          "Restore check could not complete. Check your access and backup availability, then retry.",
        );
    } finally {
      if (active === controller) {
        active = undefined;
        if (isActive()) setPending(false);
      }
    }
  };
  const cancel = (): void => {
    active?.abort();
    active = undefined;
    setPending(false);
    setEvidence();
    setError("Check request cancelled; no recovery result was confirmed.");
  };
  return {
    pending,
    evidence: () =>
      evidence()?.backup_id === backupId() && confirmedClient === client()
        ? evidence()
        : undefined,
    error,
    run,
    cancel,
  };
}
