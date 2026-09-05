// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, type Accessor } from "solid-js";
import { MeshSpanApiError } from "../../generated/fetch.gen";
import type { BackupAdministrationClient, BackupChange } from "./types";

type Changes = Readonly<{
  error: Accessor<string | undefined>;
  notice: Accessor<string | undefined>;
  pending: Accessor<BackupChange | undefined>;
  saving: Accessor<boolean>;
  locked: Accessor<boolean>;
  clearError: () => void;
  retry: () => Promise<void>;
  save: (change: BackupChange) => Promise<boolean>;
}>;

/** Keeps one request unchanged until receipt or a definite server rejection. */
export function createBackupChanges(
  client: Accessor<BackupAdministrationClient>,
  csrfToken: Accessor<string>,
  refresh: () => Promise<void>,
): Changes {
  const [pending, setPending] = createSignal<BackupChange | undefined>(
    undefined,
    { ownedWrite: true },
  );
  const [saving, setSaving] = createSignal(false, { ownedWrite: true });
  const [error, setError] = createSignal<string | undefined>(undefined, {
    ownedWrite: true,
  });
  const [notice, setNotice] = createSignal<string | undefined>(undefined, {
    ownedWrite: true,
  });
  const locked = (): boolean => saving() || pending() !== undefined;
  // Executor admission is synchronous; UI signals publish on Solid's flush.
  let inFlight = false;
  const execute = async (change: BackupChange): Promise<boolean> => {
    if (inFlight) return false;
    inFlight = true;
    setSaving(true);
    setError();
    setNotice();
    try {
      await sendChange(client(), change, csrfToken());
      setPending();
      setNotice(
        "Backup settings saved. This does not confirm a completed backup.",
      );
      await refresh();
      return true;
    } catch (failure: unknown) {
      if (isDefiniteRejection(failure)) {
        setPending();
        setError(
          "The change was rejected. Refresh the current settings and check your access before editing again.",
        );
      } else {
        setError(
          "The result is unknown. Retry the pending change to confirm its outcome; do not submit a different change.",
        );
      }
      return false;
    } finally {
      inFlight = false;
      setSaving(false);
    }
  };
  const save = async (change: BackupChange): Promise<boolean> => {
    if (locked() || inFlight) return false;
    setPending(change);
    return execute(change);
  };
  return {
    error,
    notice,
    pending,
    saving,
    locked,
    clearError: () => {
      setError();
    },
    save,
    retry: async () => {
      const change = pending();
      if (change !== undefined) await execute(change);
    },
  };
}

async function sendChange(
  client: BackupAdministrationClient,
  change: BackupChange,
  csrfToken: string,
): Promise<void> {
  if (change.kind === "schedule") {
    const receipt = await client.configureBackupSchedule(
      change.request,
      csrfToken,
    );
    if (
      receipt.operation_id !== change.request.operation_id ||
      receipt.sequence !== change.request.expected_sequence + 1 ||
      receipt.committed_revision <= 0
    ) {
      throw new TypeError(
        "Backup schedule receipt does not match the request.",
      );
    }
  } else {
    const receipt = await client.configureBackupDestination(
      change.request,
      csrfToken,
    );
    if (
      receipt.operation_id !== change.request.operation_id ||
      receipt.destination_id !== change.request.destination_id ||
      receipt.committed_revision <= change.request.expected_revision
    ) {
      throw new TypeError(
        "Backup destination receipt does not match the request.",
      );
    }
  }
}

function isDefiniteRejection(error: unknown): boolean {
  return (
    error instanceof MeshSpanApiError &&
    error.apiError !== undefined &&
    [
      "unauthenticated",
      "forbidden",
      "invalid_request",
      "operation_conflict",
      "not_found",
      "state_conflict",
    ].includes(error.apiError.code)
  );
}
