// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, type Accessor } from "solid-js";
import {
  createExactMutation,
  mutationMessage,
} from "../../native-api/mutation-outcome";
import type {
  ConfigureBackupDestinationResponse,
  ConfigureBackupScheduleResponse,
} from "../../generated/types.gen";
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
  const [hideError, setHideError] = createSignal(false, { ownedWrite: true });
  const mutation = createExactMutation(
    async (attempt: { operation_id: string; change: BackupChange }) =>
      sendChange(client(), attempt.change, csrfToken()),
    () => {
      /* sendChange checks each concrete receipt before returning. */
    },
    refresh,
  );
  const notice = (): string | undefined =>
    mutation.state().phase === "committed"
      ? "Backup settings saved. This does not confirm a completed backup."
      : undefined;
  const complete = (): boolean => {
    const committed = mutation.state().phase === "committed";
    if (committed) setPending(undefined);
    return committed;
  };
  return {
    error: () => (hideError() ? undefined : mutationMessage(mutation.state())),
    notice,
    pending,
    saving: () => mutation.state().phase === "submitting",
    locked: mutation.locked,
    clearError: () => {
      setHideError(true);
    },
    save: async (change) => {
      if (mutation.locked()) return false;
      setHideError(false);
      setPending(structuredClone(change));
      await mutation.submit({
        operation_id: change.request.operation_id,
        change,
      });
      return complete();
    },
    retry: async () => {
      setHideError(false);
      await mutation.retry();
      complete();
    },
  };
}

async function sendChange(
  client: BackupAdministrationClient,
  change: BackupChange,
  csrfToken: string,
): Promise<
  ConfigureBackupScheduleResponse | ConfigureBackupDestinationResponse
> {
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
    return receipt;
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
    return receipt;
  }
}
