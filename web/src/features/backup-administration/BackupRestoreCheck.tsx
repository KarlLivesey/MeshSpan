// SPDX-License-Identifier: GPL-2.0-only

import { Show } from "solid-js";
import type { JSX } from "@solidjs/web";
import { instantFromEpochMicroseconds } from "../../domain/instant";
import { createRestoreCheck, type RestoreCheckClient } from "./restore-check";

export function BackupRestoreCheck(
  props: Readonly<{ client: RestoreCheckClient; backupId: string }>,
): JSX.Element {
  const model = createRestoreCheck(
    () => props.client,
    () => props.backupId,
  );
  return (
    <div>
      <button
        type="button"
        class="quiet-action"
        disabled={model.pending()}
        onClick={() => void model.run()}
      >
        Check restore
      </button>
      <Show when={model.pending()}>
        <button type="button" class="quiet-action" onClick={model.cancel}>
          Cancel check
        </button>
      </Show>
      <div aria-live="polite">
        <Show when={model.pending()}>
          <p>Reading, decrypting and checking an isolated metadata copy…</p>
        </Show>
        <Show when={model.error()}>
          {(error) => <p class="error">{error()}</p>}
        </Show>
        <Show when={model.evidence()}>
          {(evidence) => (
            <>
              <p>
                Isolated restore verified at{" "}
                {instantFromEpochMicroseconds(
                  evidence().checked_at_epoch_micros,
                ).toString()}
                .
              </p>
              <p>
                This gateway decrypted and opened a disposable metadata copy.
                Live data was not replaced. Your offline recovery bundle was not
                tested.
              </p>
              <details>
                <summary>Verified state</summary>
                <p>Gateway: {evidence().checked_by_node_id}</p>
                <p>Partition: {evidence().partition_id}</p>
                <p>
                  Log position: {evidence().source_log_index}, term{" "}
                  {evidence().source_log_term}. Metadata revision:{" "}
                  {evidence().state_revision}.
                </p>
              </details>
            </>
          )}
        </Show>
      </div>
    </div>
  );
}
