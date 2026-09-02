// SPDX-License-Identifier: GPL-2.0-only

import { Show, createSignal } from "solid-js";
import type { JSX } from "@solidjs/web";

import type { RevokePermissionGrantResponse } from "../../generated/types.gen";
import type {
  PermissionGrantClient,
  VolumePermissionGrant,
} from "./permission-grant-model";

export function GrantRevocation(
  props: Readonly<{
    client: PermissionGrantClient;
    csrfToken: string;
    grant: VolumePermissionGrant;
    remove: (response: RevokePermissionGrantResponse) => void;
    volumeId: string;
  }>,
): JSX.Element {
  const [confirming, setConfirming] = createSignal(false);
  const [reason, setReason] = createSignal("");
  const [pending, setPending] = createSignal(false);
  const [error, setError] = createSignal<string>();
  const revoke = async (): Promise<void> => {
    const auditReason = reason().trim();
    if (auditReason.length === 0 || pending()) {
      setError("Enter a reason for removing access.");
      return;
    }
    setPending(true);
    setError(undefined);
    try {
      const response = await props.client.revokePermissionGrant(
        props.volumeId,
        props.grant.grant_id,
        { operation_id: crypto.randomUUID(), reason: auditReason },
        props.csrfToken,
      );
      props.remove(response);
    } catch {
      setError("MeshSpan could not remove this access grant.");
    } finally {
      setPending(false);
    }
  };
  return (
    <Show
      when={confirming()}
      fallback={<RemoveButton confirm={setConfirming} />}
    >
      <div class="grant-revocation">
        <label>
          <span>Reason for removing access</span>
          <input
            disabled={pending()}
            maxlength="512"
            onInput={(event) => {
              setReason(event.currentTarget.value);
            }}
            value={reason()}
          />
        </label>
        <RevocationActions
          cancel={() => {
            setConfirming(false);
          }}
          pending={pending()}
          revoke={revoke}
        />
        <Show when={error()}>
          {(message) => <p class="error">{message()}</p>}
        </Show>
      </div>
    </Show>
  );
}

function RevocationActions(
  props: Readonly<{
    cancel: () => void;
    pending: boolean;
    revoke: () => Promise<void>;
  }>,
): JSX.Element {
  return (
    <div class="membership-removal-actions">
      <button
        class="primary-action danger-button"
        disabled={props.pending}
        onClick={() => {
          void props.revoke();
        }}
        type="button"
      >
        {props.pending ? "Removing access…" : "Remove access"}
      </button>
      <button
        class="quiet-button"
        disabled={props.pending}
        onClick={() => {
          props.cancel();
        }}
        type="button"
      >
        Keep access
      </button>
    </div>
  );
}

function RemoveButton(
  props: Readonly<{ confirm: (value: boolean) => void }>,
): JSX.Element {
  return (
    <button
      class="quiet-action danger-action"
      onClick={() => {
        props.confirm(true);
      }}
      type="button"
    >
      Remove access
    </button>
  );
}
