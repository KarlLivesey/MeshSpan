// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, Show } from "solid-js";
import type { JSX } from "@solidjs/web";

import { instantFromEpochMicroseconds } from "../../domain/instant";
import type { AuthenticationMethodSummary } from "./model";

export function AuthenticationMethodCard(
  props: Readonly<{
    method: AuthenticationMethodSummary;
    onRevoke: (methodId: string, reason: string) => Promise<void>;
  }>,
): JSX.Element {
  const [editing, setEditing] = createSignal(false);
  return (
    <article class="method-card">
      <div class="method-card-heading">
        <div>
          <p class={`state state-${props.method.state}`}>
            {props.method.state}
          </p>
          <h3>{props.method.label}</h3>
        </div>
        <span class="method-kind">{methodKind(props.method)}</span>
      </div>
      <dl>
        <MethodFact
          label="Created"
          value={formatInstant(props.method.created_at_epoch_micros)}
        />
        <MethodFact
          label="Last used"
          value={
            props.method.last_used_at_epoch_micros === null
              ? "Not yet"
              : formatInstant(props.method.last_used_at_epoch_micros)
          }
        />
        <MethodFact label="Details" value={methodDetails(props.method)} />
      </dl>
      <Show when={props.method.state !== "revoked" && !editing()}>
        <button
          class="quiet-action danger-action"
          onClick={() => setEditing(true)}
          type="button"
        >
          Revoke method
        </button>
      </Show>
      <Show when={editing()}>
        <MethodRevocation
          methodId={props.method.method_id}
          onCancel={() => setEditing(false)}
          onRevoke={props.onRevoke}
        />
      </Show>
    </article>
  );
}

function MethodFact(
  props: Readonly<{ label: string; value: string }>,
): JSX.Element {
  return (
    <div>
      <dt>{props.label}</dt>
      <dd>{props.value}</dd>
    </div>
  );
}

function MethodRevocation(
  props: Readonly<{
    methodId: string;
    onCancel: () => void;
    onRevoke: (methodId: string, reason: string) => Promise<void>;
  }>,
): JSX.Element {
  const [reason, setReason] = createSignal("");
  const [pending, setPending] = createSignal(false);
  const [error, setError] = createSignal<string>();
  const revoke = async (event: SubmitEvent): Promise<void> => {
    event.preventDefault();
    if (pending()) {
      return;
    }
    setPending(true);
    setError(undefined);
    try {
      await props.onRevoke(props.methodId, reason().trim());
      props.onCancel();
    } catch {
      setError("MeshSpan could not revoke that sign-in method.");
    } finally {
      setPending(false);
    }
  };
  return (
    <form class="method-revocation" onSubmit={(event) => void revoke(event)}>
      <label>
        <span>Reason</span>
        <input
          disabled={pending()}
          maxlength={512}
          onInput={(event) => setReason(event.currentTarget.value)}
          required
          value={reason()}
        />
      </label>
      <div class="membership-removal-actions">
        <button
          class="primary-action danger-button"
          disabled={pending()}
          type="submit"
        >
          {pending() ? "Revoking…" : "Revoke access"}
        </button>
        <button
          class="quiet-action"
          disabled={pending()}
          onClick={() => {
            props.onCancel();
          }}
          type="button"
        >
          Cancel
        </button>
      </div>
      <Show when={error()}>
        {(message) => <p class="error">{message()}</p>}
      </Show>
    </form>
  );
}

function methodKind(method: AuthenticationMethodSummary): string {
  switch (method.details.kind) {
    case "api_key":
      return "API key";
    case "passkey":
      return "Passkey";
    case "recovery_codes":
      return "Recovery codes";
    case "totp":
      return "Authenticator app";
  }
}

function methodDetails(method: AuthenticationMethodSummary): string {
  const details = method.details;
  switch (details.kind) {
    case "api_key":
      return details.scopes.map(scopeLabel).join(", ");
    case "passkey":
      return details.backup_state ? "Backed up" : "Device-bound";
    case "recovery_codes":
      return `${String(details.remaining_codes)} unused`;
    case "totp":
      return "Six-digit codes";
  }
}

function scopeLabel(scope: "headless_api" | "https_session" | "smb_session") {
  switch (scope) {
    case "headless_api":
      return "Native API";
    case "https_session":
      return "Web sign-in";
    case "smb_session":
      return "SMB sign-in";
  }
}

function formatInstant(epochMicroseconds: number): string {
  return instantFromEpochMicroseconds(epochMicroseconds).toLocaleString();
}
