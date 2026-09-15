// SPDX-License-Identifier: GPL-2.0-only

import { createSignal } from "solid-js";
import type { JSX } from "@solidjs/web";

export type InvitationStepUpAction = (
  factor: Readonly<{ method: "totp" | "recovery_code"; code: string }>,
) => Promise<void>;

export function InvitationStepUp(
  props: Readonly<{ stepUp: InvitationStepUpAction; disabled: boolean }>,
): JSX.Element {
  const [method, setMethod] = createSignal<"totp" | "recovery_code">("totp");
  const [code, setCode] = createSignal("");
  const [busy, setBusy] = createSignal(false);
  const [pending, setPending] = createSignal(false);
  const [message, setMessage] = createSignal<string>();
  const submit = async (): Promise<void> => {
    if (busy() || props.disabled) return;
    setBusy(true);
    setPending(true);
    try {
      await props.stepUp({ method: method(), code: code().trim() });
      setCode("");
      setPending(false);
      setMessage("Identity confirmed. You can issue or revoke an invitation.");
    } catch {
      setMessage(
        "Confirmation is unknown. Retry the same confirmation before continuing.",
      );
    } finally {
      setBusy(false);
    }
  };
  return (
    <form
      onSubmit={(event) => {
        event.preventDefault();
        void submit();
      }}
    >
      <p>
        Confirm your identity with a recent additional factor before issuing or
        revoking invitations.
      </p>
      <label>
        <span>Confirmation method</span>
        <select
          disabled={pending() || props.disabled}
          value={method()}
          onChange={(event) =>
            setMethod(
              event.currentTarget.value === "recovery_code"
                ? "recovery_code"
                : "totp",
            )
          }
        >
          <option value="totp">Authenticator code</option>
          <option value="recovery_code">Recovery code</option>
        </select>
      </label>
      <label>
        <span>Confirmation code</span>
        <input
          type="password"
          autocomplete="off"
          required
          value={code()}
          disabled={pending() || props.disabled}
          onInput={(event) => setCode(event.currentTarget.value)}
        />
      </label>
      <button type="submit" disabled={busy() || props.disabled}>
        {pending() ? "Retry confirmation" : "Confirm identity"}
      </button>
      <p aria-live="polite">{message()}</p>
    </form>
  );
}
