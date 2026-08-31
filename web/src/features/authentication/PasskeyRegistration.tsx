// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, Show } from "solid-js";
import type { JSX } from "@solidjs/web";

import { browserCredentials, requestPasskeyRegistration } from "./webauthn";
import type { AuthenticationSecurityClient } from "./model";

type PasskeyRegistrationProps = Readonly<{
  client: AuthenticationSecurityClient;
  csrfToken: string;
  onChanged: () => Promise<void>;
}>;

export function PasskeyRegistration(
  props: PasskeyRegistrationProps,
): JSX.Element {
  const [label, setLabel] = createSignal("This device");
  const [pending, setPending] = createSignal(false);
  const [message, setMessage] = createSignal<string>();
  const [error, setError] = createSignal<string>();

  const register = async (event: SubmitEvent): Promise<void> => {
    event.preventDefault();
    if (pending()) {
      return;
    }
    setPending(true);
    setMessage(undefined);
    setError(undefined);
    try {
      const challenge =
        await props.client.createCurrentUserPasskeyRegistrationChallenge(
          { operation_id: crypto.randomUUID() },
          props.csrfToken,
        );
      const request = await requestPasskeyRegistration(
        challenge,
        label().trim(),
        crypto.randomUUID(),
        browserCredentials(),
      );
      await props.client.createCurrentUserPasskey(request, props.csrfToken);
      await props.onChanged();
      setMessage(`${label().trim()} is now available for sign-in.`);
    } catch {
      setError("MeshSpan could not add that passkey. Nothing was changed.");
    } finally {
      setPending(false);
    }
  };

  return (
    <form
      class="security-action-card"
      onSubmit={(event) => void register(event)}
    >
      <div>
        <p class="eyebrow">Recommended</p>
        <h3>Add a passkey</h3>
        <p>Use this device, a security key or another nearby authenticator.</p>
      </div>
      <label>
        <span>Name</span>
        <input
          disabled={pending()}
          maxlength={80}
          onInput={(event) => setLabel(event.currentTarget.value)}
          required
          value={label()}
        />
      </label>
      <button class="primary-action" disabled={pending()} type="submit">
        {pending() ? "Waiting for passkey…" : "Add passkey"}
      </button>
      <div class="form-message" aria-live="polite">
        <Show when={message()}>
          {(value) => <p class="success">{value()}</p>}
        </Show>
        <Show when={error()}>{(value) => <p class="error">{value()}</p>}</Show>
      </div>
    </form>
  );
}
