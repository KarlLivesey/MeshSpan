// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, Show } from "solid-js";
import type { JSX } from "@solidjs/web";

import { zCreatePasskeyRegistrationRequestWritable } from "../../generated/zod.gen";
import type { CreatePasskeyRegistrationRequestWritable } from "../../generated/types.gen";
import {
  createExactMutation,
  mutationMessage,
} from "../../native-api/mutation-outcome";
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
  const model = createPasskeyRegistration(props);

  return (
    <form
      class="security-action-card"
      onSubmit={(event) => void model.register(event)}
    >
      <div>
        <p class="eyebrow">Recommended</p>
        <h3>Add a passkey</h3>
        <p>Use this device, a security key or another nearby authenticator.</p>
      </div>
      <label>
        <span>Name</span>
        <input
          disabled={model.locked()}
          maxlength={80}
          onInput={(event) => model.setLabel(event.currentTarget.value)}
          required
          value={model.label()}
        />
      </label>
      <button class="primary-action" disabled={model.pending()} type="submit">
        {model.buttonLabel()}
      </button>
      <div class="form-message" aria-live="polite">
        <Show when={model.message()}>
          {(value) => <p class="success">{value()}</p>}
        </Show>
        <Show when={model.error()}>
          {(value) => <p class="error">{value()}</p>}
        </Show>
      </div>
    </form>
  );
}

function createPasskeyRegistration(props: PasskeyRegistrationProps) {
  const [label, setLabel] = createSignal("This device");
  const [preparing, setPreparing] = createSignal(false);
  const [localError, setLocalError] = createSignal<string>();
  const mutation = createExactMutation(
    async (request: CreatePasskeyRegistrationRequestWritable) =>
      props.client.createCurrentUserPasskey(request, props.csrfToken),
    (receipt, request) => {
      if (receipt.operation_id !== request.operation_id)
        throw new TypeError("Passkey receipt does not match the request.");
    },
    async () => props.onChanged(),
  );
  const pending = () => preparing() || mutation.busy();
  const locked = () => pending() || mutation.locked();
  const message = () =>
    mutation.state().phase === "committed"
      ? "The passkey is now available for sign-in."
      : undefined;
  const error = () => localError() ?? mutationMessage(mutation.state());
  let preparingRequest = false;

  const register = async (event: SubmitEvent): Promise<void> => {
    event.preventDefault();
    if (preparingRequest || pending()) {
      return;
    }
    setLocalError(undefined);
    if (mutation.locked()) {
      await mutation.retry();
      return;
    }
    preparingRequest = true;
    setPreparing(true);
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
      await mutation.submit(
        zCreatePasskeyRegistrationRequestWritable.parse(request),
      );
    } catch {
      setLocalError(
        "Passkey preparation did not finish. Registration was not submitted.",
      );
    } finally {
      preparingRequest = false;
      setPreparing(false);
    }
  };

  const buttonLabel = (): string => {
    if (pending()) return "Waiting for passkey…";
    return mutation.locked() ? "Retry passkey registration" : "Add passkey";
  };
  return {
    label,
    setLabel,
    locked,
    pending,
    register,
    message,
    error,
    buttonLabel,
  };
}
