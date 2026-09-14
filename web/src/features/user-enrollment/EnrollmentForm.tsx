// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, Show } from "solid-js";
import type { JSX } from "@solidjs/web";

import type { MeshSpanFetchClient } from "../../generated/fetch.gen";
import type { RedeemUserEnrollmentApiKeyRequestWritable } from "../../generated/types.gen";
import { zRedeemUserEnrollmentApiKeyRequestWritable } from "../../generated/zod.gen";
import {
  createExactMutation,
  mutationMessage,
} from "../../native-api/mutation-outcome";

type EnrollmentProps = Readonly<{
  client: Pick<MeshSpanFetchClient, "redeemUserEnrollmentApiKey">;
  signIn: (key: string) => Promise<void>;
}>;

export function EnrollmentForm(props: EnrollmentProps): JSX.Element {
  const model = createEnrollment(props);
  return (
    <section class="sign-in-page">
      <h1>Accept your invitation</h1>
      <p>
        Enter the invitation your administrator shared privately to create your
        first API key.
      </p>
      <form
        class="sign-in-form"
        onSubmit={(event) => {
          event.preventDefault();
          void model.submit();
        }}
      >
        <label>
          <span>Invitation token</span>
          <input
            autocomplete="off"
            type="password"
            maxlength={125}
            spellcheck={false}
            required
            value={model.token()}
            disabled={model.locked()}
            onInput={(event) => model.setToken(event.currentTarget.value)}
          />
        </label>
        <label>
          <span>Key name</span>
          <input
            maxlength={80}
            required
            value={model.label()}
            disabled={model.locked()}
            onInput={(event) => model.setLabel(event.currentTarget.value)}
          />
        </label>
        <p>
          The key permits web sign-in and native API access within your assigned
          permissions.
        </p>
        <Show when={model.secret() === undefined}>
          <button type="submit" disabled={model.busy()}>
            {model.pending() ? "Retry enrollment" : "Create my key"}
          </button>
        </Show>
      </form>
      <Show when={model.secret()}>
        {(secret) => (
          <div class="one-time-secret">
            <p>
              Your key was created. Save it privately before leaving this page.
            </p>
            <output class="secret-output">{secret()}</output>
            <button
              type="button"
              disabled={model.signingIn()}
              onClick={() => void model.signIn()}
            >
              Sign in with my key
            </button>
          </div>
        )}
      </Show>
      <p aria-live="polite">{model.message()}</p>
      <a href="/sign-in">Return to sign in</a>
    </section>
  );
}

function createEnrollment(props: EnrollmentProps) {
  const [token, setToken] = createSignal("");
  const [label, setLabel] = createSignal("My key");
  const [localError, setLocalError] = createSignal<string>();
  const [signingIn, setSigningIn] = createSignal(false);
  const mutation = createExactMutation(
    async (request: RedeemUserEnrollmentApiKeyRequestWritable) =>
      props.client.redeemUserEnrollmentApiKey(request),
    (receipt, request) => {
      if (
        receipt.operation_id !== request.operation_id ||
        receipt.expires_at_epoch_micros !== null ||
        receipt.scopes.length !== 2 ||
        !receipt.scopes.includes("https_session") ||
        !receipt.scopes.includes("headless_api")
      ) {
        throw new TypeError("Enrollment receipt does not match the request.");
      }
    },
    async () => {
      setToken("");
      return Promise.resolve();
    },
  );
  const secret = () => {
    const state = mutation.state();
    return state.phase === "committed" ? state.receipt.secret : undefined;
  };
  const submit = async (): Promise<void> => {
    if (secret() !== undefined) return;
    setLocalError(undefined);
    if (mutation.locked()) {
      await mutation.retry();
      return;
    }
    const request = zRedeemUserEnrollmentApiKeyRequestWritable.safeParse({
      operation_id: crypto.randomUUID(),
      token: token().trim(),
      label: label().trim(),
      scopes: ["https_session", "headless_api"],
      expires_at_epoch_micros: null,
    });
    if (!request.success) {
      setLocalError(
        "Enter a valid invitation and key name. Nothing was submitted.",
      );
      return;
    }
    await mutation.submit(request.data);
  };
  const signIn = async (): Promise<void> => {
    const key = secret();
    if (key === undefined || signingIn()) return;
    setSigningIn(true);
    setLocalError(undefined);
    try {
      await props.signIn(key);
    } catch {
      setLocalError(
        "Your key is created, but sign-in could not be confirmed. Keep the key and try signing in again.",
      );
    } finally {
      setSigningIn(false);
    }
  };
  return {
    token,
    setToken,
    label,
    setLabel,
    secret,
    submit,
    signIn,
    signingIn,
    busy: mutation.busy,
    pending: mutation.locked,
    locked: () => mutation.locked() || secret() !== undefined,
    message: () => localError() ?? mutationMessage(mutation.state()),
  };
}
