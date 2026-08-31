// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, Show, type Accessor } from "solid-js";
import type { JSX } from "@solidjs/web";

import type { CreateTotpRegistrationChallengeResponse } from "../../generated/types.gen";
import type { AuthenticationSecurityClient } from "./model";

type TotpRegistrationProps = Readonly<{
  client: AuthenticationSecurityClient;
  csrfToken: string;
  onChanged: () => Promise<void>;
}>;

export function TotpRegistration(props: TotpRegistrationProps): JSX.Element {
  const controller = createTotpController(props);
  return (
    <section class="security-action-card">
      <div>
        <p class="eyebrow">Second factor</p>
        <h3>Authenticator codes</h3>
        <p>Add a standard six-digit code generator.</p>
      </div>
      <Show
        when={controller.challenge()}
        fallback={<TotpStartForm controller={controller} />}
      >
        {(material) => (
          <TotpConfirmationForm controller={controller} material={material()} />
        )}
      </Show>
      <OperationMessage error={controller.error} message={controller.message} />
    </section>
  );
}

function createTotpController(props: TotpRegistrationProps) {
  const [label, setLabel] = createSignal("Authenticator app");
  const [challenge, setChallenge] =
    createSignal<CreateTotpRegistrationChallengeResponse>();
  const [code, setCode] = createSignal("");
  const [pending, setPending] = createSignal(false);
  const [message, setMessage] = createSignal<string>();
  const [error, setError] = createSignal<string>();
  const execute = async <T,>(operation: Promise<T>): Promise<T | undefined> => {
    if (pending()) {
      return undefined;
    }
    setPending(true);
    setMessage(undefined);
    setError(undefined);
    try {
      return await operation;
    } catch {
      setError("MeshSpan could not complete authenticator setup.");
      return undefined;
    } finally {
      setPending(false);
    }
  };
  const begin = async (): Promise<void> => {
    const result = await execute(
      props.client.createCurrentUserTotpRegistrationChallenge(
        { label: label().trim(), operation_id: crypto.randomUUID() },
        props.csrfToken,
      ),
    );
    if (result !== undefined) {
      setChallenge(result);
    }
  };
  const confirm = async (): Promise<void> => {
    const current = challenge();
    if (current === undefined) {
      return;
    }
    const result = await execute(
      props.client.createCurrentUserTotp(
        {
          challenge_id: current.challenge_id,
          code: code().trim(),
          operation_id: crypto.randomUUID(),
        },
        props.csrfToken,
      ),
    );
    if (result !== undefined) {
      setChallenge(undefined);
      setCode("");
      await props.onChanged();
      setMessage("Authenticator codes are now enabled.");
    }
  };
  return {
    begin,
    challenge,
    code,
    confirm,
    error,
    label,
    message,
    pending,
    setCode,
    setLabel,
  };
}

type TotpController = ReturnType<typeof createTotpController>;

function TotpStartForm(
  props: Readonly<{ controller: TotpController }>,
): JSX.Element {
  return (
    <form
      class="security-card-form"
      onSubmit={(event) => {
        event.preventDefault();
        void props.controller.begin();
      }}
    >
      <label>
        <span>Name</span>
        <input
          disabled={props.controller.pending()}
          maxlength={80}
          onInput={(event) =>
            props.controller.setLabel(event.currentTarget.value)
          }
          required
          value={props.controller.label()}
        />
      </label>
      <button
        class="quiet-button"
        disabled={props.controller.pending()}
        type="submit"
      >
        {props.controller.pending() ? "Preparing…" : "Set up authenticator"}
      </button>
    </form>
  );
}

function TotpConfirmationForm(
  props: Readonly<{
    controller: TotpController;
    material: CreateTotpRegistrationChallengeResponse;
  }>,
): JSX.Element {
  return (
    <form
      class="security-card-form"
      onSubmit={(event) => {
        event.preventDefault();
        void props.controller.confirm();
      }}
    >
      <p class="sensitive-note">
        Add this secret to your authenticator. It is shown only during setup.
      </p>
      <output class="secret-output">{props.material.secret}</output>
      <a class="quiet-action" href={props.material.provisioning_uri}>
        Open in an authenticator app
      </a>
      <label>
        <span>Current six-digit code</span>
        <input
          autocomplete="one-time-code"
          disabled={props.controller.pending()}
          inputmode="numeric"
          maxlength={6}
          onInput={(event) =>
            props.controller.setCode(event.currentTarget.value)
          }
          pattern="[0-9]{6}"
          required
          value={props.controller.code()}
        />
      </label>
      <button
        class="primary-action"
        disabled={props.controller.pending()}
        type="submit"
      >
        {props.controller.pending() ? "Confirming…" : "Confirm authenticator"}
      </button>
    </form>
  );
}

function OperationMessage(
  props: Readonly<{
    error: Accessor<string | undefined>;
    message: Accessor<string | undefined>;
  }>,
): JSX.Element {
  return (
    <div class="form-message" aria-live="polite">
      <Show when={props.message()}>
        {(value) => <p class="success">{value()}</p>}
      </Show>
      <Show when={props.error()}>
        {(value) => <p class="error">{value()}</p>}
      </Show>
    </div>
  );
}
