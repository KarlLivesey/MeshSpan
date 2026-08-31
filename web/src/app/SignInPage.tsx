// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, Show, type Accessor, type Setter } from "solid-js";
import { useNavigate } from "@solidjs/router";
import type { JSX } from "@solidjs/web";

import { useSession, type SessionAdditionalFactor } from "./session";

type FactorKind = "none" | "recovery_code" | "totp";
type PendingMethod = "api_key" | "passkey";

export function SignInPage(): JSX.Element {
  const session = useSession();
  const navigate = useNavigate();
  const [apiKey, setApiKey] = createSignal("");
  const [factorCode, setFactorCode] = createSignal("");
  const [factorKind, setFactorKind] = createSignal<FactorKind>("none");
  const [remember, setRemember] = createSignal(false);
  const [pending, setPending] = createSignal<PendingMethod>();
  const [error, setError] = createSignal<string>();

  const finishSignIn = async (operation: Promise<void>): Promise<void> => {
    setError(undefined);
    try {
      await operation;
      setApiKey("");
      setFactorCode("");
      navigate("/", { replace: true });
    } catch {
      setError(
        "MeshSpan could not complete sign-in. Check the selected method and factor, then try again.",
      );
    } finally {
      setPending(undefined);
    }
  };

  const signIn = (method: PendingMethod): void => {
    if (pending() !== undefined) {
      return;
    }
    const factor = readAdditionalFactor(factorKind(), factorCode());
    const persistent = remember();
    setPending(method);
    const operation =
      method === "passkey"
        ? session.signInWithPasskey(persistent, factor)
        : session.signInWithApiKey(apiKey(), persistent, factor);
    void finishSignIn(operation);
  };

  return (
    <section class="sign-in-page">
      <SignInIntroduction />
      <div class="sign-in-form">
        <PasskeyEntry
          pending={pending}
          signIn={() => {
            signIn("passkey");
          }}
        />
        <div class="sign-in-divider" aria-hidden="true">
          <span>or</span>
        </div>
        <ApiKeyEntry
          apiKey={apiKey}
          pending={pending}
          setApiKey={setApiKey}
          signIn={() => {
            signIn("api_key");
          }}
        />
        <AdditionalFactorEntry
          code={factorCode}
          kind={factorKind}
          pending={pending}
          setCode={setFactorCode}
          setKind={setFactorKind}
        />
        <SignInPreferences
          error={error}
          pending={pending}
          remember={remember}
          setRemember={setRemember}
        />
      </div>
    </section>
  );
}

function SignInPreferences(
  props: Readonly<{
    error: Accessor<string | undefined>;
    pending: Accessor<PendingMethod | undefined>;
    remember: Accessor<boolean>;
    setRemember: Setter<boolean>;
  }>,
): JSX.Element {
  return (
    <>
      <label class="check-field">
        <input
          checked={props.remember()}
          disabled={props.pending() !== undefined}
          onChange={(event) => props.setRemember(event.currentTarget.checked)}
          type="checkbox"
        />
        <span>Keep this browser signed in</span>
      </label>
      <div aria-live="polite">
        <Show when={props.error()}>
          {(message) => <p class="error">{message()}</p>}
        </Show>
      </div>
    </>
  );
}

function SignInIntroduction(): JSX.Element {
  return (
    <div class="sign-in-copy">
      <p class="eyebrow">Secure entry</p>
      <h1>Sign in to your swarm</h1>
      <p>
        Use a passkey for ordinary access. API-key sign-in remains available for
        initial setup, recovery and explicitly scoped credentials.
      </p>
    </div>
  );
}

function PasskeyEntry(
  props: Readonly<{
    pending: Accessor<PendingMethod | undefined>;
    signIn: () => void;
  }>,
): JSX.Element {
  return (
    <div class="sign-in-method">
      <h2>Passkey</h2>
      <p class="field-note-reset">
        Your browser will ask for the passkey stored on this device or a nearby
        authenticator.
      </p>
      <button
        class="primary-action"
        disabled={props.pending() !== undefined}
        onClick={() => {
          props.signIn();
        }}
        type="button"
      >
        {props.pending() === "passkey"
          ? "Waiting for passkey…"
          : "Use a passkey"}
      </button>
    </div>
  );
}

function ApiKeyEntry(
  props: Readonly<{
    apiKey: Accessor<string>;
    pending: Accessor<PendingMethod | undefined>;
    setApiKey: Setter<string>;
    signIn: () => void;
  }>,
): JSX.Element {
  return (
    <form
      class="sign-in-method"
      onSubmit={(event) => {
        event.preventDefault();
        props.signIn();
      }}
    >
      <h2>API key</h2>
      <label>
        <span>API key</span>
        <input
          aria-describedby="api-key-note"
          autocomplete="current-password"
          disabled={props.pending() !== undefined}
          onInput={(event) => props.setApiKey(event.currentTarget.value)}
          required
          spellcheck={false}
          type="password"
          value={props.apiKey()}
        />
      </label>
      <p id="api-key-note" class="field-note-reset">
        The key must include HTTPS session access.
      </p>
      <button
        class="quiet-button"
        disabled={props.pending() !== undefined}
        type="submit"
      >
        {props.pending() === "api_key" ? "Signing in…" : "Sign in with API key"}
      </button>
    </form>
  );
}

function AdditionalFactorEntry(
  props: Readonly<{
    code: Accessor<string>;
    kind: Accessor<FactorKind>;
    pending: Accessor<PendingMethod | undefined>;
    setCode: Setter<string>;
    setKind: Setter<FactorKind>;
  }>,
): JSX.Element {
  return (
    <fieldset class="factor-fields" disabled={props.pending() !== undefined}>
      <legend>Additional factor</legend>
      <label>
        <span>Only if your swarm requires one</span>
        <select
          onChange={(event) =>
            props.setKind(event.currentTarget.value as FactorKind)
          }
          value={props.kind()}
        >
          <option value="none">No additional factor</option>
          <option value="totp">Authenticator code</option>
          <option value="recovery_code">Recovery code</option>
        </select>
      </label>
      <Show when={props.kind() !== "none"}>
        <label>
          <span>
            {props.kind() === "totp" ? "Authenticator code" : "Recovery code"}
          </span>
          <input
            autocomplete={props.kind() === "totp" ? "one-time-code" : "off"}
            inputmode={props.kind() === "totp" ? "numeric" : "text"}
            onInput={(event) => props.setCode(event.currentTarget.value)}
            required
            spellcheck={false}
            value={props.code()}
          />
        </label>
      </Show>
    </fieldset>
  );
}

function readAdditionalFactor(
  kind: FactorKind,
  code: string,
): SessionAdditionalFactor | undefined {
  return kind === "none" ? undefined : { code: code.trim(), method: kind };
}
