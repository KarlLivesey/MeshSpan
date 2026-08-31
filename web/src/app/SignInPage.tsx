// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, Show } from "solid-js";
import { useNavigate } from "@solidjs/router";
import type { JSX } from "@solidjs/web";

import { useSession } from "./session";

export function SignInPage(): JSX.Element {
  const session = useSession();
  const navigate = useNavigate();
  const [apiKey, setApiKey] = createSignal("");
  const [remember, setRemember] = createSignal(false);
  const [pending, setPending] = createSignal(false);
  const [error, setError] = createSignal<string>();

  const signIn = async (event: SubmitEvent): Promise<void> => {
    event.preventDefault();
    if (pending()) {
      return;
    }
    setPending(true);
    setError(undefined);
    try {
      await session.signInWithApiKey(apiKey(), remember());
      setApiKey("");
      navigate("/", { replace: true });
    } catch {
      setError("MeshSpan did not accept that API key. Check it and try again.");
    } finally {
      setPending(false);
    }
  };

  return (
    <section class="sign-in-page">
      <div class="sign-in-copy">
        <p class="eyebrow">Secure entry</p>
        <h1>Sign in to your swarm</h1>
        <p>
          Use one of your normal MeshSpan API keys. It is exchanged for a
          browser session and is never stored by this panel.
        </p>
      </div>
      <form class="sign-in-form" onSubmit={(event) => void signIn(event)}>
        <label>
          <span>API key</span>
          <input
            aria-describedby="api-key-note"
            autocomplete="current-password"
            disabled={pending()}
            onInput={(event) => setApiKey(event.currentTarget.value)}
            required
            spellcheck={false}
            type="password"
            value={apiKey()}
          />
        </label>
        <p id="api-key-note" class="field-note">
          The key must allow HTTPS session sign-in.
        </p>
        <label class="check-field">
          <input
            checked={remember()}
            disabled={pending()}
            onChange={(event) => setRemember(event.currentTarget.checked)}
            type="checkbox"
          />
          <span>Keep this browser signed in</span>
        </label>
        <button class="primary-action" disabled={pending()} type="submit">
          {pending() ? "Signing in…" : "Sign in"}
        </button>
        <div aria-live="polite">
          <Show when={error()}>
            {(message) => <p class="error">{message()}</p>}
          </Show>
        </div>
      </form>
    </section>
  );
}
