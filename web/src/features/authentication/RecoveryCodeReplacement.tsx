// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, For, Show } from "solid-js";
import type { JSX } from "@solidjs/web";

import type { AuthenticationSecurityClient } from "./model";

type RecoveryCodeReplacementProps = Readonly<{
  client: AuthenticationSecurityClient;
  csrfToken: string;
  onChanged: () => Promise<void>;
}>;

export function RecoveryCodeReplacement(
  props: RecoveryCodeReplacementProps,
): JSX.Element {
  const [codes, setCodes] = createSignal<readonly string[]>();
  const [pending, setPending] = createSignal(false);
  const [error, setError] = createSignal<string>();

  const replace = async (): Promise<void> => {
    if (pending()) {
      return;
    }
    setPending(true);
    setCodes(undefined);
    setError(undefined);
    try {
      const result = await props.client.createCurrentUserRecoveryCodes(
        { label: "Recovery codes", operation_id: crypto.randomUUID() },
        props.csrfToken,
      );
      setCodes(result.codes);
      await props.onChanged();
    } catch {
      setError("MeshSpan could not replace your recovery codes.");
    } finally {
      setPending(false);
    }
  };

  return (
    <section class="security-action-card">
      <div>
        <p class="eyebrow">Recovery</p>
        <h3>Recovery codes</h3>
        <p>
          Generating a set permanently replaces any previous recovery codes.
        </p>
      </div>
      <button
        class="quiet-button"
        disabled={pending()}
        onClick={() => void replace()}
        type="button"
      >
        {pending() ? "Generating…" : "Generate new recovery codes"}
      </button>
      <Show when={codes()}>
        {(values) => (
          <div
            class="one-time-secret"
            role="group"
            aria-label="New recovery codes"
          >
            <p class="sensitive-note">
              Save these now. MeshSpan will not show them through an ordinary
              read.
            </p>
            <ol class="recovery-code-list">
              <For each={values()}>{(code) => <li>{code}</li>}</For>
            </ol>
          </div>
        )}
      </Show>
      <div class="form-message" aria-live="polite">
        <Show when={error()}>{(value) => <p class="error">{value()}</p>}</Show>
      </div>
    </section>
  );
}
