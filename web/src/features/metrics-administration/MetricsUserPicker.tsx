// SPDX-License-Identifier: GPL-2.0-only

import { For, Show, createSignal, onCleanup, type Accessor } from "solid-js";
import type { JSX } from "@solidjs/web";
import type { ListPrincipalsResponse } from "../../generated";
import type { MetricsClient } from "./model";

/** Keeps one bounded server page; selected identities are owned by the policy form. */
export function MetricsUserPicker(
  props: Readonly<{
    client: MetricsClient;
    selected: readonly string[];
    disabled: boolean;
    onSelect: (id: string) => void;
  }>,
): JSX.Element {
  const directory = createUserPage(
    () => props.client,
    () => props.disabled,
  );
  return (
    <div>
      <button
        type="button"
        class="quiet-action"
        disabled={props.disabled || directory.busy()}
        onClick={() => void directory.load()}
      >
        Choose users
      </button>
      <Show when={directory.page()}>
        {(current) => (
          <>
            <ul aria-label="Available metrics users">
              <For each={current().principals}>
                {(user) => (
                  <li>
                    {user.display_name}{" "}
                    <button
                      type="button"
                      class="quiet-action"
                      disabled={
                        props.disabled ||
                        directory.busy() ||
                        user.state !== "active" ||
                        props.selected.includes(user.principal_id) ||
                        props.selected.length >= 64
                      }
                      onClick={() => {
                        props.onSelect(user.principal_id);
                      }}
                    >
                      Allow {user.display_name}
                    </button>
                  </li>
                )}
              </For>
            </ul>
            <Show when={current().next_page_url}>
              {(next) => (
                <button
                  type="button"
                  class="quiet-action"
                  disabled={props.disabled || directory.busy()}
                  onClick={() => void directory.load(next())}
                >
                  Next users
                </button>
              )}
            </Show>
          </>
        )}
      </Show>
      <Show when={directory.error()}>
        {(message) => (
          <p class="error" role="alert">
            {message()}
          </p>
        )}
      </Show>
    </div>
  );
}

type UserPage = Readonly<{
  page: Accessor<ListPrincipalsResponse | undefined>;
  busy: Accessor<boolean>;
  error: Accessor<string | undefined>;
  load: (next?: string) => Promise<void>;
}>;

function createUserPage(
  client: Accessor<MetricsClient>,
  disabled: Accessor<boolean>,
): UserPage {
  const [page, setPage] = createSignal<ListPrincipalsResponse | undefined>(
    undefined,
    {
      ownedWrite: true,
    },
  );
  const [busy, setBusy] = createSignal(false, { ownedWrite: true });
  const [error, setError] = createSignal<string | undefined>(undefined, {
    ownedWrite: true,
  });
  let alive = true;
  const mounted = (): boolean => alive;
  let inFlight = false;
  onCleanup(() => {
    alive = false;
  });
  const load = async (next?: string): Promise<void> => {
    if (!mounted() || inFlight || disabled()) return;
    inFlight = true;
    setBusy(true);
    setError();
    try {
      const result =
        next === undefined
          ? await client().listUsers()
          : await client().listNextPrincipals(next);
      if (result.kind !== "user")
        throw new TypeError("Metrics consumers must be users.");
      if (mounted()) setPage(result);
    } catch {
      if (mounted())
        setError("Could not read users. Refresh the user list to try again.");
    } finally {
      inFlight = false;
      if (mounted()) setBusy(false);
    }
  };
  return { page, busy, error, load };
}
