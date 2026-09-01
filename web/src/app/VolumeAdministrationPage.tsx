// SPDX-License-Identifier: GPL-2.0-only

import { Match, Switch } from "solid-js";
import type { JSX } from "@solidjs/web";

import { VolumeAdministrationPanel } from "../features/volume-administration/VolumeAdministrationPanel";
import { useSession } from "./session";

export function VolumeAdministrationPage(): JSX.Element {
  const session = useSession();
  const state = session.state;
  const current = () => {
    const value = state();
    return value.phase === "authenticated" ? value.session : undefined;
  };

  return (
    <Switch>
      <Match when={state().phase === "checking"}>
        <p class="route-status" aria-live="polite">
          Confirming administration access…
        </p>
      </Match>
      <Match when={state().phase === "unavailable"}>
        <p class="route-status error">
          MeshSpan could not confirm administration access. Try again when the
          local service is reachable.
        </p>
      </Match>
      <Match when={state().phase === "anonymous"}>
        <section class="route-status">
          <h1>Sign in required</h1>
          <p>Sign in before opening swarm administration.</p>
          <a class="primary-action" href="/sign-in">
            Go to sign in
          </a>
        </section>
      </Match>
      <Match
        when={current() !== undefined && !current()?.administration_available}
      >
        <section class="route-status">
          <h1>Administration is not available</h1>
          <p>Your current permissions do not include swarm administration.</p>
        </section>
      </Match>
      <Match
        when={
          current()?.administration_available === true &&
          session.csrfToken() !== undefined
        }
      >
        <VolumeAdministrationPanel
          client={session.client}
          csrfToken={session.csrfToken() ?? ""}
        />
      </Match>
      <Match when={true}>
        <section class="route-status">
          <h1>Sign in again to make changes</h1>
          <p>The browser session is valid, but its mutation proof is absent.</p>
          <a class="primary-action" href="/sign-in">
            Sign in again
          </a>
        </section>
      </Match>
    </Switch>
  );
}
