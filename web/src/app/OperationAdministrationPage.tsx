// SPDX-License-Identifier: GPL-2.0-only

import { Match, Switch } from "solid-js";
import type { JSX } from "@solidjs/web";

import { OperationAdministrationPanel } from "../features/operation-administration/OperationAdministrationPanel";
import { useSession } from "./session";

export function OperationAdministrationPage(): JSX.Element {
  const session = useSession();
  const current = () => {
    const value = session.state();
    return value.phase === "authenticated" ? value.session : undefined;
  };

  return (
    <Switch>
      <Match when={session.state().phase === "checking"}>
        <p class="route-status" aria-live="polite">
          Confirming administration access…
        </p>
      </Match>
      <Match when={session.state().phase === "unavailable"}>
        <p class="route-status error">
          MeshSpan could not confirm administration access. Try again when the
          local service is reachable.
        </p>
      </Match>
      <Match when={session.state().phase === "anonymous"}>
        <section class="route-status">
          <h1>Sign in required</h1>
          <p>Sign in before opening swarm administration.</p>
          <a class="primary-action" href="/sign-in">
            Go to sign in
          </a>
        </section>
      </Match>
      <Match when={current()?.administration_available === true}>
        <OperationAdministrationPanel
          client={session.client}
          csrfToken={session.csrfToken() ?? ""}
        />
      </Match>
      <Match when={true}>
        <section class="route-status">
          <h1>Administration is not available</h1>
          <p>Your current permissions do not include swarm administration.</p>
        </section>
      </Match>
    </Switch>
  );
}
