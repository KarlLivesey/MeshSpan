// SPDX-License-Identifier: GPL-2.0-only

import { Match, Switch } from "solid-js";
import type { JSX } from "@solidjs/web";

import { AuthenticationSecurityPanel } from "../features/authentication/AuthenticationSecurityPanel";
import { useSession } from "./session";

export function SecurityPage(): JSX.Element {
  const session = useSession();

  return (
    <Switch>
      <Match when={session.state().phase === "checking"}>
        <p class="route-status" aria-live="polite">
          Confirming account access…
        </p>
      </Match>
      <Match when={session.state().phase === "unavailable"}>
        <p class="route-status error">
          MeshSpan could not confirm this session. Try again when the local
          service is reachable.
        </p>
      </Match>
      <Match when={session.state().phase === "anonymous"}>
        <section class="route-status">
          <h1>Sign in required</h1>
          <p>Sign in before managing your account security.</p>
          <a class="primary-action" href="/sign-in">
            Go to sign in
          </a>
        </section>
      </Match>
      <Match when={session.csrfToken() !== undefined}>
        <AuthenticationSecurityPanel
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
