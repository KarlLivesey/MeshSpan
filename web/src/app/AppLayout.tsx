// SPDX-License-Identifier: GPL-2.0-only

import { Show, type ParentProps } from "solid-js";
import type { JSX } from "@solidjs/web";

import { useSession } from "./session";

export function AppLayout(props: Readonly<ParentProps>): JSX.Element {
  const session = useSession();
  const authenticated = () =>
    session.state().phase === "authenticated" ? session.state() : undefined;
  const canAdminister = () => {
    const current = authenticated();
    return (
      current?.phase === "authenticated" &&
      current.session.administration_available
    );
  };

  return (
    <>
      <a class="skip-link" href="#main-content">
        Skip to main content
      </a>
      <header class="app-header">
        <a class="wordmark" href="/">
          <span class="wordmark-mark" aria-hidden="true">
            M
          </span>
          <span>MeshSpan</span>
        </a>
        <nav aria-label="Primary navigation">
          <a href="/">Files</a>
          <Show when={canAdminister()}>
            <a href="/admin/identities">Administration</a>
          </Show>
        </nav>
        <Show
          when={authenticated()}
          fallback={
            <a class="header-action" href="/sign-in">
              Sign in
            </a>
          }
        >
          <button
            class="header-action"
            onClick={() => void session.signOut()}
            type="button"
          >
            Sign out
          </button>
        </Show>
      </header>
      <main id="main-content">{props.children}</main>
    </>
  );
}
