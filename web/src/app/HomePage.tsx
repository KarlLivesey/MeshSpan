// SPDX-License-Identifier: GPL-2.0-only

import { Show } from "solid-js";
import type { JSX } from "@solidjs/web";

import { FileBrowser } from "../features/file-browser/FileBrowser";
import { useSession } from "./session";

export function HomePage(): JSX.Element {
  const session = useSession();

  return (
    <Show
      when={session.state().phase === "authenticated"}
      fallback={
        <AnonymousHome checking={session.state().phase === "checking"} />
      }
    >
      <FileBrowser client={session.client} csrfToken={session.csrfToken} />
    </Show>
  );
}

function AnonymousHome(props: Readonly<{ checking: boolean }>): JSX.Element {
  return (
    <section class="home-page">
      <div>
        <p class="eyebrow">Your swarm</p>
        <h1>Files, without the machinery.</h1>
        <p class="home-lead">
          MeshSpan keeps placement, repair and consensus out of the ordinary
          path.
        </p>
      </div>
      <Show when={!props.checking}>
        <a class="primary-action" href="/sign-in">
          Sign in to this swarm
        </a>
      </Show>
    </section>
  );
}
