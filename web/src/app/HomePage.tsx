// SPDX-License-Identifier: GPL-2.0-only

import { Show } from "solid-js";
import type { JSX } from "@solidjs/web";

import { useSession } from "./session";

export function HomePage(): JSX.Element {
  const session = useSession();

  return (
    <section class="home-page">
      <div>
        <p class="eyebrow">Your swarm</p>
        <h1>Files, without the machinery.</h1>
        <p class="home-lead">
          The file browser lands here next. MeshSpan keeps placement, repair and
          consensus out of the ordinary path.
        </p>
      </div>
      <Show when={session.state().phase === "anonymous"}>
        <a class="primary-action" href="/sign-in">
          Sign in to this swarm
        </a>
      </Show>
    </section>
  );
}
