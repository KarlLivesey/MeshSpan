// SPDX-License-Identifier: GPL-2.0-only

import { For, Show } from "solid-js";
import type { JSX } from "@solidjs/web";

import type { TopologyDirectory, TopologyTarget } from "./model";

export function TargetInventory(
  props: Readonly<{ directory: TopologyDirectory }>,
): JSX.Element {
  return (
    <section class="topology-section" aria-labelledby="topology-targets-title">
      <div class="section-heading">
        <div>
          <p class="eyebrow">Mesh-wide capacity</p>
          <h2 id="topology-targets-title">Storage targets</h2>
        </div>
        <span>{props.directory.targets().length} shown</span>
      </div>
      <p>
        Local filesystem paths stay private to their daemon; this view shows
        only the identities and limits needed by the mesh.
      </p>
      <Show
        when={props.directory.targets().length > 0}
        fallback={<p>No storage targets have been registered yet.</p>}
      >
        <div class="topology-card-grid">
          <For each={props.directory.targets()}>
            {(target) => (
              <article class="topology-card">
                <div>
                  <span class={`state-pill state-${target.state}`}>
                    {target.state}
                  </span>
                  <h3>{target.display_name}</h3>
                  <p>Machine {target.host_id.slice(0, 8)}…</p>
                </div>
                <strong>{formatLimit(target)}</strong>
                <small>Generation {target.generation}</small>
              </article>
            )}
          </For>
        </div>
      </Show>
      <Show when={props.directory.nextTargets()}>
        <button
          type="button"
          onClick={() => {
            void props.directory.loadMoreTargets();
          }}
        >
          Show more targets
        </button>
      </Show>
    </section>
  );
}

function formatLimit(target: TopologyTarget): string {
  return target.usage_limit.kind === "percent"
    ? `${String(target.usage_limit.percent)}% capacity ceiling`
    : `${target.usage_limit.bytes} byte ceiling`;
}
