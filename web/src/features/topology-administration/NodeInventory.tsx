// SPDX-License-Identifier: GPL-2.0-only

import { For, Show } from "solid-js";
import type { JSX } from "@solidjs/web";

import type { TopologyDirectory } from "./model";

export function NodeInventory(
  props: Readonly<{ directory: TopologyDirectory }>,
): JSX.Element {
  return (
    <section class="topology-section" aria-labelledby="topology-nodes-title">
      <div class="section-heading">
        <div>
          <p class="eyebrow">Processes and machines</p>
          <h2 id="topology-nodes-title">Nodes</h2>
        </div>
        <span>{props.directory.nodes().length} shown</span>
      </div>
      <Show
        when={props.directory.nodes().length > 0}
        fallback={<p>No mesh nodes are visible yet.</p>}
      >
        <div class="topology-card-grid">
          <For each={props.directory.nodes()}>
            {(node) => (
              <article class="topology-card">
                <div>
                  <span class={`state-pill state-${node.state}`}>
                    {node.state}
                  </span>
                  <h3>{node.display_name}</h3>
                  <p>Machine {shortId(node.host_id)}</p>
                </div>
                <ul class="role-list" aria-label="Node roles">
                  <Show when={node.roles.storage}>
                    <li>Storage</li>
                  </Show>
                  <Show when={node.roles.gateway}>
                    <li>Gateway</li>
                  </Show>
                  <Show when={node.roles.metadata_eligible}>
                    <li>Metadata eligible</li>
                  </Show>
                </ul>
                <small>{node.private_endpoint ?? "Endpoint not active yet"}</small>
              </article>
            )}
          </For>
        </div>
      </Show>
      <Show when={props.directory.nextNodes()}>
        <button
          type="button"
          onClick={() => {
            void props.directory.loadMoreNodes();
          }}
        >
          Show more nodes
        </button>
      </Show>
    </section>
  );
}

function shortId(value: string): string {
  return `${value.slice(0, 8)}…`;
}
