// SPDX-License-Identifier: GPL-2.0-only

import { For, Show } from "solid-js";
import type { JSX } from "@solidjs/web";

import type { StorageDrainSummary } from "../../generated";
import { instantFromEpochMicroseconds } from "../../domain/instant";
import type { StorageDrainDirectory } from "./storage-drain-model";

type Scope = StorageDrainSummary["scope"];

export function StorageDrainList(
  props: Readonly<{ directory: StorageDrainDirectory }>,
): JSX.Element {
  return (
    <>
      <Show when={props.directory.error()}>
        <p class="form-error" role="status" aria-live="polite">
          {props.directory.error()}
        </p>
      </Show>
      <Show
        when={props.directory.items().length > 0}
        fallback={<p>No storage drains have been requested.</p>}
      >
        <div class="topology-card-grid">
          <For each={props.directory.items()}>
            {(drain) => (
              <article class="topology-card">
                <div>
                  <span class={`state-pill state-${drain.state}`}>
                    {stateLabel(drain.state)}
                  </span>
                  <h3>{scopeLabel(drain.scope)}</h3>
                  <p>{scopeIdentity(drain.scope)}</p>
                </div>
                <small>
                  Requested {formatInstant(drain.requested_at_epoch_micros)}
                </small>
              </article>
            )}
          </For>
        </div>
      </Show>
      <Show when={props.directory.nextPageUrl() !== null}>
        <button type="button" onClick={() => void props.directory.loadMore()}>
          Show earlier drains
        </button>
      </Show>
    </>
  );
}

function scopeLabel(scope: Scope): string {
  if (scope.kind === "target") return "Storage folder";
  if (scope.kind === "node") return "Node";
  return "Shared-failure group";
}

function scopeIdentity(scope: Scope): string {
  if (scope.kind === "target") return shortId(scope.target_id);
  if (scope.kind === "node") return shortId(scope.node_id);
  return shortId(scope.fault_group_id);
}

function shortId(value: string): string {
  return `${value.slice(0, 8)}…`;
}

function stateLabel(state: string): string {
  if (state === "safe_to_detach") return "Safe to detach";
  if (state === "membership_fenced") return "Leaving consensus";
  return "Evacuating";
}

function formatInstant(epochMicros: number): string {
  return instantFromEpochMicroseconds(epochMicros).toLocaleString();
}
