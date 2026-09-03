// SPDX-License-Identifier: GPL-2.0-only

import { For, Show } from "solid-js";
import type { JSX } from "@solidjs/web";

import { instantFromEpochMicroseconds } from "../../domain/instant";
import type { ManualDnsTask, ManualDnsTaskDirectory } from "./model";

export function ManualDnsTaskList(
  props: Readonly<{ directory: ManualDnsTaskDirectory }>,
): JSX.Element {
  return (
    <section class="topology-section" aria-labelledby="manual-dns-heading">
      <div class="section-heading">
        <div>
          <p class="eyebrow">Manual DNS-01</p>
          <h2 id="manual-dns-heading">DNS work</h2>
        </div>
        <span>{props.directory.items().length} current</span>
      </div>
      <Show
        when={props.directory.phase() !== "loading"}
        fallback={<p class="skeleton-line">Reading DNS work…</p>}
      >
        <Show
          when={props.directory.items().length > 0}
          fallback={<p>No manual DNS records need attention.</p>}
        >
          <div class="topology-card-grid">
            <For each={props.directory.items()}>
              {(task) => <ManualDnsTaskCard task={task} />}
            </For>
          </div>
        </Show>
      </Show>
      <TaskActions directory={props.directory} />
    </section>
  );
}

function ManualDnsTaskCard(
  props: Readonly<{ task: ManualDnsTask }>,
): JSX.Element {
  return (
    <article class="topology-card manual-dns-card">
      <div>
        <span class={`state-pill state-${props.task.action}`}>
          {props.task.action === "publish" ? "Publish TXT" : "Remove TXT"}
        </span>
        <h3>{props.task.record_name}</h3>
        <code>{props.task.record_value}</code>
      </div>
      <small>Before {formatInstant(props.task.expires_at_epoch_micros)}</small>
    </article>
  );
}

function TaskActions(
  props: Readonly<{ directory: ManualDnsTaskDirectory }>,
): JSX.Element {
  return (
    <div class="list-footer" aria-live="polite">
      <Show when={props.directory.error()}>
        {(message) => <p class="error">{message()}</p>}
      </Show>
      <button
        class="quiet-action"
        disabled={props.directory.phase() !== "idle"}
        onClick={() => void props.directory.loadInitial()}
        type="button"
      >
        Refresh
      </button>
      <Show when={props.directory.nextPageUrl() !== null}>
        <button
          class="quiet-action"
          disabled={props.directory.phase() !== "idle"}
          onClick={() => void props.directory.loadNext()}
          type="button"
        >
          {props.directory.phase() === "loading_more"
            ? "Loading more DNS work…"
            : "Load more DNS work"}
        </button>
      </Show>
    </div>
  );
}

function formatInstant(epochMicros: number): string {
  return instantFromEpochMicroseconds(epochMicros).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}
