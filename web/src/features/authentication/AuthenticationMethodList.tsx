// SPDX-License-Identifier: GPL-2.0-only

import { For, Show } from "solid-js";
import type { JSX } from "@solidjs/web";

import { AuthenticationMethodCard } from "./AuthenticationMethodCard";
import type { AuthenticationMethodSummary } from "./model";

type AuthenticationMethodListProps = Readonly<{
  error: string | undefined;
  items: readonly AuthenticationMethodSummary[];
  loading: boolean;
  loadingMore: boolean;
  nextPageAvailable: boolean;
  onLoadMore: () => Promise<void>;
  onRevoke: (methodId: string, reason: string) => Promise<void>;
}>;

export function AuthenticationMethodList(
  props: AuthenticationMethodListProps,
): JSX.Element {
  return (
    <section class="authentication-methods" aria-labelledby="method-list-title">
      <div class="section-heading method-list-heading">
        <div>
          <p class="eyebrow">Current access</p>
          <h2 id="method-list-title">Your sign-in methods</h2>
        </div>
        <span
          class="record-count"
          aria-label={`${String(props.items.length)} loaded methods`}
        >
          {props.items.length}
        </span>
      </div>
      <Show when={props.error !== undefined}>
        <p class="error" role="alert">
          {props.error}
        </p>
      </Show>
      <Show when={props.loading}>
        <div class="skeleton-line" aria-label="Loading sign-in methods" />
      </Show>
      <Show when={!props.loading && props.items.length === 0}>
        <p class="empty-state">No sign-in methods were returned.</p>
      </Show>
      <div class="method-grid">
        <For each={props.items}>
          {(method) => (
            <AuthenticationMethodCard
              method={method}
              onRevoke={props.onRevoke}
            />
          )}
        </For>
      </div>
      <Show when={props.nextPageAvailable}>
        <button
          class="quiet-action"
          disabled={props.loadingMore}
          onClick={() => {
            void props.onLoadMore();
          }}
          type="button"
        >
          {props.loadingMore ? "Loading…" : "Load more methods"}
        </button>
      </Show>
    </section>
  );
}
