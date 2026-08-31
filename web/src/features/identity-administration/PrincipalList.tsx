// SPDX-License-Identifier: GPL-2.0-only

import { For, Show } from "solid-js";
import type { JSX } from "@solidjs/web";

import { instantFromEpochMicroseconds } from "../../domain/instant";
import type {
  PrincipalDirectory,
  PrincipalKind,
  PrincipalSummary,
} from "./model";

type PrincipalListProps = Readonly<{
  directory: PrincipalDirectory;
  kind: PrincipalKind;
  onSelect?: (principal: PrincipalSummary) => void;
  selectedPrincipalId?: string | undefined;
}>;

export function PrincipalList(props: PrincipalListProps): JSX.Element {
  const plural = () => (props.kind === "user" ? "Users" : "Groups");
  const emptyMessage = () =>
    props.kind === "user"
      ? "No users yet. Create one when someone needs access."
      : "No groups yet. Groups make shared access easier to manage.";

  return (
    <section class="principal-list" aria-labelledby={`${props.kind}-heading`}>
      <div class="principal-list-heading">
        <div>
          <p class="eyebrow">Current directory</p>
          <h2 id={`${props.kind}-heading`}>{plural()}</h2>
        </div>
        <span class="record-count">{props.directory.items().length}</span>
      </div>

      <Show
        when={props.directory.phase() !== "loading"}
        fallback={<p class="skeleton-line">Reading committed identities…</p>}
      >
        <Show
          when={props.directory.items().length > 0}
          fallback={<p class="empty-state">{emptyMessage()}</p>}
        >
          <PrincipalTable {...props} />
        </Show>
      </Show>

      <PrincipalListFooter directory={props.directory} plural={plural()} />
    </section>
  );
}

function PrincipalTable(props: PrincipalListProps): JSX.Element {
  return (
    <div class="principal-table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">Name</th>
            <th scope="col">State</th>
            <th scope="col">Created</th>
            <Show when={props.onSelect !== undefined}>
              <th scope="col">Membership</th>
            </Show>
          </tr>
        </thead>
        <tbody>
          <For each={props.directory.items()}>
            {(principal) => <PrincipalRow {...props} principal={principal} />}
          </For>
        </tbody>
      </table>
    </div>
  );
}

type PrincipalRowProps = PrincipalListProps &
  Readonly<{ principal: PrincipalSummary }>;

function PrincipalRow(props: PrincipalRowProps): JSX.Element {
  const selected = () =>
    props.selectedPrincipalId === props.principal.principal_id;
  return (
    <tr>
      <th data-label="Name" scope="row">
        {props.principal.display_name}
      </th>
      <td data-label="State">
        <span class={`state state-${props.principal.state}`}>
          {props.principal.state}
        </span>
      </td>
      <td data-label="Created" class="timestamp">
        {formatInstant(props.principal.created_at_epoch_micros)}
      </td>
      <Show when={props.onSelect !== undefined}>
        <td data-label="Membership">
          <button
            aria-pressed={selected() ? "true" : "false"}
            class="quiet-action table-action"
            onClick={() => {
              props.onSelect?.(props.principal);
            }}
            type="button"
          >
            {selected() ? "Managing" : "Manage members"}
          </button>
        </td>
      </Show>
    </tr>
  );
}

function PrincipalListFooter(
  props: Readonly<{ directory: PrincipalDirectory; plural: string }>,
): JSX.Element {
  return (
    <div class="list-footer" aria-live="polite">
      <Show when={props.directory.error()}>
        {(message) => <p class="error">{message()}</p>}
      </Show>
      <Show when={props.directory.nextPageUrl() !== null}>
        <button
          class="quiet-action"
          disabled={props.directory.phase() !== "idle"}
          onClick={() => void props.directory.loadNext()}
          type="button"
        >
          {props.directory.phase() === "loading_more"
            ? `Loading more ${props.plural.toLowerCase()}…`
            : `Load more ${props.plural.toLowerCase()}`}
        </button>
      </Show>
    </div>
  );
}

function formatInstant(epochMicroseconds: number): string {
  return instantFromEpochMicroseconds(epochMicroseconds).toLocaleString(
    undefined,
    {
      dateStyle: "medium",
      timeStyle: "short",
    },
  );
}
