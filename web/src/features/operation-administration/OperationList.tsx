// SPDX-License-Identifier: GPL-2.0-only

import { For, Show } from "solid-js";
import type { JSX } from "@solidjs/web";

import { instantFromEpochMicroseconds } from "../../domain/instant";
import type { OperationDirectory } from "./model";

export function OperationList(
  props: Readonly<{ directory: OperationDirectory }>,
): JSX.Element {
  return (
    <section aria-labelledby="operation-list-heading">
      <ListHeading count={props.directory.items().length} />
      <Show
        when={props.directory.phase() !== "loading"}
        fallback={<p class="skeleton-line">Reading durable operations…</p>}
      >
        <Show
          when={props.directory.items().length > 0}
          fallback={
            <p class="empty-state">No operations have been committed yet.</p>
          }
        >
          <OperationTable directory={props.directory} />
        </Show>
      </Show>
      <ListActions directory={props.directory} />
    </section>
  );
}

function ListHeading(props: Readonly<{ count: number }>): JSX.Element {
  return (
    <div class="principal-list-heading">
      <div>
        <p class="eyebrow">Recent activity</p>
        <h2 id="operation-list-heading">Operation journal</h2>
      </div>
      <span class="record-count">{props.count}</span>
    </div>
  );
}

function OperationTable(
  props: Readonly<{ directory: OperationDirectory }>,
): JSX.Element {
  return (
    <div class="principal-table-wrap">
      <table>
        <thead>
          <tr>
            <th scope="col">Operation</th>
            <th scope="col">State</th>
            <th scope="col">Progress</th>
            <th scope="col">Updated</th>
            <th scope="col">Revision</th>
          </tr>
        </thead>
        <tbody>
          <For each={props.directory.items()}>
            {(operation) => <OperationRow operation={operation} />}
          </For>
        </tbody>
      </table>
    </div>
  );
}

function OperationRow(
  props: Readonly<{
    operation: ReturnType<OperationDirectory["items"]>[number];
  }>,
): JSX.Element {
  const operation = () => props.operation;
  return (
    <tr>
      <th data-label="Operation" scope="row">
        <span class="operation-kind">{label(operation().kind)}</span>
        <code>{operation().operation_id}</code>
      </th>
      <td data-label="State">
        <span class={`state state-${operation().state}`}>
          {label(operation().state)}
        </span>
        <Show when={operation().failure}>
          {(failure) => <p class="error">{failure().message}</p>}
        </Show>
      </td>
      <td data-label="Progress">{progressLabel(operation())}</td>
      <td data-label="Updated" class="timestamp">
        {formatInstant(operation().updated_at_epoch_micros)}
      </td>
      <td data-label="Revision">{operation().revision}</td>
    </tr>
  );
}

function ListActions(
  props: Readonly<{ directory: OperationDirectory }>,
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
            ? "Loading more operations…"
            : "Load more operations"}
        </button>
      </Show>
    </div>
  );
}

function label(value: string): string {
  return value.replaceAll("_", " ");
}

function progressLabel(
  operation: ReturnType<OperationDirectory["items"]>[number],
): string {
  const progress = operation.progress;
  return progress === null
    ? label(operation.state)
    : `${String(progress.completed)} of ${String(progress.total)} ${progress.unit}`;
}

function formatInstant(epochMicros: number): string {
  return instantFromEpochMicroseconds(epochMicros).toLocaleString(undefined, {
    dateStyle: "medium",
    timeStyle: "short",
  });
}
