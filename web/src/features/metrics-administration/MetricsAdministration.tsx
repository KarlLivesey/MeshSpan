// SPDX-License-Identifier: GPL-2.0-only

import { For, Show, createSignal, createEffect } from "solid-js";
import type { JSX } from "@solidjs/web";
import type { MetricsExporterResponse } from "../../generated";
import { MetricsUserPicker } from "./MetricsUserPicker";
import {
  createMetricsAdministration,
  type MetricsAdministration as Model,
  type MetricsClient,
} from "./model";

export function MetricsAdministration(
  props: Readonly<{ client: MetricsClient; csrfToken: string }>,
): JSX.Element {
  const model = createMetricsAdministration(
    () => props.client,
    () => props.csrfToken,
  );
  void model.load();
  return (
    <section class="topology-section" aria-labelledby="metrics-heading">
      <h2 id="metrics-heading">Metrics access</h2>
      <p>
        Let your monitoring tool read this node’s operational measurements. Off
        by default; no telemetry is sent anywhere automatically.
      </p>
      <p>
        Scrape endpoint: <code>/api/latest/metrics</code> on this node’s HTTPS
        address, using an Authorization bearer header. Format: OpenMetrics 1.0.
      </p>
      <p>
        Measurements are process-local observations, not proof that files are
        protected. Counters reset when the node restarts.
      </p>
      <button
        type="button"
        class="quiet-action"
        disabled={model.busy() || model.pending() !== undefined}
        onClick={() => void model.load()}
      >
        Refresh metrics settings
      </button>
      <Show
        when={model.configuration()}
        fallback={<p>Current metrics policy has not been loaded.</p>}
      >
        {(configuration) => (
          <MetricsSettings
            configuration={configuration()}
            model={model}
            client={props.client}
          />
        )}
      </Show>
      <Show when={model.pending()}>
        <button
          type="button"
          class="quiet-action"
          disabled={model.busy()}
          onClick={() => void model.retry()}
        >
          Retry metrics change
        </button>
      </Show>
      <div aria-live="polite">
        <Show when={model.busy()}>
          <p>Working on metrics settings…</p>
        </Show>
        <Show when={model.message()}>{(message) => <p>{message()}</p>}</Show>
        <Show when={model.error()}>
          {(error) => (
            <p class="error" role="alert">
              {error()}
            </p>
          )}
        </Show>
      </div>
    </section>
  );
}

function MetricsSettings(
  props: Readonly<{
    configuration: MetricsExporterResponse;
    model: Model;
    client: MetricsClient;
  }>,
): JSX.Element {
  const [enabled, setEnabled] = createSignal(false);
  const [selected, setSelected] = createSignal<readonly string[]>([]);
  createEffect(
    () => props.configuration.configuration?.policy,
    (policy) => {
      setEnabled(policy?.enabled ?? false);
      setSelected(policy?.allowed_principals ?? []);
    },
  );
  const locked = (): boolean =>
    props.model.busy() || props.model.pending() !== undefined;
  const select = (id: string): void => {
    if (!locked() && !selected().includes(id) && selected().length < 64)
      setSelected([...selected(), id]);
  };
  const submit = (event: SubmitEvent): void => {
    event.preventDefault();
    if (!locked()) void props.model.save(enabled(), selected());
  };
  return (
    <>
      <p>
        Current access:{" "}
        <strong>
          {props.configuration.configuration?.policy.enabled === true
            ? "Enabled"
            : "Off"}
        </strong>
      </p>
      <details class="backup-settings">
        <summary>Configure monitoring access</summary>
        <form onSubmit={submit}>
          <fieldset disabled={locked()}>
            <legend>Who can read metrics</legend>
            <label>
              <input
                type="checkbox"
                name="metrics_enabled"
                checked={enabled()}
                onChange={(event) => setEnabled(event.currentTarget.checked)}
              />{" "}
              Enable metrics access
            </label>
            <p>
              Selected users can connect with an existing HTTPS-capable API key.
              Administration alone does not grant access. Do not put a key in
              the URL.
            </p>
            <SelectedMetricsUsers
              selected={selected()}
              remove={(id) => {
                setSelected(selected().filter((value) => value !== id));
              }}
            />
            <MetricsUserPicker
              client={props.client}
              selected={selected()}
              disabled={locked()}
              onSelect={select}
            />
            <button class="primary-action" type="submit">
              Save metrics settings
            </button>
          </fieldset>
        </form>
      </details>
    </>
  );
}

function SelectedMetricsUsers(
  props: Readonly<{
    selected: readonly string[];
    remove: (id: string) => void;
  }>,
): JSX.Element {
  return (
    <>
      <ul aria-label="Selected metrics users">
        <For each={props.selected}>
          {(id) => (
            <li>
              <span class="identifier">{id}</span>{" "}
              <button
                type="button"
                class="quiet-action"
                onClick={() => {
                  props.remove(id);
                }}
              >
                Remove user {id}
              </button>
            </li>
          )}
        </For>
      </ul>
      <p>
        {props.selected.length} of 64 users selected. Selections on other pages
        are kept.
      </p>
    </>
  );
}
