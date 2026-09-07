// SPDX-License-Identifier: GPL-2.0-only

import { For, Show, createSignal } from "solid-js";
import type { JSX } from "@solidjs/web";
import { instantFromEpochMicroseconds } from "../../domain/instant";
import type { MetricHistoryResponse } from "../../generated";
import { zMetricHistoryResponse } from "../../generated/zod.gen";
type MetricHistoryResolution = MetricHistoryResponse["resolution"];
type MetricHistoryPoint = MetricHistoryResponse["points"][number];
import { createMetricHistory, type MetricHistoryClient } from "./history";

/** Optional engineering history; loading it never enables external telemetry. */
export function MetricHistory(
  props: Readonly<{ client: MetricHistoryClient }>,
): JSX.Element {
  const history = createMetricHistory(() => props.client);
  const [resolution, setResolution] =
    createSignal<MetricHistoryResolution>("minute");
  return (
    <details class="backup-settings">
      <summary>Recent measurements on this node</summary>
      <p>
        Last observed samples, not averages or proof of protection. Gaps stay
        unknown. History clears when this daemon restarts.
      </p>
      <label>
        Time window
        <select
          disabled={history.loading()}
          value={resolution()}
          onChange={(event) =>
            setResolution(
              zMetricHistoryResponse.shape.resolution.parse(
                event.currentTarget.value,
              ),
            )
          }
        >
          <option value="minute">Six hours — minute samples</option>
          <option value="hour">Seven days — hourly samples</option>
        </select>
      </label>
      <button
        type="button"
        class="quiet-action"
        disabled={history.loading()}
        onClick={() => void history.load(resolution())}
      >
        Load recent history
      </button>
      <div aria-live="polite">
        <Show when={history.loading()}>
          <p>Reading one page of local history…</p>
        </Show>
        <Show when={history.error()}>
          {(error) => (
            <p class="error" role="alert">
              {error()}
            </p>
          )}
        </Show>
      </div>
      <Show when={history.page()}>
        {(page) => (
          <>
            <HistoryPage page={page()} />
            <Show when={page().next_page_url}>
              {(next) => (
                <button
                  type="button"
                  class="quiet-action"
                  disabled={history.loading()}
                  onClick={() => void history.load(page().resolution, next())}
                >
                  Older measurements
                </button>
              )}
            </Show>
          </>
        )}
      </Show>
    </details>
  );
}

function HistoryPage(
  props: Readonly<{ page: MetricHistoryResponse }>,
): JSX.Element {
  const [selected, setSelected] = createSignal("meshspan_v1_https_dispatches");
  const names = (): readonly string[] =>
    [
      ...new Set(
        props.page.points.flatMap(
          (point) => point.metrics?.map((metric) => metric.name) ?? [],
        ),
      ),
    ].sort((left, right) => left.localeCompare(right));
  const selection = (): string =>
    names().includes(selected()) ? selected() : (names()[0] ?? "");
  return (
    <>
      <p>
        {props.page.resolution === "minute" ? "Minute" : "Hourly"} observations,
        newest first. Counters and histograms accumulate within this process;
        they are not per-bucket rates.
      </p>
      <Show when={props.page.older_samples_expired}>
        <p>Earlier samples have expired from this local window.</p>
      </Show>
      <Show
        when={props.page.points.length > 0}
        fallback={
          <p>
            No samples yet. Load recent history after the daemon has had time to
            observe its work.
          </p>
        }
      >
        <label>
          Measurement
          <select
            value={selection()}
            onChange={(event) => setSelected(event.currentTarget.value)}
          >
            <For each={names()}>
              {(name) => (
                <option value={name}>
                  {name.replace("meshspan_v1_", "").replaceAll("_", " ")}
                </option>
              )}
            </For>
          </select>
        </label>
        <ol class="metric-history-samples">
          <For each={props.page.points}>
            {(point) => (
              <li>
                <span>{observedTime(point)}</span>
                {" — "}
                <strong>{measurement(point, selection())}</strong>
                <span>
                  {" "}
                  ({point.sampled_uptime_seconds} seconds after startup)
                </span>
              </li>
            )}
          </For>
        </ol>
      </Show>
    </>
  );
}

function observedTime(point: MetricHistoryPoint): string {
  return point.observed_at_epoch_micros === null
    ? "Wall-clock time unavailable"
    : instantFromEpochMicroseconds(point.observed_at_epoch_micros).toString();
}

function measurement(point: MetricHistoryPoint, name: string): string {
  if (point.metrics === null) return "Sample unavailable";
  const value = point.metrics.find(
    (metric) => metric.name === name,
  )?.measurement;
  if (value === undefined) return "Not observed";
  switch (value.kind) {
    case "counter":
    case "gauge":
      return value.value;
    case "bytes":
      return `${value.value} bytes`;
    case "seconds":
      return `${value.value} seconds`;
    case "histogram":
      return `${value.count} observations; ${value.sum_seconds} seconds total`;
  }
}
