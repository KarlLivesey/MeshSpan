// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, onCleanup, type Accessor } from "solid-js";
import type {
  MeshSpanFetchClient,
  MetricHistoryResponse,
} from "../../generated";
type MetricHistoryResolution = MetricHistoryResponse["resolution"];

export type MetricHistoryClient = Pick<
  MeshSpanFetchClient,
  "getMetricHistory" | "getNextMetricHistory"
>;
type History = Readonly<{
  page: Accessor<MetricHistoryResponse | undefined>;
  loading: Accessor<boolean>;
  error: Accessor<string | undefined>;
  load: (resolution: MetricHistoryResolution, next?: string) => Promise<void>;
}>;

/** Owns one page and one request; never prefetches or retains data after a refused read. */
export function createMetricHistory(
  client: Accessor<MetricHistoryClient>,
): History {
  const [page, setPage] = createSignal<MetricHistoryResponse | undefined>(
    undefined,
    { ownedWrite: true },
  );
  const [loading, setLoading] = createSignal(false, { ownedWrite: true });
  const [error, setError] = createSignal<string | undefined>(undefined, {
    ownedWrite: true,
  });
  let active = true;
  const isActive = (): boolean => active;
  let inFlight = false;
  onCleanup(() => {
    active = false;
  });
  const load = async (
    resolution: MetricHistoryResolution,
    next?: string,
  ): Promise<void> => {
    if (!isActive() || inFlight) return;
    inFlight = true;
    setLoading(true);
    setPage();
    setError();
    const current = client();
    try {
      const result =
        next === undefined
          ? await current.getMetricHistory({ resolution })
          : await current.getNextMetricHistory(next);
      if (isActive() && current === client()) setPage(result);
    } catch {
      if (isActive())
        setError(
          "History could not be read. Check your connection and access, then load recent history again. A restart clears this node’s history.",
        );
    } finally {
      inFlight = false;
      if (isActive()) setLoading(false);
    }
  };
  return { page, loading, error, load };
}
