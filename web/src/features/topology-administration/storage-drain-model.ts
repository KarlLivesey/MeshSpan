// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, type Accessor } from "solid-js";

import type {
  BeginStorageDrainRequest,
  ListStorageDrainsResponse,
  MeshSpanFetchClient,
  StorageDrainSummary,
} from "../../generated";

export type StorageDrainClient = Pick<
  MeshSpanFetchClient,
  "beginStorageDrain" | "listNextStorageDrains" | "listStorageDrains"
>;

export type StorageDrainDirectory = Readonly<{
  begin: (
    scope: BeginStorageDrainRequest["scope"],
    allowTemporaryDegraded: boolean,
    cleanupRequested: boolean,
    csrfToken: string,
  ) => Promise<void>;
  error: Accessor<string | undefined>;
  items: Accessor<readonly StorageDrainSummary[]>;
  load: () => Promise<void>;
  loadMore: () => Promise<void>;
  nextPageUrl: Accessor<string | null>;
  phase: Accessor<"idle" | "loading" | "saving">;
}>;

export function createStorageDrainDirectory(
  client: Accessor<StorageDrainClient>,
): StorageDrainDirectory {
  const [items, setItems] = createSignal<readonly StorageDrainSummary[]>([], {
    equals: false,
    ownedWrite: true,
  });
  const [nextPageUrl, setNextPageUrl] = createSignal<string | null>(null, {
    ownedWrite: true,
  });
  const [phase, setPhase] = createSignal<"idle" | "loading" | "saving">(
    "idle",
    { ownedWrite: true },
  );
  const [error, setError] = createSignal<string | undefined>(undefined, {
    ownedWrite: true,
  });

  const apply = (page: ListStorageDrainsResponse, append: boolean): void => {
    setItems((current) => merge(append ? current : [], page.drains));
    setNextPageUrl(page.next_page_url);
  };

  const load = async (): Promise<void> => {
    if (phase() !== "idle") return;
    setPhase("loading");
    setError();
    try {
      apply(await client().listStorageDrains(), false);
    } catch {
      setError("MeshSpan could not read safe-removal progress.");
    } finally {
      setPhase("idle");
    }
  };

  const loadMore = async (): Promise<void> => {
    const next = nextPageUrl();
    if (next === null || phase() !== "idle") return;
    setPhase("loading");
    setError();
    try {
      apply(await client().listNextStorageDrains(next), true);
    } catch {
      setError("MeshSpan could not read the next safe-removal page.");
    } finally {
      setPhase("idle");
    }
  };

  const begin: StorageDrainDirectory["begin"] = async (
    scope,
    allowTemporaryDegraded,
    cleanupRequested,
    csrfToken,
  ) => {
    if (phase() !== "idle") return;
    setPhase("saving");
    setError();
    try {
      const response = await client().beginStorageDrain(
        {
          allow_temporary_degraded: allowTemporaryDegraded,
          cleanup_requested: cleanupRequested,
          operation_id: crypto.randomUUID(),
          scope,
        },
        csrfToken,
      );
      setItems((current) => merge(current, [response.drain]));
    } catch {
      setError(
        "MeshSpan could not start that safe removal. Check its current state and retry.",
      );
      throw new Error("storage-drain admission failed");
    } finally {
      setPhase("idle");
    }
  };

  return { begin, error, items, load, loadMore, nextPageUrl, phase };
}

function merge(
  first: readonly StorageDrainSummary[],
  second: readonly StorageDrainSummary[],
): readonly StorageDrainSummary[] {
  const byId = new Map(first.map((drain) => [drain.drain_id, drain]));
  for (const drain of second) byId.set(drain.drain_id, drain);
  return [...byId.values()].toSorted(
    (left, right) =>
      right.requested_at_epoch_micros - left.requested_at_epoch_micros ||
      right.drain_id.localeCompare(left.drain_id),
  );
}
