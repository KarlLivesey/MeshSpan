// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, type Accessor } from "solid-js";

import type {
  ListOperationsResponse,
  MeshSpanFetchClient,
  OperationStatusResponse,
} from "../../generated";

export type OperationAdministrationClient = Pick<
  MeshSpanFetchClient,
  "listNextOperations" | "listOperations"
>;

type LoadPhase = "idle" | "loading" | "loading_more";

export type OperationDirectory = Readonly<{
  error: Accessor<string | undefined>;
  items: Accessor<readonly OperationStatusResponse[]>;
  loadInitial: () => Promise<void>;
  loadNext: () => Promise<void>;
  nextPageUrl: Accessor<string | null>;
  phase: Accessor<LoadPhase>;
}>;

export function createOperationDirectory(
  client: Accessor<OperationAdministrationClient>,
): OperationDirectory {
  const [items, setItems] = createSignal<readonly OperationStatusResponse[]>(
    [],
    { equals: false, ownedWrite: true },
  );
  const [nextPageUrl, setNextPageUrl] = createSignal<string | null>(null, {
    ownedWrite: true,
  });
  const [phase, setPhase] = createSignal<LoadPhase>("idle", {
    ownedWrite: true,
  });
  const [error, setError] = createSignal<string | undefined>(undefined, {
    ownedWrite: true,
  });

  const apply = (page: ListOperationsResponse, append: boolean): void => {
    setItems((current) =>
      mergeOperations(append ? current : [], page.operations),
    );
    setNextPageUrl(page.next_page_url);
  };

  const loadInitial = async (): Promise<void> => {
    setPhase("loading");
    setError();
    try {
      apply(await client().listOperations(), false);
    } catch {
      setError("MeshSpan could not read the operation journal.");
    } finally {
      setPhase("idle");
    }
  };

  const loadNext = async (): Promise<void> => {
    const next = nextPageUrl();
    if (next === null || phase() !== "idle") return;
    setPhase("loading_more");
    setError();
    try {
      apply(await client().listNextOperations(next), true);
    } catch {
      setError("MeshSpan could not read the next operation page.");
    } finally {
      setPhase("idle");
    }
  };

  return { error, items, loadInitial, loadNext, nextPageUrl, phase };
}

function mergeOperations(
  first: readonly OperationStatusResponse[],
  second: readonly OperationStatusResponse[],
): readonly OperationStatusResponse[] {
  const byId = new Map(
    first.map((operation) => [operation.operation_id, operation]),
  );
  for (const operation of second) byId.set(operation.operation_id, operation);
  return [...byId.values()].toSorted(
    (left, right) => right.revision - left.revision,
  );
}
