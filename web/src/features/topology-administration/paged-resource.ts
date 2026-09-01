// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, type Accessor } from "solid-js";

type ResourcePage<T> = Readonly<{
  items: readonly T[];
  nextPageUrl: string | null;
}>;

export type PagedResource<T> = Readonly<{
  items: Accessor<readonly T[]>;
  loadInitial: () => Promise<void>;
  loadNext: () => Promise<void>;
  nextPageUrl: Accessor<string | null>;
  record: (value: T) => void;
  replace: (items: readonly T[]) => void;
}>;

export function createPagedResource<T>(
  loadInitialPage: () => Promise<ResourcePage<T>>,
  loadNextPage: (url: string) => Promise<ResourcePage<T>>,
  identity: (value: T) => string,
): PagedResource<T> {
  const [items, setItems] = createSignal<readonly T[]>([], {
    equals: false,
    ownedWrite: true,
  });
  const [nextPageUrl, setNextPageUrl] = createSignal<string | null>(null, {
    ownedWrite: true,
  });
  const apply = (page: ResourcePage<T>, append: boolean): void => {
    setItems((current) => merge(append ? current : [], page.items, identity));
    setNextPageUrl(page.nextPageUrl);
  };
  const loadInitial = async (): Promise<void> => {
    apply(await loadInitialPage(), false);
  };
  const loadNext = async (): Promise<void> => {
    const url = nextPageUrl();
    if (url !== null) apply(await loadNextPage(url), true);
  };
  return {
    items,
    loadInitial,
    loadNext,
    nextPageUrl,
    record: (value) => setItems((current) => merge(current, [value], identity)),
    replace: setItems,
  };
}

function merge<T>(
  first: readonly T[],
  second: readonly T[],
  identity: (value: T) => string,
): readonly T[] {
  const records = new Map(first.map((record) => [identity(record), record]));
  for (const record of second) records.set(identity(record), record);
  return [...records.values()];
}
