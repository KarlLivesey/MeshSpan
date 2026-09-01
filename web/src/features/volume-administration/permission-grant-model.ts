// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, type Accessor } from "solid-js";

import type { MeshSpanFetchClient } from "../../generated/fetch.gen";
import type {
  CreateVolumePermissionGrantResponse,
  ListVolumePermissionGrantsResponse,
  RevokePermissionGrantResponse,
} from "../../generated/types.gen";

export type PermissionGrantClient = Pick<
  MeshSpanFetchClient,
  | "createVolumePermissionGrant"
  | "listNextVolumePermissionGrants"
  | "listVolumePermissionGrants"
  | "revokePermissionGrant"
>;

export type VolumePermissionGrant =
  ListVolumePermissionGrantsResponse["grants"][number];

export type PermissionGrantDirectory = Readonly<{
  error: Accessor<string | undefined>;
  items: Accessor<readonly VolumePermissionGrant[]>;
  load: (volumeId: string) => Promise<void>;
  loadNext: () => Promise<void>;
  nextPageUrl: Accessor<string | null>;
  phase: Accessor<"idle" | "loading" | "loading_more">;
  record: (response: CreateVolumePermissionGrantResponse) => void;
  remove: (response: RevokePermissionGrantResponse) => void;
}>;

export function createPermissionGrantDirectory(
  client: Accessor<PermissionGrantClient>,
): PermissionGrantDirectory {
  let selectedVolumeId: string | undefined;
  const collection = createGrantCollection(() => selectedVolumeId);
  const [phase, setPhase] = createSignal<"idle" | "loading" | "loading_more">(
    "idle",
    { ownedWrite: true },
  );
  const [error, setError] = createSignal<string>();
  let loadGeneration = 0;

  const load = async (volumeId: string): Promise<void> => {
    selectedVolumeId = volumeId;
    const generation = ++loadGeneration;
    setPhase("loading");
    setError(undefined);
    try {
      const page = await client().listVolumePermissionGrants({ volumeId });
      if (generation !== loadGeneration || selectedVolumeId !== volumeId) {
        return;
      }
      collection.applyPage(page, false, volumeId);
    } catch {
      if (generation === loadGeneration) {
        collection.clear();
        setError("MeshSpan could not load the current permission grants.");
      }
    } finally {
      if (generation === loadGeneration) {
        setPhase("idle");
      }
    }
  };

  const loadNext = async (): Promise<void> => {
    const next = collection.nextPageUrl();
    const volumeId = selectedVolumeId;
    if (next === null || volumeId === undefined || phase() !== "idle") {
      return;
    }
    setPhase("loading_more");
    setError(undefined);
    try {
      collection.applyPage(
        await client().listNextVolumePermissionGrants(next),
        true,
        volumeId,
      );
    } catch {
      setError("MeshSpan could not load more permission grants.");
    } finally {
      setPhase("idle");
    }
  };

  return {
    error,
    items: collection.items,
    load,
    loadNext,
    nextPageUrl: collection.nextPageUrl,
    phase,
    record: collection.record,
    remove: collection.remove,
  };
}

function createGrantCollection(selectedVolumeId: Accessor<string | undefined>) {
  const [items, setItems] = createSignal<readonly VolumePermissionGrant[]>([], {
    ownedWrite: true,
  });
  const [nextPageUrl, setNextPageUrl] = createSignal<string | null>(null, {
    ownedWrite: true,
  });
  const applyPage = (
    page: ListVolumePermissionGrantsResponse,
    append: boolean,
    volumeId: string,
  ): void => {
    if (page.volume_id !== volumeId) {
      throw new TypeError("permission-grant page returned the wrong volume");
    }
    setItems((current) => mergeGrants(append ? current : [], page.grants));
    setNextPageUrl(page.next_page_url);
  };
  return {
    applyPage,
    clear: (): void => {
      setItems([]);
      setNextPageUrl(null);
    },
    items,
    nextPageUrl,
    record: (response: CreateVolumePermissionGrantResponse): void => {
      if (response.grant.volume_id !== selectedVolumeId()) {
        throw new TypeError(
          "created permission grant belongs to another volume",
        );
      }
      setItems((current) => mergeGrants([response.grant], current));
    },
    remove: (response: RevokePermissionGrantResponse): void => {
      setItems((current) =>
        current.filter((grant) => grant.grant_id !== response.grant_id),
      );
    },
  };
}

function mergeGrants(
  first: readonly VolumePermissionGrant[],
  second: readonly VolumePermissionGrant[],
): readonly VolumePermissionGrant[] {
  const seen = new Set<string>();
  return [...first, ...second].filter((grant) => {
    if (seen.has(grant.grant_id)) {
      return false;
    }
    seen.add(grant.grant_id);
    return true;
  });
}
