// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, type Accessor } from "solid-js";

import type { MeshSpanFetchClient } from "../../generated/fetch.gen";
import type {
  CreateVolumeResponse,
  ListVolumesResponse,
} from "../../generated/types.gen";

export type VolumeAdministrationClient = Pick<
  MeshSpanFetchClient,
  | "createVolume"
  | "createVolumePermissionGrant"
  | "listGroups"
  | "listNextPrincipals"
  | "listNextVolumes"
  | "listNextVolumePermissionGrants"
  | "listUsers"
  | "listVolumes"
  | "listVolumePermissionGrants"
  | "publishSmbExport"
  | "revokePermissionGrant"
  | "withdrawSmbExport"
>;

export type AdminVolume = Readonly<{
  createdAtEpochMicros: number;
  name: string;
  revision: number;
  rootObjectId: string;
  state: ListVolumesResponse["volumes"][number]["state"] | "committed";
  volumeId: string;
}>;

export type VolumeDirectory = Readonly<{
  error: Accessor<string | undefined>;
  items: Accessor<readonly AdminVolume[]>;
  loadInitial: () => Promise<void>;
  loadNext: () => Promise<void>;
  nextPageUrl: Accessor<string | null>;
  phase: Accessor<"idle" | "loading" | "loading_more">;
  recordCommitted: (response: CreateVolumeResponse) => void;
}>;

export function createVolumeDirectory(
  client: Accessor<VolumeAdministrationClient>,
): VolumeDirectory {
  const [items, setItems] = createSignal<readonly AdminVolume[]>([], {
    ownedWrite: true,
  });
  const [nextPageUrl, setNextPageUrl] = createSignal<string | null>(null, {
    ownedWrite: true,
  });
  const [phase, setPhase] = createSignal<"idle" | "loading" | "loading_more">(
    "idle",
    { ownedWrite: true },
  );
  const [error, setError] = createSignal<string | undefined>(undefined, {
    ownedWrite: true,
  });

  const applyPage = (page: ListVolumesResponse, append: boolean): void => {
    const volumes = page.volumes.map(publicVolume);
    setItems((current) => mergeVolumes(append ? current : [], volumes));
    setNextPageUrl(page.next_page_url);
  };

  const loadInitial = async (): Promise<void> => {
    setPhase("loading");
    setError(undefined);
    try {
      applyPage(await client().listVolumes(), false);
    } catch {
      setError("MeshSpan could not load the current volume list.");
    } finally {
      setPhase("idle");
    }
  };

  const loadNext = async (): Promise<void> => {
    const next = nextPageUrl();
    if (next === null || phase() !== "idle") {
      return;
    }
    setPhase("loading_more");
    setError(undefined);
    try {
      applyPage(await client().listNextVolumes(next), true);
    } catch {
      setError("MeshSpan could not load more volumes.");
    } finally {
      setPhase("idle");
    }
  };

  const recordCommitted = (response: CreateVolumeResponse): void => {
    setItems((current) =>
      mergeVolumes(
        [
          {
            createdAtEpochMicros: response.created_at_epoch_micros,
            name: response.name,
            revision: response.revision,
            rootObjectId: response.root_object_id,
            state: "committed",
            volumeId: response.volume_id,
          },
        ],
        current,
      ),
    );
  };

  return {
    error,
    items,
    loadInitial,
    loadNext,
    nextPageUrl,
    phase,
    recordCommitted,
  };
}

function publicVolume(
  volume: ListVolumesResponse["volumes"][number],
): AdminVolume {
  return {
    createdAtEpochMicros: volume.created_at_epoch_micros,
    name: volume.name,
    revision: volume.revision,
    rootObjectId: volume.root_object_id,
    state: volume.state,
    volumeId: volume.volume_id,
  };
}

function mergeVolumes(
  first: readonly AdminVolume[],
  second: readonly AdminVolume[],
): readonly AdminVolume[] {
  const seen = new Set<string>();
  return [...first, ...second].filter((volume) => {
    if (seen.has(volume.volumeId)) {
      return false;
    }
    seen.add(volume.volumeId);
    return true;
  });
}
