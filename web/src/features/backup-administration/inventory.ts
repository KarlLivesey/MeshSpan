// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, type Accessor } from "solid-js";
import type { BackupAdministrationClient, BackupView } from "./types";

type Inventory = Readonly<{
  view: Accessor<BackupView | undefined>;
  loading: Accessor<boolean>;
  error: Accessor<string | undefined>;
  load: (kind?: "destinations" | "targets") => Promise<void>;
}>;

/** Loads bounded pages on demand and clears private content after a failed read. */
export function createBackupInventory(
  client: Accessor<BackupAdministrationClient>,
): Inventory {
  const [view, setView] = createSignal<BackupView | undefined>(undefined, {
    ownedWrite: true,
  });
  const [loading, setLoading] = createSignal(false, { ownedWrite: true });
  const [error, setError] = createSignal<string | undefined>(undefined, {
    ownedWrite: true,
  });
  let inFlight = false;
  const load = async (kind?: "destinations" | "targets"): Promise<void> => {
    if (inFlight) return;
    inFlight = true;
    setLoading(true);
    setError();
    try {
      setView(await readView(client(), view(), kind));
    } catch {
      setView();
      setError(
        "Backup settings could not be read. Check your connection and access, then refresh.",
      );
    } finally {
      inFlight = false;
      setLoading(false);
    }
  };
  return { view, loading, error, load };
}

async function readView(
  client: BackupAdministrationClient,
  current: BackupView | undefined,
  kind: "destinations" | "targets" | undefined,
): Promise<BackupView> {
  if (kind === undefined || current === undefined) {
    const [schedule, destinations, targets] = await Promise.all([
      client.getBackupSchedule(),
      client.listBackupDestinations({ limit: 50 }),
      client.listTopologyTargets({ limit: 50 }),
    ]);
    return { schedule, destinations, targets };
  }
  if (kind === "destinations" && current.destinations.next_page_url !== null) {
    const page = await client.listNextBackupDestinations(
      current.destinations.next_page_url,
    );
    return {
      ...current,
      destinations: {
        ...page,
        destinations: merge(
          current.destinations.destinations,
          page.destinations,
          (item) => item.destination_id,
        ),
      },
    };
  }
  if (kind === "targets" && current.targets.next_page_url !== null) {
    const page = await client.listNextTopologyTargets(
      current.targets.next_page_url,
    );
    return {
      ...current,
      targets: {
        ...page,
        targets: merge(
          current.targets.targets,
          page.targets,
          (item) => item.target_id,
        ),
      },
    };
  }
  return current;
}

function merge<T>(
  first: readonly T[],
  second: readonly T[],
  identity: (item: T) => string,
): T[] {
  const values = new Map(first.map((item) => [identity(item), item]));
  for (const item of second) values.set(identity(item), item);
  return [...values.values()];
}
