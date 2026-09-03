// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, type Accessor } from "solid-js";

import type {
  CertificateStatusResponse,
  ListManualDnsTasksResponse,
  MeshSpanFetchClient,
} from "../../generated";

export type CertificateAdministrationClient = Pick<
  MeshSpanFetchClient,
  | "getCertificateStatus"
  | "listManualDnsTasks"
  | "listNextManualDnsTasks"
  | "provisionCertificate"
>;

export type CertificateStatusResource = Readonly<{
  error: Accessor<string | undefined>;
  load: () => Promise<void>;
  loading: Accessor<boolean>;
  value: Accessor<CertificateStatusResponse | undefined>;
}>;

export function createCertificateStatusResource(
  client: Accessor<CertificateAdministrationClient>,
): CertificateStatusResource {
  const [value, setValue] = createSignal<CertificateStatusResponse | undefined>(
    undefined,
    { ownedWrite: true },
  );
  const [loading, setLoading] = createSignal(true, { ownedWrite: true });
  const [error, setError] = createSignal<string | undefined>(undefined, {
    ownedWrite: true,
  });
  const load = async (): Promise<void> => {
    setLoading(true);
    setError();
    try {
      setValue(await client().getCertificateStatus());
    } catch {
      setError("MeshSpan could not read the current certificate status.");
    } finally {
      setLoading(false);
    }
  };
  return { error, load, loading, value };
}

export type ManualDnsTask = ListManualDnsTasksResponse["tasks"][number];

type LoadPhase = "idle" | "loading" | "loading_more";

export type ManualDnsTaskDirectory = Readonly<{
  error: Accessor<string | undefined>;
  items: Accessor<readonly ManualDnsTask[]>;
  loadInitial: () => Promise<void>;
  loadNext: () => Promise<void>;
  nextPageUrl: Accessor<string | null>;
  phase: Accessor<LoadPhase>;
}>;

export function createManualDnsTaskDirectory(
  client: Accessor<CertificateAdministrationClient>,
): ManualDnsTaskDirectory {
  const [items, setItems] = createSignal<readonly ManualDnsTask[]>([], {
    equals: false,
    ownedWrite: true,
  });
  const [nextPageUrl, setNextPageUrl] = createSignal<string | null>(null, {
    ownedWrite: true,
  });
  const [phase, setPhase] = createSignal<LoadPhase>("idle", {
    ownedWrite: true,
  });
  const [error, setError] = createSignal<string | undefined>(undefined, {
    ownedWrite: true,
  });

  const apply = (page: ListManualDnsTasksResponse, append: boolean): void => {
    setItems((current) => mergeTasks(append ? current : [], page.tasks));
    setNextPageUrl(page.next_page_url);
  };

  const loadInitial = async (): Promise<void> => {
    setPhase("loading");
    setError();
    try {
      apply(await client().listManualDnsTasks(), false);
    } catch {
      setError("MeshSpan could not read the current manual DNS work.");
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
      apply(await client().listNextManualDnsTasks(next), true);
    } catch {
      setError("MeshSpan could not read the next manual DNS work page.");
    } finally {
      setPhase("idle");
    }
  };

  return { error, items, loadInitial, loadNext, nextPageUrl, phase };
}

function mergeTasks(
  first: readonly ManualDnsTask[],
  second: readonly ManualDnsTask[],
): readonly ManualDnsTask[] {
  const byDigest = new Map(first.map((task) => [task.task_digest, task]));
  for (const task of second) byDigest.set(task.task_digest, task);
  return [...byDigest.values()].toSorted(compareTasks);
}

function compareTasks(left: ManualDnsTask, right: ManualDnsTask): number {
  return (
    left.expires_at_epoch_micros - right.expires_at_epoch_micros ||
    left.created_at_epoch_micros - right.created_at_epoch_micros ||
    left.task_digest.localeCompare(right.task_digest)
  );
}
