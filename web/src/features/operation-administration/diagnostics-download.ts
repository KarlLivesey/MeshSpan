// SPDX-License-Identifier: GPL-2.0-only

import { createSignal, onCleanup, type Accessor } from "solid-js";
import type { MeshSpanFetchClient } from "../../generated";
import { zDiagnosticsBundleResponse } from "../../generated/zod.gen";

export type DiagnosticsClient = Pick<
  MeshSpanFetchClient,
  "readDiagnosticsBundle"
>;
type DiagnosticsDownload = Readonly<{
  pending: Accessor<boolean>;
  message: Accessor<string | undefined>;
  error: Accessor<string | undefined>;
  run: () => Promise<void>;
  cancel: () => void;
}>;

/** Explicit bounded download; stale or cancelled responses never create browser downloads. */
export function createDiagnosticsDownload(
  client: Accessor<DiagnosticsClient>,
): DiagnosticsDownload {
  const [pending, setPending] = createSignal(false, { ownedWrite: true });
  const [message, setMessage] = createSignal<string | undefined>(undefined, {
    ownedWrite: true,
  });
  const [error, setError] = createSignal<string | undefined>(undefined, {
    ownedWrite: true,
  });
  let active: AbortController | undefined;
  let disposed = false;
  const isMounted = (): boolean => !disposed;
  const ownsResponse = (
    controller: AbortController,
    selected: DiagnosticsClient,
  ): boolean =>
    isMounted() &&
    active === controller &&
    !controller.signal.aborted &&
    selected === client();
  onCleanup(() => {
    disposed = true;
    active?.abort();
  });
  const run = async (): Promise<void> => {
    if (active || !isMounted()) return;
    const controller = new AbortController();
    active = controller;
    const current = client();
    setPending(true);
    setError();
    setMessage();
    try {
      const bundle = zDiagnosticsBundleResponse.parse(
        await current.readDiagnosticsBundle(controller.signal),
      );
      if (ownsResponse(controller, current)) {
        saveDownload(
          new Blob([JSON.stringify(bundle, null, 2)], {
            type: "application/json",
          }),
        );
        setMessage("Download requested. Review the file before sharing it.");
      }
    } catch {
      if (ownsResponse(controller, current)) {
        setError(
          "Diagnostics could not be collected. Check your administration access and connection, then retry.",
        );
      }
    } finally {
      if (active === controller) {
        active = undefined;
        if (isMounted()) setPending(false);
      }
    }
  };
  const cancel = (): void => {
    active?.abort();
    active = undefined;
    setPending(false);
    setError();
    setMessage("Collection cancelled; no download was started.");
  };
  return { pending, message, error, run, cancel };
}

function saveDownload(blob: Blob): void {
  const url = URL.createObjectURL(blob);
  try {
    const anchor = document.createElement("a");
    anchor.download = "meshspan-diagnostics.json";
    anchor.href = url;
    anchor.click();
  } finally {
    URL.revokeObjectURL(url);
  }
}
