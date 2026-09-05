// SPDX-License-Identifier: GPL-2.0-only
// @vitest-environment jsdom

import { render } from "@solidjs/web";
import { flush } from "solid-js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { DiagnosticsDownload } from "../src/features/operation-administration/DiagnosticsDownload";
import type { DiagnosticsClient } from "../src/features/operation-administration/diagnostics-download";
import type { DiagnosticsBundleResponse } from "../src/generated";

const ID = "11111111-1111-4111-8111-111111111111";
const BUNDLE: DiagnosticsBundleResponse = {
  metadata: {
    mesh_id: ID,
    partition_id: ID,
    node_id: ID,
    daemon_version: "0.1.0",
    collected_at_epoch_micros: 100,
    revision_before: "1",
    revision_after: "1",
    consensus: null,
    nodes: { items: [], truncated: false },
    targets: { items: [], truncated: false },
    recent_operations: { items: [], truncated: false },
  },
  runtime: null,
};
const created = vi.fn<(blob: Blob) => string>(() => "blob:meshspan-test");
const revoked = vi.fn<(url: string) => void>();
const clicked = vi.fn<(anchor: HTMLAnchorElement) => void>();
const disposals = new Set<() => void>();

class DownloadURL extends URL {
  static override readonly createObjectURL = created;
  static override readonly revokeObjectURL = revoked;
}

beforeEach(() => {
  vi.stubGlobal("URL", DownloadURL);
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (
    this: HTMLAnchorElement,
  ) {
    clicked(this);
  });
});

afterEach(() => {
  for (const dispose of disposals) dispose();
  disposals.clear();
  document.body.replaceChildren();
  vi.restoreAllMocks();
  vi.unstubAllGlobals();
  vi.clearAllMocks();
});

function mount(client: DiagnosticsClient): () => void {
  const root = document.createElement("div");
  document.body.append(root);
  const dispose = render(() => <DiagnosticsDownload client={client} />, root);
  disposals.add(dispose);
  return dispose;
}

function click(label: string): void {
  const button = [...document.querySelectorAll("button")].find(
    (candidate) => candidate.textContent.trim() === label,
  );
  if (!button) throw new TypeError(`Missing button: ${label}`);
  button.click();
  flush();
}

async function settle(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
  flush();
}

async function blobText(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = (): void => {
      if (typeof reader.result === "string") resolve(reader.result);
      else reject(new TypeError("Expected JSON text"));
    };
    reader.onerror = (): void => {
      reject(reader.error ?? new Error("Blob read failed"));
    };
    reader.readAsText(blob);
  });
}

describe("diagnostic download control", () => {
  it("downloads validated JSON only after an explicit request and releases the object URL", async () => {
    const readDiagnosticsBundle = vi.fn<
      DiagnosticsClient["readDiagnosticsBundle"]
    >(async () => BUNDLE);
    mount({ readDiagnosticsBundle });
    expect(readDiagnosticsBundle).not.toHaveBeenCalled();
    expect(document.body.textContent).toContain("not a backup");
    click("Download diagnostics");
    expect(document.body.textContent).toContain("Collecting diagnostics");
    await settle();
    expect(readDiagnosticsBundle).toHaveBeenCalledOnce();
    expect(created).toHaveBeenCalledOnce();
    expect(created.mock.calls[0]?.[0].type).toBe("application/json");
    const saved = created.mock.calls[0]?.[0];
    if (!saved) throw new TypeError("Expected a diagnostic Blob");
    const downloaded: unknown = JSON.parse(await blobText(saved));
    expect(downloaded).toEqual(BUNDLE);
    const anchor = clicked.mock.calls[0]?.[0];
    expect(anchor?.download).toBe("meshspan-diagnostics.json");
    expect(anchor?.href).toBe("blob:meshspan-test");
    expect(revoked).toHaveBeenCalledWith("blob:meshspan-test");
    expect(
      document.querySelector("[aria-live='polite']")?.textContent,
    ).toContain("Download requested");
  });

  it("cancels collection and discards a late response even if the client ignores abort", async () => {
    const deferred = Promise.withResolvers<DiagnosticsBundleResponse>();
    const readDiagnosticsBundle = vi.fn<
      DiagnosticsClient["readDiagnosticsBundle"]
    >(async () => deferred.promise);
    mount({ readDiagnosticsBundle });
    click("Download diagnostics");
    click("Cancel collection");
    expect(readDiagnosticsBundle.mock.calls[0]?.[0]?.aborted).toBe(true);
    deferred.resolve(BUNDLE);
    await settle();
    expect(created).not.toHaveBeenCalled();
    expect(document.body.textContent).toContain("no download was started");
  });

  it("aborts on unmount and never downloads the disposed response", async () => {
    const deferred = Promise.withResolvers<DiagnosticsBundleResponse>();
    const readDiagnosticsBundle = vi.fn<
      DiagnosticsClient["readDiagnosticsBundle"]
    >(async () => deferred.promise);
    const dispose = mount({ readDiagnosticsBundle });
    click("Download diagnostics");
    dispose();
    disposals.delete(dispose);
    expect(readDiagnosticsBundle.mock.calls[0]?.[0]?.aborted).toBe(true);
    deferred.resolve(BUNDLE);
    await settle();
    expect(created).not.toHaveBeenCalled();
  });

  it("does not download structurally invalid output or display the raw error", async () => {
    mount({
      readDiagnosticsBundle: async () => ({
        ...BUNDLE,
        metadata: { ...BUNDLE.metadata, daemon_version: "secret/path" },
      }),
    });
    click("Download diagnostics");
    await settle();
    expect(created).not.toHaveBeenCalled();
    expect(document.body.textContent).toContain(
      "Check your administration access",
    );
    expect(document.body.textContent).not.toContain("secret/path");
  });
});
