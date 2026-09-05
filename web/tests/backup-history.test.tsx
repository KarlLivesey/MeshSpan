// SPDX-License-Identifier: GPL-2.0-only

import { render } from "@solidjs/web";
import { flush } from "solid-js";
import { afterEach, describe, expect, it, vi } from "vitest";
import { BackupHistory } from "../src/features/backup-administration/BackupHistory";
import type { BackupHistoryClient } from "../src/features/backup-administration/history";
import type { ListBackupRunsResponse } from "../src/generated";
import { createMeshSpanFetchClient } from "../src/generated/fetch.gen";

const disposals = new Set<() => void>();
const NEXT = "/api/latest/admin/backups/runs?limit=25&cursor=v1.bkr.example";
afterEach(() => {
  for (const dispose of disposals) dispose();
  disposals.clear();
  document.body.replaceChildren();
});

describe("backup history panel", () => {
  it("distinguishes all recorded outcomes from current recovery safety", async () => {
    const states = [
      "queued",
      "claimed",
      "recorded",
      "protected",
      "incomplete",
    ] as const;
    const runs = states.map((state, index) => ({
      ...run(String(5 - index)),
      state,
      completed_at_epoch_micros:
        state === "protected" || state === "incomplete" ? 2_000_000 : null,
    }));
    mount({
      listBackupRuns: async () => ({ runs, next_page_url: null }),
      listNextBackupRuns: async () => page("1"),
    });
    await shows("Required protection met at completion");
    expect(document.body.textContent).toContain(
      "does not prove a backup is recoverable now",
    );
    for (const label of [
      "Queued",
      "Assigned to a worker",
      "Copy recorded; protection not yet confirmed",
      "Incomplete — required protection was not met",
    ]) {
      expect(document.body.textContent).toContain(label);
    }
    expect(document.body.textContent).toContain("1970-01-01T00:00:01Z");
    expect(document.querySelectorAll("li")).toHaveLength(5);
    expect(document.querySelectorAll("a")).toHaveLength(1);
  });

  it("follows one older page on demand, replaces rows and refreshes newest", async () => {
    const list = vi.fn(async () => ({ ...page("3"), next_page_url: NEXT }));
    const next = vi.fn(async () => page("2"));
    mount({ listBackupRuns: list, listNextBackupRuns: next });
    await shows("Attempt 3");
    expect(next).not.toHaveBeenCalled();
    button("Older attempts").click();
    await shows("Attempt 2");
    expect(next).toHaveBeenCalledExactlyOnceWith(NEXT);
    expect(document.body.textContent).not.toContain("Attempt 3");
    expect(document.querySelectorAll("li")).toHaveLength(1);
    button("Refresh history").click();
    await shows("Attempt 3");
    expect(list).toHaveBeenCalledTimes(2);
  });

  it("clears prior private rows after a failed page and can retry newest", async () => {
    mount({
      listBackupRuns: async () => ({ ...page("3"), next_page_url: NEXT }),
      listNextBackupRuns: async () => {
        throw new Error("secret internal failure");
      },
    });
    await shows("Attempt 3");
    button("Older attempts").click();
    await shows("Backup history could not be read");
    expect(document.body.textContent).not.toContain("Attempt 3");
    expect(document.body.textContent).not.toContain("secret internal failure");
    button("Refresh history").click();
    await shows("Attempt 3");
  });

  it("prevents duplicate requests while loading and explains an empty history", async () => {
    const pending = Promise.withResolvers<ListBackupRunsResponse>();
    const list = vi.fn(async () => pending.promise);
    mount({ listBackupRuns: list, listNextBackupRuns: async () => page("1") });
    flush();
    const refresh = button("Refresh history");
    refresh.click();
    refresh.click();
    expect(list).toHaveBeenCalledOnce();
    expect(refresh.disabled).toBe(true);
    pending.resolve({ runs: [], next_page_url: null });
    await shows("No backup attempts have been recorded yet");
    expect(refresh.disabled).toBe(false);
  });
});

describe("backup download controls", () => {
  it("links the exact protected generation without fetching or claiming success", async () => {
    const fetcher = vi.fn<typeof fetch>();
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: fetcher,
    });
    mount(
      {
        listBackupRuns: async () => ({
          runs: [{ ...run("1"), state: "protected" }],
          next_page_url: null,
        }),
        listNextBackupRuns: async () => page("1"),
      },
      client.metadataBackupDownloadUrl,
    );
    await shows("Download encrypted backup");
    const link = document.querySelector("a");
    expect(link?.href).toBe(
      "https://node.example/api/latest/admin/backups/01900000-0000-7000-8000-000000000001/export",
    );
    expect(link?.target).toBe("_blank");
    expect(link?.rel).toBe("noopener noreferrer");
    // Only a successful server response supplies attachment headers; an error
    // must not be forcibly saved as a backup by an HTML download attribute.
    expect(link?.hasAttribute("download")).toBe(false);
    expect(fetcher).not.toHaveBeenCalled();
    expect(document.body.textContent).toContain("not a restore check");
  });

  it("does not build a download from malformed generation evidence", async () => {
    mount({
      listBackupRuns: async () => ({
        runs: [{ ...run("1"), state: "protected", backup_id: "../wrong" }],
        next_page_url: null,
      }),
      listNextBackupRuns: async () => page("1"),
    });
    await shows("Download unavailable");
    expect(document.querySelector("a")).toBeNull();
    expect(document.body.textContent).not.toContain("ZodError");
  });

  it("removes download controls when current history access is rejected", async () => {
    const list = vi
      .fn<BackupHistoryClient["listBackupRuns"]>()
      .mockResolvedValueOnce({
        runs: [{ ...run("1"), state: "protected" }],
        next_page_url: null,
      })
      .mockRejectedValueOnce(new Error("access revoked"));
    mount({ listBackupRuns: list, listNextBackupRuns: async () => page("1") });
    await shows("Download encrypted backup");
    button("Refresh history").click();
    await shows("Backup history could not be read");
    expect(document.querySelector("a")).toBeNull();
  });
});

function page(sequence: string): ListBackupRunsResponse {
  return { runs: [run(sequence)], next_page_url: null };
}
function run(sequence: string): ListBackupRunsResponse["runs"][number] {
  return {
    backup_id: "01900000-0000-7000-8000-000000000001",
    run_sequence: sequence,
    schedule_sequence: "1",
    scheduled_for_epoch_micros: 1_000_000,
    completed_at_epoch_micros: null,
    state: "queued",
    minimum_verified_copies: 2,
    minimum_independent_copies: 1,
  };
}
function mount(
  client: Omit<BackupHistoryClient, "metadataBackupDownloadUrl">,
  downloadUrl = createMeshSpanFetchClient({
    baseUrl: "https://node.example/api/latest/",
  }).metadataBackupDownloadUrl,
): void {
  const root = document.createElement("div");
  document.body.append(root);
  const historyClient = { ...client, metadataBackupDownloadUrl: downloadUrl };
  disposals.add(render(() => <BackupHistory client={historyClient} />, root));
}
function button(label: string): HTMLButtonElement {
  const found = [...document.querySelectorAll("button")].find(
    (element) => element.textContent === label,
  );
  if (!found) throw new Error(`Missing button: ${label}`);
  return found;
}
async function shows(text: string): Promise<void> {
  await vi.waitFor(() => {
    flush();
    expect(document.body.textContent).toContain(text);
  });
}
