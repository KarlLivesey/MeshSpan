// SPDX-License-Identifier: GPL-2.0-only

import { render } from "@solidjs/web";
import { flush } from "solid-js";
import { afterEach, describe, expect, it, vi } from "vitest";
import { BackupRestoreCheck } from "../src/features/backup-administration/BackupRestoreCheck";
import type { RestoreCheckClient } from "../src/features/backup-administration/restore-check";
import { createMeshSpanFetchClient } from "../src/generated/fetch.gen";
import type { BackupReadinessResponse } from "../src/generated/types.gen";

const BACKUP = "11111111-1111-4111-8111-111111111111";
const RESULT: BackupReadinessResponse = {
  backup_id: BACKUP,
  checked_by_node_id: "22222222-2222-4222-8222-222222222222",
  partition_id: "33333333-3333-4333-8333-333333333333",
  source_log_index: "9007199254740993",
  source_log_term: "1",
  state_revision: "20",
  checked_at_epoch_micros: 1_000_000,
  verification: "gateway_key",
};
const disposals = new Set<() => void>();
afterEach(() => {
  for (const dispose of disposals) dispose();
  disposals.clear();
  document.body.replaceChildren();
});

describe("restore check panel", () => {
  it("waits for an explicit action and only displays confirmed scoped evidence", async () => {
    const pending = Promise.withResolvers<BackupReadinessResponse>();
    const check = vi.fn(async () => pending.promise);
    mount({ checkMetadataBackupReadiness: check });
    flush();
    expect(check).not.toHaveBeenCalled();
    button("Check restore").click();
    flush();
    button("Check restore").click();
    expect(check).toHaveBeenCalledOnce();
    expect(document.body.textContent).toContain("Reading, decrypting");
    expect(document.body.textContent).not.toContain(
      "Isolated restore verified",
    );
    pending.resolve(RESULT);
    await shows("Isolated restore verified at 1970-01-01T00:00:01Z");
    expect(document.body.textContent).toContain("9007199254740993");
    expect(document.body.textContent).toContain(
      "offline recovery bundle was not tested",
    );
  });

  it("cancels and ignores a response delivered after cancellation", async () => {
    const pending = Promise.withResolvers<BackupReadinessResponse>();
    const check = vi.fn<RestoreCheckClient["checkMetadataBackupReadiness"]>(
      async () => pending.promise,
    );
    mount({ checkMetadataBackupReadiness: check });
    button("Check restore").click();
    flush();
    button("Cancel check").click();
    flush();
    expect(check.mock.calls[0]?.[1]?.aborted).toBe(true);
    pending.resolve(RESULT);
    await shows("no recovery result was confirmed");
    expect(document.body.textContent).not.toContain(
      "Isolated restore verified",
    );
  });

  it("does not retain success across a failed recheck or show raw failures", async () => {
    const check = vi
      .fn<RestoreCheckClient["checkMetadataBackupReadiness"]>()
      .mockResolvedValueOnce(RESULT)
      .mockRejectedValueOnce(new Error("secret internal path"));
    mount({ checkMetadataBackupReadiness: check });
    button("Check restore").click();
    await shows("Isolated restore verified");
    button("Check restore").click();
    await shows("Restore check could not complete");
    expect(document.body.textContent).not.toContain(
      "Isolated restore verified",
    );
    expect(document.body.textContent).not.toContain("secret internal path");
  });

  it("rejects evidence for another generation", async () => {
    mount({
      checkMetadataBackupReadiness: async () => ({
        ...RESULT,
        backup_id: RESULT.partition_id,
      }),
    });
    button("Check restore").click();
    await shows("Restore check could not complete");
    expect(document.body.textContent).not.toContain(
      "Isolated restore verified",
    );
  });
});

describe("restore check generated client", () => {
  it("uses the Rust route, existing authentication, cancellation and lossless response", async () => {
    const sent: string[] = [];
    const cancellation = new AbortController();
    const apiKey = `meshspan-key-v1.${"3".repeat(32)}.${"4".repeat(64)}`;
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      apiKey,
      fetch: async (input, init) => {
        sent.push(input instanceof Request ? input.url : input.toString());
        expect(new Headers(init?.headers).get("authorization")).toBe(
          `Bearer ${apiKey}`,
        );
        expect(init?.signal).toBe(cancellation.signal);
        return response(RESULT);
      },
    });
    expect(
      await client.checkMetadataBackupReadiness(BACKUP, cancellation.signal),
    ).toEqual(RESULT);
    await expect(
      client.checkMetadataBackupReadiness("../wrong"),
    ).rejects.toThrow();
    expect(sent).toEqual([
      `https://node.example/api/latest/admin/backups/${BACKUP}/restore-readiness`,
    ]);
  });

  it.each([
    { ...RESULT, backup_id: RESULT.partition_id },
    { ...RESULT, verification: "offline_recovery" },
    { ...RESULT, state_revision: 20 },
    { ...RESULT, checked_at_epoch_micros: null },
    { ...RESULT, unknown: true },
  ])("rejects invalid or substituted proof", async (value) => {
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async () => response(value),
    });
    await expect(client.checkMetadataBackupReadiness(BACKUP)).rejects.toThrow();
  });
});

function response(value: unknown): Response {
  return Response.json(value, {
    headers: {
      "MeshSpan-API-Version": "latest",
      "MeshSpan-API-Schema": `sha256:${"a".repeat(64)}`,
    },
  });
}
function mount(client: RestoreCheckClient): void {
  const root = document.createElement("div");
  document.body.append(root);
  disposals.add(
    render(
      () => <BackupRestoreCheck client={client} backupId={BACKUP} />,
      root,
    ),
  );
  flush();
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
