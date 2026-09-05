// SPDX-License-Identifier: GPL-2.0-only

import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex } from "@noble/hashes/utils.js";
import { describe, expect, it, vi } from "vitest";
import { createMeshSpanFetchClient } from "../src/generated/fetch.gen";
import {
  zBackupExportHeaders,
  zBackupExportPath,
} from "../src/generated/zod.gen";

const BACKUP = "11111111-1111-4111-8111-111111111111";
const BYTES = new Uint8Array([1, 2, 3]);

describe("browser backup download URLs", () => {
  it("uses the generated route without a request, credentials or copied query", () => {
    const fetcher = vi.fn<typeof fetch>();
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/?unrelated=private#fragment",
      fetch: fetcher,
    });
    expect(client.metadataBackupDownloadUrl(BACKUP)).toBe(
      `https://node.example/api/latest/admin/backups/${BACKUP}/export`,
    );
    expect(() => client.metadataBackupDownloadUrl("../wrong")).toThrow();
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("requires API-key clients to use the authenticated stream", () => {
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      apiKey: `meshspan-key-v1.${"3".repeat(32)}.${"4".repeat(64)}`,
    });
    expect(() => client.metadataBackupDownloadUrl(BACKUP)).toThrow(
      "API-key clients must use the authenticated backup stream",
    );
  });

  it("rejects non-HTTP links", () => {
    const client = createMeshSpanFetchClient({
      baseUrl: "ftp://node.example/api/latest/",
    });
    expect(() => client.metadataBackupDownloadUrl(BACKUP)).toThrow(
      "HTTP or HTTPS endpoint",
    );
  });
});

function headers(): Record<string, string> {
  return {
    "content-length": "3",
    "content-type": "application/octet-stream",
    "MeshSpan-Backup-ID": BACKUP,
    "MeshSpan-Backup-Digest": `sha256:${bytesToHex(sha256(BYTES))}`,
    "MeshSpan-API-Schema": `sha256:${"a".repeat(64)}`,
    "MeshSpan-API-Version": "latest",
  };
}

describe("encrypted backup export", () => {
  it("streams and verifies exact bytes using the Rust-generated route", async () => {
    const sent: string[] = [];
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async (input) => {
        sent.push(input instanceof Request ? input.url : input.toString());
        return new Response(BYTES, { headers: headers() });
      },
    });
    const transfer = await client.exportMetadataBackup(BACKUP);
    expect(transfer.headers["Content-Length"]).toBe("3");
    expect(
      new Uint8Array(await new Response(transfer.body).arrayBuffer()),
    ).toEqual(BYTES);
    await expect(client.exportMetadataBackup("../../other")).rejects.toThrow();
    expect(sent).toEqual([
      `https://node.example/api/latest/admin/backups/${BACKUP}/export`,
    ]);
  });

  it.each([
    ["short", new Uint8Array([1, 2])],
    ["overlong", new Uint8Array([1, 2, 3, 4])],
    ["corrupt", new Uint8Array([1, 2, 4])],
  ])("does not complete a %s stream", async (_, source) => {
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async () => new Response(source, { headers: headers() }),
    });
    const transfer = await client.exportMetadataBackup(BACKUP);
    await expect(new Response(transfer.body).arrayBuffer()).rejects.toThrow();
  });
});

describe("export authority and cancellation", () => {
  it("cancels a substituted generation before passing bytes to its caller", async () => {
    let cancelled = false;
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async () =>
        new Response(
          new ReadableStream<Uint8Array>({
            cancel(): void {
              cancelled = true;
            },
          }),
          {
            headers: {
              ...headers(),
              "MeshSpan-Backup-ID": "22222222-2222-4222-8222-222222222222",
            },
          },
        ),
    });
    await expect(client.exportMetadataBackup(BACKUP)).rejects.toThrow(
      "another generation",
    );
    expect(cancelled).toBe(true);
  });

  it("propagates cancellation to the source", async () => {
    let cancelled = false;
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async () =>
        new Response(
          new ReadableStream<Uint8Array>({
            cancel(): void {
              cancelled = true;
            },
          }),
          { headers: headers() },
        ),
    });
    const transfer = await client.exportMetadataBackup(BACKUP);
    await transfer.body.cancel();
    expect(cancelled).toBe(true);
  });
});

describe("generated export evidence", () => {
  it("rejects missing, null, numeric, unknown and malformed header fields", () => {
    const valid = {
      "Content-Length": "9007199254740993",
      "MeshSpan-Backup-ID": BACKUP,
      "MeshSpan-Backup-Digest": `sha256:${"a".repeat(64)}`,
    };
    expect(zBackupExportHeaders.parse(valid)["Content-Length"]).toBe(
      "9007199254740993",
    );
    for (const change of [
      { "Content-Length": 3 },
      { "Content-Length": null },
      { "Content-Length": "03" },
      { "MeshSpan-Backup-Digest": "bad" },
      { unknown: true },
    ]) {
      expect(
        zBackupExportHeaders.safeParse({ ...valid, ...change }).success,
      ).toBe(false);
    }
    expect(zBackupExportHeaders.safeParse({}).success).toBe(false);
    expect(
      zBackupExportPath.safeParse({ backup_id: BACKUP, extra: true }).success,
    ).toBe(false);
  });
});
