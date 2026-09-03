// SPDX-License-Identifier: GPL-2.0-only

import { describe, expect, it } from "vitest";

import { createMeshSpanFetchClient } from "../src/generated/fetch.gen";

const RESPONSE_HEADERS = {
  "Content-Type": "application/json",
  "MeshSpan-API-Schema": `sha256:${"a".repeat(64)}`,
  "MeshSpan-API-Version": "latest",
};

describe("generated certificate-administration client", () => {
  it("validates provisioning and follows only its manual-DNS continuation", async () => {
    const requests: Readonly<{ body: string | null; url: string }>[] = [];
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async (input, init) => {
        requests.push({
          body: typeof init?.body === "string" ? init.body : null,
          url: requestUrl(input),
        });
        return Promise.resolve(jsonResponse(responseBody(requests.length)));
      },
    });

    const first = await client.listManualDnsTasks({ limit: 1 });
    await client.listNextManualDnsTasks(first.next_page_url ?? "missing");
    await client.provisionCertificate({
      certificate_names: ["files.example.test"],
      challenge: { kind: "http01" },
      directory_url: "https://acme.example.test/directory",
      operation_id: operationId(),
    });

    expect(requests.map(({ url }) => url)).toEqual([
      "https://node.example/api/latest/admin/certificate-tasks/manual-dns?limit=1",
      `https://node.example${first.next_page_url ?? ""}`,
      "https://node.example/api/latest/admin/certificates/acme",
    ]);
    expect(JSON.parse(requests[2]?.body ?? "null")).toEqual({
      certificate_names: ["files.example.test"],
      challenge: { kind: "http01" },
      directory_url: "https://acme.example.test/directory",
      operation_id: operationId(),
    });
  });

  it("rejects hostile continuations and unknown task fields", async () => {
    let calls = 0;
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async () => {
        calls += 1;
        return Promise.resolve(
          jsonResponse({
            next_page_url: null,
            tasks: [{ ...manualDnsTask(), sibling_file: "secret" }],
          }),
        );
      },
    });

    await expect(
      client.listNextManualDnsTasks("https://attacker.example/steal"),
    ).rejects.toThrow();
    expect(calls).toBe(0);
    await expect(client.listManualDnsTasks()).rejects.toThrow();
  });
});

function manualDnsTask() {
  return {
    action: "publish",
    created_at_epoch_micros: 1_700_000_000_000_000,
    expires_at_epoch_micros: 1_700_000_600_000_000,
    order_fence: "1",
    order_id: "00000000-0000-4000-8000-000000000002",
    record_name: "_acme-challenge.files.example.test",
    record_value: "challenge_value",
    revision: 3,
    task_digest: "b".repeat(64),
    transitioned_at_epoch_micros: 1_700_000_010_000_000,
  };
}

function operationId(): string {
  return "00000000-0000-4000-8000-000000000003";
}

function responseBody(call: number): unknown {
  if (call === 1) {
    return {
      next_page_url:
        "/api/latest/admin/certificate-tasks/manual-dns?cursor=v1.next&limit=1",
      tasks: [manualDnsTask()],
    };
  }
  return call === 2
    ? { next_page_url: null, tasks: [] }
    : {
        certificate_names: ["files.example.test"],
        configuration_id: "00000000-0000-4000-8000-000000000004",
        operation_id: operationId(),
        order_id: "00000000-0000-4000-8000-000000000002",
        revision: 3,
      };
}

function requestUrl(input: RequestInfo | URL): string {
  if (input instanceof URL) return input.href;
  return input instanceof Request ? input.url : input;
}

function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), { headers: RESPONSE_HEADERS });
}
