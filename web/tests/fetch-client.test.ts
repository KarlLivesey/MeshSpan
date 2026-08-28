// SPDX-License-Identifier: GPL-2.0-only

import { describe, expect, it } from "vitest";

import type { MeshSpanApiError } from "../src/generated/fetch.gen";
import { createMeshSpanFetchClient } from "../src/generated/fetch.gen";

const RESPONSE_HEADERS = {
  "Content-Type": "application/json",
  "MeshSpan-API-Schema": `sha256:${"a".repeat(64)}`,
  "MeshSpan-API-Version": "latest",
};

describe("generated native Fetch client requests", () => {
  it("uses the generated route and validates the response", async () => {
    const requests: Readonly<{
      input: RequestInfo | URL;
      init?: RequestInit;
    }>[] = [];
    const fetchStub: typeof globalThis.fetch = async (input, init) => {
      requests.push({ input, ...(init === undefined ? {} : { init }) });
      return Promise.resolve(
        jsonResponse({
          api_version: "latest",
          schema_digest: `sha256:${"b".repeat(64)}`,
          status: "ready",
        }),
      );
    };
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: fetchStub,
    });

    await expect(client.getHealth()).resolves.toEqual({
      api_version: "latest",
      schema_digest: `sha256:${"b".repeat(64)}`,
      status: "ready",
    });
    expect(requests).toHaveLength(1);
    expect(readRequestUrl(requests[0]?.input)).toBe(
      "https://node.example/api/latest/health",
    );
    expect(requests[0]?.init?.method).toBe("GET");
  });

  it("validates a request before calling Fetch", async () => {
    let callCount = 0;
    const fetchStub: typeof globalThis.fetch = async () => {
      callCount += 1;
      return Promise.resolve(jsonResponse({}));
    };
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: fetchStub,
    });

    await expect(
      client.createSession({
        login_name: "ada@example.test",
        operation_id: "not-an-operation-id",
        password: "not-a-real-password",
        remember: false,
      }),
    ).rejects.toThrow();
    expect(callCount).toBe(0);
  });
});

describe("generated native Fetch client responses", () => {
  it("rejects an invalid successful response", async () => {
    const fetchStub: typeof globalThis.fetch = async () =>
      Promise.resolve(
        jsonResponse({
          api_version: "latest",
          schema_digest: "wrong",
          status: "ready",
        }),
      );
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: fetchStub,
    });

    await expect(client.getHealth()).rejects.toThrow();
  });

  it("returns a typed bounded API error", async () => {
    const fetchStub: typeof globalThis.fetch = async () =>
      Promise.resolve(
        jsonResponse(
          {
            code: "unauthenticated",
            issues: [],
            message: "Authentication failed",
            operation_id: null,
            request_id: "018f1d20-7b4c-7a1e-9d22-39a1558b4c61",
          },
          401,
        ),
      );
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: fetchStub,
    });

    const request = client.createSession({
      login_name: "ada@example.test",
      operation_id: "018f1d20-7b4c-7a1e-9d22-39a1558b4c61",
      password: "not-a-real-password",
      remember: false,
    });
    await expect(request).rejects.toMatchObject({
      apiError: {
        code: "unauthenticated",
        issues: [],
        message: "Authentication failed",
        operation_id: null,
        request_id: "018f1d20-7b4c-7a1e-9d22-39a1558b4c61",
      },
      statusCode: 401,
    } satisfies Partial<MeshSpanApiError>);
  });

  it("rejects a body that exceeds the bounded JSON response size", async () => {
    const fetchStub: typeof globalThis.fetch = async () =>
      Promise.resolve(
        new Response("{}", {
          headers: {
            ...RESPONSE_HEADERS,
            "Content-Length": "65537",
          },
        }),
      );
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: fetchStub,
    });

    await expect(client.getHealth()).rejects.toThrow(RangeError);
  });
});

function readRequestUrl(
  input: RequestInfo | URL | undefined,
): string | undefined {
  if (input instanceof URL) {
    return input.href;
  }
  if (input instanceof Request) {
    return input.url;
  }
  return input;
}

function jsonResponse(value: unknown, statusCode = 200): Response {
  return new Response(JSON.stringify(value), {
    headers: RESPONSE_HEADERS,
    status: statusCode,
  });
}
