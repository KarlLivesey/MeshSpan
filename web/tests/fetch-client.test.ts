// SPDX-License-Identifier: GPL-2.0-only

import { describe, expect, it } from "vitest";

import type { MeshSpanApiError } from "../src/generated/fetch.gen";
import { createMeshSpanFetchClient } from "../src/generated/fetch.gen";

const RESPONSE_HEADERS = {
  "Content-Type": "application/json",
  "MeshSpan-API-Schema": `sha256:${"a".repeat(64)}`,
  "MeshSpan-API-Version": "latest",
};
const SETUP_OPERATION_ID = "00000000-0000-4000-8000-000000000001";
const SETUP_CLAIM = `meshspan-claim-v1.${"1".repeat(32)}.${"2".repeat(64)}`;
const SESSION_API_KEY = `meshspan-key-v1.${"3".repeat(32)}.${"4".repeat(64)}`;
const SESSION_CSRF = `meshspan-csrf-v1.${"5".repeat(32)}.${"6".repeat(64)}`;

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
        authentication: {
          method: "api_key",
          secret: "meshspan_api_7hR9vQ2mK4xP8nT6wY3cF5aJ",
        },
        operation_id: "not-an-operation-id",
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
      authentication: {
        method: "api_key",
        secret: "meshspan_api_7hR9vQ2mK4xP8nT6wY3cF5aJ",
      },
      operation_id: "018f1d20-7b4c-7a1e-9d22-39a1558b4c61",
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

describe("generated anonymous setup status", () => {
  it("reads only the closed lifecycle state", async () => {
    const fetchStub: typeof globalThis.fetch = async (input) => {
      expect(readRequestUrl(input)).toBe(
        "https://node.example/api/latest/setup/status",
      );
      return Promise.resolve(jsonResponse({ state: "claim_required" }));
    };
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: fetchStub,
    });

    await expect(client.getSetupStatus()).resolves.toEqual({
      state: "claim_required",
    });
  });

  it("rejects leaked fields", async () => {
    const fetchStub: typeof globalThis.fetch = async () =>
      Promise.resolve(
        jsonResponse({ claim_id: "must-not-leak", state: "claim_required" }),
      );
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: fetchStub,
    });

    await expect(client.getSetupStatus()).rejects.toThrow();
  });
});

describe("generated first-mesh setup", () => {
  it("posts the exact bounded request and validates the sensitive result", async () => {
    const fetchStub: typeof globalThis.fetch = async (input, init) => {
      expect(readRequestUrl(input)).toBe(
        "https://node.example/api/latest/setup/meshes",
      );
      expect(init?.method).toBe("POST");
      expect(JSON.parse(readStringBody(init?.body))).toMatchObject({
        claim: SETUP_CLAIM,
        operation_id: SETUP_OPERATION_ID,
      });
      return Promise.resolve(jsonResponse(validSetupResponse(), 201));
    };
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: fetchStub,
    });

    await expect(client.createMeshSetup(validSetupRequest())).resolves.toEqual(
      validSetupResponse(),
    );
  });

  it("rejects invalid setup input before Fetch", async () => {
    let called = false;
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async () => {
        called = true;
        return Promise.resolve(jsonResponse(validSetupResponse(), 201));
      },
    });

    await expect(
      client.createMeshSetup({ ...validSetupRequest(), mesh_name: "bad/name" }),
    ).rejects.toThrow();
    expect(called).toBe(false);
  });
});

describe("generated session delivery", () => {
  it("returns the validated body and independently validated CSRF header", async () => {
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async () =>
        Promise.resolve(
          jsonResponse(validSessionResponse(), 201, {
            "MeshSpan-CSRF-Token": SESSION_CSRF,
          }),
        ),
    });

    await expect(client.createSession(validSessionRequest())).resolves.toEqual({
      csrfToken: SESSION_CSRF,
      session: validSessionResponse(),
    });
  });

  it("rejects a successful body without the required CSRF header", async () => {
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async () =>
        Promise.resolve(jsonResponse(validSessionResponse(), 201)),
    });

    await expect(client.createSession(validSessionRequest())).rejects.toThrow(
      "response has an invalid MeshSpan CSRF token",
    );
  });
});

function validSetupRequest() {
  return {
    administrator_name: "Administrator",
    claim: SETUP_CLAIM,
    host_name: "First host",
    mesh_name: "Home storage",
    node_name: "First node",
    operation_id: SETUP_OPERATION_ID,
  } as const;
}

function validSetupResponse() {
  return {
    api_key: `meshspan-key-v1.${"3".repeat(32)}.${"4".repeat(64)}`,
    mesh_id: "00000000-0000-4000-8000-000000000002",
    node_id: "00000000-0000-4000-8000-000000000003",
    operation_id: SETUP_OPERATION_ID,
  } as const;
}

function validSessionRequest() {
  return {
    authentication: { method: "api_key", secret: SESSION_API_KEY },
    operation_id: SETUP_OPERATION_ID,
    remember: false,
  } as const;
}

function validSessionResponse() {
  return {
    assurance: "single_factor",
    expires_at_epoch_micros: 60_000_000,
    operation_id: SETUP_OPERATION_ID,
    session_id: "00000000-0000-4000-8000-000000000007",
  } as const;
}

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

function readStringBody(body: BodyInit | null | undefined): string {
  if (typeof body !== "string") {
    throw new TypeError("expected a string request body");
  }
  return body;
}

function jsonResponse(
  value: unknown,
  statusCode = 200,
  additionalHeaders: Readonly<Record<string, string>> = {},
): Response {
  return new Response(JSON.stringify(value), {
    headers: { ...RESPONSE_HEADERS, ...additionalHeaders },
    status: statusCode,
  });
}
