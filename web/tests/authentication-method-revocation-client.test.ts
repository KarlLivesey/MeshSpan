// SPDX-License-Identifier: GPL-2.0-only

import { describe, expect, it } from "vitest";

import { createMeshSpanFetchClient } from "../src/generated/fetch.gen";

const OPERATION_ID = "00000000-0000-4000-8000-000000000001";
const METHOD_ID = "00000000-0000-4000-8000-00000000000a";
const CSRF_TOKEN = `meshspan-csrf-v1.${"5".repeat(32)}.${"6".repeat(64)}`;
const RESPONSE_HEADERS = {
  "Content-Type": "application/json",
  "MeshSpan-API-Schema": `sha256:${"a".repeat(64)}`,
  "MeshSpan-API-Version": "latest",
};

describe("generated current-user authentication-method revocation", () => {
  it("substitutes the validated method path and sends the session-bound CSRF token", async () => {
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async (input, init) => {
        expect(readRequestUrl(input)).toBe(
          `https://node.example/api/latest/users/current/authentication-methods/${METHOD_ID}/revocations`,
        );
        expect(init?.method).toBe("POST");
        expect(new Headers(init?.headers).get("MeshSpan-CSRF-Token")).toBe(
          CSRF_TOKEN,
        );
        expect(JSON.parse(readStringBody(init?.body))).toEqual({
          operation_id: OPERATION_ID,
          reason: "Rotating the automation credential",
        });
        return Promise.resolve(jsonResponse(validResponse()));
      },
    });

    await expect(
      client.revokeCurrentUserAuthenticationMethod(
        METHOD_ID,
        validRequest(),
        CSRF_TOKEN,
      ),
    ).resolves.toEqual(validResponse());
  });

  it("rejects an invalid path or CSRF token before Fetch", async () => {
    let called = false;
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async () => {
        called = true;
        return Promise.resolve(jsonResponse({}));
      },
    });

    await expect(
      client.revokeCurrentUserAuthenticationMethod(
        "not-a-method-id",
        validRequest(),
        CSRF_TOKEN,
      ),
    ).rejects.toThrow();
    await expect(
      client.revokeCurrentUserAuthenticationMethod(
        METHOD_ID,
        validRequest(),
        "invalid",
      ),
    ).rejects.toThrow("request has an invalid MeshSpan CSRF token");
    expect(called).toBe(false);
  });
});

function validRequest() {
  return {
    operation_id: OPERATION_ID,
    reason: "Rotating the automation credential",
  } as const;
}

function validResponse() {
  return {
    method_id: METHOD_ID,
    operation_id: OPERATION_ID,
    revoked_at_epoch_micros: 80_000_000,
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

function jsonResponse(value: unknown): Response {
  return new Response(JSON.stringify(value), {
    headers: RESPONSE_HEADERS,
  });
}
