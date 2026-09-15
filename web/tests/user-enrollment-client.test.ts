// SPDX-License-Identifier: GPL-2.0-only

import { describe, expect, it } from "vitest";
import { createMeshSpanFetchClient } from "../src/generated/fetch.gen";

const OPERATION = "00000000-0000-4000-8000-000000000001";
const PRINCIPAL = "00000000-0000-4000-8000-000000000002";
const TOKEN = `meshspan-user-enrollment-v1.${"1".repeat(32)}.${"2".repeat(64)}`;
const CSRF = `meshspan-csrf-v1.${"3".repeat(32)}.${"4".repeat(64)}`;
const issueRequest = {
  operation_id: OPERATION,
  expected_principal_revision: 1,
  expires_at_epoch_micros: 1000,
};
const invitation = {
  operation_id: OPERATION,
  principal_id: PRINCIPAL,
  token: TOKEN,
  expires_at_epoch_micros: 1000,
  committed_revision: 2,
};

describe("generated manager enrollment consent client", () => {
  it("issues consent through the manager route with CSRF", async () => {
    const capture = fixture(invitation);
    await expect(
      capture.client.issueUserEnrollment(PRINCIPAL, issueRequest, CSRF),
    ).resolves.toEqual(invitation);
    expect(capture.calls).toEqual([
      {
        url: `https://node.example/api/latest/admin/identities/users/${PRINCIPAL}/enrollments`,
        body: issueRequest,
        csrf: CSRF,
      },
    ]);
  });

  it("revokes the exact issuance operation with its current revision", async () => {
    const response = {
      operation_id: OPERATION,
      enrollment_operation_id: OPERATION,
      committed_revision: 3,
    };
    const capture = fixture(response);
    await expect(
      capture.client.revokeUserEnrollment(
        OPERATION,
        { operation_id: OPERATION, expected_revision: 2 },
        CSRF,
      ),
    ).resolves.toEqual(response);
    expect(capture.calls[0]?.url).toBe(
      `https://node.example/api/latest/admin/identities/user-enrollments/${OPERATION}/revocations`,
    );
  });
});

describe("generated anonymous credential enrollment client", () => {
  it("returns a validated ordinary key to the recipient", async () => {
    const response = {
      operation_id: OPERATION,
      key_id: PRINCIPAL,
      method_id: "00000000-0000-4000-8000-000000000003",
      created_at_epoch_micros: 100,
      valid_from_epoch_micros: 100,
      expires_at_epoch_micros: null,
      scopes: ["https_session"],
      secret: `meshspan-key-v1.${PRINCIPAL.replaceAll("-", "")}.${"a".repeat(64)}`,
    };
    const capture = fixture(response);
    await expect(
      capture.client.redeemUserEnrollmentApiKey({
        operation_id: OPERATION,
        token: TOKEN,
        label: "My first key",
        scopes: ["https_session"],
        expires_at_epoch_micros: null,
      }),
    ).resolves.toEqual(response);
  });

  it("sends anonymous capability redemption only inside JSON and validates the receipt", async () => {
    const capture = fixture({});
    const request = {
      operation_id: OPERATION,
      token: TOKEN,
      label: "My first key",
      scopes: ["https_session" as const],
      expires_at_epoch_micros: null,
    };
    await expect(
      capture.client.redeemUserEnrollmentApiKey(request),
    ).rejects.toThrow();
    expect(capture.calls).toEqual([
      {
        url: "https://node.example/api/latest/user-enrollments/api-keys",
        body: request,
        csrf: null,
      },
    ]);
  });

  it("rejects malformed invitation and path input before Fetch", async () => {
    const capture = fixture(invitation);
    await expect(
      capture.client.issueUserEnrollment("../../bad", issueRequest, CSRF),
    ).rejects.toThrow();
    await expect(
      capture.client.redeemUserEnrollmentApiKey({
        operation_id: OPERATION,
        token: "invalid",
        label: "key",
        scopes: ["https_session"],
        expires_at_epoch_micros: null,
      }),
    ).rejects.toThrow();
    expect(capture.calls).toHaveLength(0);
  });
});

function fixture(response: unknown) {
  const calls: {
    url: string;
    body: unknown;
    csrf: string | null;
  }[] = [];
  const client = createMeshSpanFetchClient({
    baseUrl: "https://node.example/api/latest/",
    fetch: async (input, init) => {
      calls.push({
        url: input instanceof Request ? input.url : String(input),
        body: readBody(init?.body),
        csrf: new Headers(init?.headers).get("MeshSpan-CSRF-Token"),
      });
      return Promise.resolve(
        new Response(JSON.stringify(response), {
          headers: {
            "Content-Type": "application/json",
            "MeshSpan-API-Schema": `sha256:${"a".repeat(64)}`,
            "MeshSpan-API-Version": "latest",
          },
        }),
      );
    },
  });
  return { client, calls };
}

function readBody(body: BodyInit | null | undefined): unknown {
  if (typeof body !== "string")
    throw new TypeError("expected JSON request body");
  return JSON.parse(body);
}
