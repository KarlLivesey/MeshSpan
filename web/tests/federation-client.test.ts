// SPDX-License-Identifier: GPL-2.0-only

import { describe, expect, it } from "vitest";

import { createMeshSpanFetchClient } from "../src/generated/fetch.gen";
import {
  zAcceptFederationPairingBody,
  zCancelFederationPairingInvitationBody,
  zCreateFederationPairingInvitationBody,
} from "../src/generated/zod.gen";

const OPERATION = "11111111-1111-8111-8111-111111111111";
const INVITATION = "21111111-1111-8111-8111-111111111111";
const CSRF_TOKEN = `meshspan-csrf-v1.${"5".repeat(32)}.${"6".repeat(64)}`;
const CREATE = {
  operation_id: OPERATION,
  pairing_endpoint: "https://node.example",
  valid_for_seconds: 900,
};
const CANCEL = {
  operation_id: OPERATION,
  invitation_id: INVITATION,
  expected_invitation_revision: 2,
  reason: "Withdraw",
};

describe("generated federation connection client", () => {
  it("sends local manager intent and validates the returned approval", async () => {
    const request = {
      operation_id: OPERATION,
      connection_code: `meshspan-federate-v1.${"a".repeat(300)}`,
      local_endpoint: "https://local.example",
    };
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async (input, init) => {
        expect(input instanceof Request ? input.url : input.toString()).toBe(
          "https://node.example/api/latest/admin/federation/connections",
        );
        expect(init?.method).toBe("POST");
        expect(new Headers(init?.headers).get("MeshSpan-CSRF-Token")).toBe(
          CSRF_TOKEN,
        );
        if (typeof init?.body !== "string") {
          throw new TypeError("Expected a JSON request body");
        }
        expect(JSON.parse(init.body)).toEqual(request);
        return Promise.resolve(
          response({
            operation_id: OPERATION,
            relationship_id: INVITATION,
            committed_revision: 4,
          }),
        );
      },
    });
    expect(
      (await client.connectFederation(request, CSRF_TOKEN)).committed_revision,
    ).toBe(4);
  });
});

describe("generated federation peer acceptance client", () => {
  it("uses only the invitation credential for peer acceptance", async () => {
    const connectionCode = `meshspan-federate-v1.${"a".repeat(300)}`;
    const request = { operation_id: OPERATION, peer_record: "A".repeat(172) };
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      apiKey: `meshspan-key-v1.${"1".repeat(32)}.${"2".repeat(64)}`,
      fetch: async (input, init) => {
        expect(input instanceof Request ? input.url : input.toString()).toBe(
          "https://node.example/api/latest/federation/pairings/accept",
        );
        expect(init?.method).toBe("POST");
        expect(init?.credentials).toBe("omit");
        expect(new Headers(init?.headers).get("Authorization")).toBe(
          `MeshSpan-Pairing ${connectionCode}`,
        );
        expect(init?.body).toBe(JSON.stringify(request));
        return Promise.resolve(
          response({
            ...request,
            relationship_id: INVITATION,
            committed_revision: 4,
          }),
        );
      },
    });
    expect(
      (await client.acceptFederationPairing(request, connectionCode))
        .committed_revision,
    ).toBe(4);
  });

  it("rejects malformed acceptance records before a request", () => {
    const valid = { operation_id: OPERATION, peer_record: "A".repeat(172) };
    expect(zAcceptFederationPairingBody.safeParse(valid).success).toBe(true);
    for (const invalid of [
      { ...valid, unknown: true },
      { ...valid, peer_record: null },
      { ...valid, peer_record: "A".repeat(171) },
      { ...valid, peer_record: "A".repeat(24_577) },
      { ...valid, peer_record: "=".repeat(172) },
    ]) {
      expect(zAcceptFederationPairingBody.safeParse(invalid).success).toBe(
        false,
      );
    }
  });
});

describe("generated federation invitation administration client", () => {
  it("sends the exact native cancellation route, intent and CSRF header", async () => {
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async (input, init) => {
        expect(input instanceof Request ? input.url : input.toString()).toBe(
          "https://node.example/api/latest/admin/federation/invitations/cancel",
        );
        expect(init?.method).toBe("POST");
        if (typeof init?.body !== "string") {
          throw new TypeError("Expected a JSON request body");
        }
        expect(JSON.parse(init.body)).toEqual(CANCEL);
        expect(new Headers(init.headers).get("MeshSpan-CSRF-Token")).toBe(
          CSRF_TOKEN,
        );
        return Promise.resolve(
          response({
            operation_id: OPERATION,
            invitation_id: INVITATION,
            committed_revision: 3,
          }),
        );
      },
    });
    expect(
      (await client.cancelFederationPairingInvitation(CANCEL, CSRF_TOKEN))
        .committed_revision,
    ).toBe(3);
  });

  it("rejects coercion, unknown fields and out-of-range validity", () => {
    expect(
      zCreateFederationPairingInvitationBody.safeParse(CREATE).success,
    ).toBe(true);
    for (const invalid of [
      { ...CREATE, extra: true },
      { ...CREATE, valid_for_seconds: "900" },
      { ...CREATE, valid_for_seconds: 59 },
      { ...CREATE, valid_for_seconds: 3601 },
      { ...CREATE, pairing_endpoint: "http://node.example" },
    ]) {
      expect(
        zCreateFederationPairingInvitationBody.safeParse(invalid).success,
      ).toBe(false);
    }
    expect(
      zCancelFederationPairingInvitationBody.safeParse(CANCEL).success,
    ).toBe(true);
    expect(
      zCancelFederationPairingInvitationBody.safeParse({
        ...CANCEL,
        expected_invitation_revision: null,
      }).success,
    ).toBe(false);
  });

  it("rejects malformed secret-bearing responses from the server", async () => {
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async () =>
        Promise.resolve(
          response({
            operation_id: OPERATION,
            invitation_id: INVITATION,
            connection_code: "invalid",
            expires_at_epoch_micros: 900_000_000,
            committed_revision: 2,
          }),
        ),
    });
    await expect(
      client.createFederationPairingInvitation(CREATE),
    ).rejects.toThrow();
  });
});

function response(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: {
      "Content-Type": "application/json",
      "MeshSpan-API-Version": "latest",
      "MeshSpan-API-Schema": `sha256:${"a".repeat(64)}`,
    },
  });
}
