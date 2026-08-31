// SPDX-License-Identifier: GPL-2.0-only

import { describe, expect, it } from "vitest";

import { createMeshSpanFetchClient } from "../src/generated/fetch.gen";

const OPERATION_ID = "00000000-0000-4000-8000-000000000001";
const CHALLENGE_ID = "00000000-0000-4000-8000-000000000002";
const METHOD_ID = "00000000-0000-4000-8000-000000000003";
const SESSION_ID = "00000000-0000-4000-8000-000000000004";
const CSRF_TOKEN = `meshspan-csrf-v1.${"5".repeat(32)}.${"6".repeat(64)}`;
const RESPONSE_HEADERS = {
  "Content-Type": "application/json",
  "MeshSpan-API-Schema": `sha256:${"a".repeat(64)}`,
  "MeshSpan-API-Version": "latest",
};

describe("generated authentication-method inventory client", () => {
  it("validates the initial query and a server-provided continuation", async () => {
    const requestedUrls: string[] = [];
    const nextPageUrl =
      "/api/latest/users/current/authentication-methods?limit=1&cursor=v1.am.proof";
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async (input) => {
        requestedUrls.push(readRequestUrl(input));
        const isNext = requestedUrls.length === 2;
        return Promise.resolve(
          jsonResponse({
            methods: isNext ? [] : [validAuthenticationMethod()],
            next_page_url: isNext ? null : nextPageUrl,
          }),
        );
      },
    });

    const first = await client.listCurrentUserAuthenticationMethods({
      limit: 1,
    });
    await expect(
      client.listNextCurrentUserAuthenticationMethods(
        first.next_page_url ?? "missing",
      ),
    ).resolves.toEqual({ methods: [], next_page_url: null });
    expect(requestedUrls).toEqual([
      "https://node.example/api/latest/users/current/authentication-methods?limit=1",
      `https://node.example${nextPageUrl}`,
    ]);
  });

  it("rejects substituted or ambiguous continuation URLs before Fetch", async () => {
    let calls = 0;
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async () => {
        calls += 1;
        return Promise.resolve(jsonResponse({}));
      },
    });

    for (const value of [
      "https://attacker.example/api/latest/users/current/authentication-methods",
      "/api/latest/admin/users",
      "/api/latest/users/current/authentication-methods?limit=1&limit=2",
    ]) {
      await expect(
        client.listNextCurrentUserAuthenticationMethods(value),
      ).rejects.toThrow();
    }
    expect(calls).toBe(0);
  });

  it("rejects secret-bearing or otherwise unknown response fields", async () => {
    const client = clientForResponse({
      methods: [{ ...validAuthenticationMethod(), secret: "must-not-pass" }],
      next_page_url: null,
    });
    await expect(
      client.listCurrentUserAuthenticationMethods(),
    ).rejects.toThrow();
  });
});

describe("generated passkey client", () => {
  it("creates and validates anonymous assertion challenges", async () => {
    const challenge = validPasskeyChallenge();
    const capture = captureResponse(challenge);
    const client = capture.client;

    await expect(
      client.createPasskeyChallenge({ operation_id: OPERATION_ID }),
    ).resolves.toEqual(challenge);
    expect(capture.url()).toBe(
      "https://node.example/api/latest/sessions/passkey/challenges",
    );
    expect(capture.body()).toEqual({ operation_id: OPERATION_ID });
  });

  it("creates registration options and submits browser evidence", async () => {
    const challenge = validRegistrationChallenge();
    const challengeCapture = captureResponse(challenge);
    await expect(
      challengeCapture.client.createCurrentUserPasskeyRegistrationChallenge(
        { operation_id: OPERATION_ID },
        CSRF_TOKEN,
      ),
    ).resolves.toEqual(challenge);
    expect(challengeCapture.csrf()).toBe(CSRF_TOKEN);

    const result = validMethodCreationResponse();
    const completionCapture = captureResponse(result);
    await expect(
      completionCapture.client.createCurrentUserPasskey(
        {
          attestation_object: "AA",
          challenge_id: CHALLENGE_ID,
          client_data_json: "e30",
          credential_id: "AQ",
          label: "Laptop passkey",
          operation_id: OPERATION_ID,
          transports: ["internal"],
        },
        CSRF_TOKEN,
      ),
    ).resolves.toEqual(result);
    expect(completionCapture.url()).toBe(
      "https://node.example/api/latest/users/current/authentication-methods/passkeys",
    );
  });
});

describe("generated TOTP and recovery client", () => {
  it("creates TOTP material and confirms its current code", async () => {
    const material = validTotpChallenge();
    const challengeCapture = captureResponse(material);
    await expect(
      challengeCapture.client.createCurrentUserTotpRegistrationChallenge(
        { label: "Authenticator", operation_id: OPERATION_ID },
        CSRF_TOKEN,
      ),
    ).resolves.toEqual(material);

    const result = validMethodCreationResponse();
    const completionCapture = captureResponse(result);
    await expect(
      completionCapture.client.createCurrentUserTotp(
        {
          challenge_id: CHALLENGE_ID,
          code: "123456",
          operation_id: OPERATION_ID,
        },
        CSRF_TOKEN,
      ),
    ).resolves.toEqual(result);
    expect(completionCapture.csrf()).toBe(CSRF_TOKEN);
  });

  it("returns an exactly validated ten-code recovery set", async () => {
    const response = {
      codes: Array.from(
        { length: 10 },
        (_, index) =>
          `meshspan-recovery-v1.${index.toString(16).padStart(32, "0")}.${"7".repeat(64)}`,
      ),
      ...validMethodCreationResponse(),
    };
    const capture = captureResponse(response);

    await expect(
      capture.client.createCurrentUserRecoveryCodes(
        { label: "Recovery codes", operation_id: OPERATION_ID },
        CSRF_TOKEN,
      ),
    ).resolves.toEqual(response);
    expect(capture.url()).toBe(
      "https://node.example/api/latest/users/current/authentication-methods/recovery-codes",
    );
  });
});

describe("generated session step-up client", () => {
  it("validates both the rotated session and replacement CSRF header", async () => {
    const response = {
      assurance: "recent_step_up",
      expires_at_epoch_micros: 80_000_000,
      operation_id: OPERATION_ID,
      session_id: SESSION_ID,
    } as const;
    const replacementCsrf = `meshspan-csrf-v1.${"8".repeat(32)}.${"9".repeat(64)}`;
    const capture = captureResponse(response, replacementCsrf);

    await expect(
      capture.client.stepUpCurrentSession(
        {
          additional_factor: { code: "123456", method: "totp" },
          operation_id: OPERATION_ID,
        },
        CSRF_TOKEN,
      ),
    ).resolves.toEqual({ csrfToken: replacementCsrf, session: response });
    expect(capture.csrf()).toBe(CSRF_TOKEN);
  });
});

function clientForResponse(value: unknown) {
  return createMeshSpanFetchClient({
    baseUrl: "https://node.example/api/latest/",
    fetch: async () => Promise.resolve(jsonResponse(value)),
  });
}

function captureResponse(value: unknown, responseCsrf?: string) {
  let requestInput: RequestInfo | URL | undefined;
  let requestInit: RequestInit | undefined;
  return {
    body: () => JSON.parse(readStringBody(requestInit?.body)) as unknown,
    client: createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: async (input, init) => {
        requestInput = input;
        requestInit = init;
        const headers =
          responseCsrf === undefined
            ? undefined
            : { "MeshSpan-CSRF-Token": responseCsrf };
        return Promise.resolve(jsonResponse(value, headers));
      },
    }),
    csrf: () => new Headers(requestInit?.headers).get("MeshSpan-CSRF-Token"),
    url: () =>
      requestInput === undefined
        ? "request not sent"
        : readRequestUrl(requestInput),
  };
}

function validAuthenticationMethod() {
  return {
    created_at_epoch_micros: 10,
    details: {
      key_id: "00000000-0000-4000-8000-000000000005",
      kind: "api_key",
      scopes: ["headless_api"],
      valid_from_epoch_micros: 10,
    },
    expires_at_epoch_micros: null,
    label: "Automation",
    last_used_at_epoch_micros: null,
    method_id: METHOD_ID,
    revision: 1,
    state: "active",
  };
}

function validPasskeyChallenge() {
  return {
    challenge: "a".repeat(43),
    challenge_id: CHALLENGE_ID,
    operation_id: OPERATION_ID,
    relying_party_id: "node.example",
    timeout_milliseconds: 30_000,
    user_verification: "required",
  };
}

function validRegistrationChallenge() {
  return {
    attestation: "none",
    challenge: "a".repeat(43),
    challenge_id: CHALLENGE_ID,
    exclude_credentials: [{ id: "AQ", type: "public-key" }],
    operation_id: OPERATION_ID,
    public_key_parameters: [{ algorithm: -7, type: "public-key" }],
    relying_party_id: "node.example",
    relying_party_name: "MeshSpan",
    resident_key: "required",
    timeout_milliseconds: 30_000,
    user_display_name: "Administrator",
    user_id: "a".repeat(22),
    user_name: "Administrator",
    user_verification: "required",
  };
}

function validTotpChallenge() {
  return {
    algorithm: "SHA1",
    challenge_id: CHALLENGE_ID,
    digits: 6,
    expires_at_epoch_micros: 80_000_000,
    operation_id: OPERATION_ID,
    period_seconds: 30,
    provisioning_uri:
      "otpauth://totp/MeshSpan:Administrator?secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    secret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  };
}

function validMethodCreationResponse() {
  return {
    created_at_epoch_micros: 80_000_000,
    method_id: METHOD_ID,
    operation_id: OPERATION_ID,
  };
}

function jsonResponse(
  value: unknown,
  additionalHeaders?: Readonly<Record<string, string>>,
): Response {
  return new Response(JSON.stringify(value), {
    headers: { ...RESPONSE_HEADERS, ...additionalHeaders },
  });
}

function readRequestUrl(input: RequestInfo | URL): string {
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
