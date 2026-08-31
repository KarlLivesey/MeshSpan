// SPDX-License-Identifier: GPL-2.0-only

import { describe, expect, it, vi } from "vitest";

import {
  requestPasskeyAssertion,
  requestPasskeyRegistration,
} from "../src/features/authentication/webauthn";
import type {
  CreatePasskeyChallengeResponse,
  CreatePasskeyRegistrationChallengeResponse,
} from "../src/generated/types.gen";

const OPERATION_ID = "00000000-0000-4000-8000-000000000001";
const CHALLENGE_ID = "00000000-0000-4000-8000-000000000002";

describe("passkey assertion browser boundary", () => {
  it("translates exact browser evidence into canonical unpadded base64url", async () => {
    const credentials = assertionCredentials({ signature: bytes(7, 8, 9) });
    await expect(
      requestPasskeyAssertion(assertionChallenge(), credentials),
    ).resolves.toEqual({
      authenticator_data: "AwQ",
      challenge_id: CHALLENGE_ID,
      client_data_json: "BQY",
      credential_id: "AQI",
      method: "passkey",
      signature: "BwgJ",
      user_handle: null,
    });
    expect(credentials.get).toHaveBeenCalledWith({
      publicKey: {
        challenge: bytes(1, 2, 3).buffer,
        rpId: "node.example",
        timeout: 30_000,
        userVerification: "required",
      },
    });
  });

  it("rejects non-canonical server bytes and oversized authenticator evidence", async () => {
    const credentials = assertionCredentials({
      signature: new Uint8Array(1_025),
    });
    await expect(
      requestPasskeyAssertion(
        { ...assertionChallenge(), challenge: "ab" },
        credentials,
      ),
    ).rejects.toThrow("non-canonical");
    await expect(
      requestPasskeyAssertion(assertionChallenge(), credentials),
    ).rejects.toThrow("oversized signature");
  });
});

describe("passkey registration browser boundary", () => {
  it("sends exact discoverable-credential policy and bounds the result", async () => {
    const credentials = registrationCredentials();
    await expect(
      requestPasskeyRegistration(
        registrationChallenge(),
        "Laptop",
        OPERATION_ID,
        credentials,
      ),
    ).resolves.toEqual({
      attestation_object: "Cgs",
      challenge_id: CHALLENGE_ID,
      client_data_json: "DA0",
      credential_id: "AQI",
      label: "Laptop",
      operation_id: OPERATION_ID,
      transports: ["internal", "hybrid"],
    });
    const createOptions = credentials.create.mock.calls[0]?.[0];
    expect(createOptions?.publicKey).toMatchObject({
      attestation: "none",
      authenticatorSelection: {
        requireResidentKey: true,
        residentKey: "required",
        userVerification: "required",
      },
      rp: { id: "node.example", name: "MeshSpan" },
    });
  });

  it("rejects an invented transport rather than forwarding it", async () => {
    const credentials = registrationCredentials(["cable"]);
    await expect(
      requestPasskeyRegistration(
        registrationChallenge(),
        "Laptop",
        OPERATION_ID,
        credentials,
      ),
    ).rejects.toThrow("invalid transports");
  });
});

function assertionChallenge(): CreatePasskeyChallengeResponse {
  return {
    challenge: "AQID",
    challenge_id: CHALLENGE_ID,
    operation_id: OPERATION_ID,
    relying_party_id: "node.example",
    timeout_milliseconds: 30_000,
    user_verification: "required",
  };
}

function registrationChallenge(): CreatePasskeyRegistrationChallengeResponse {
  return {
    attestation: "none",
    challenge: "AQID",
    challenge_id: CHALLENGE_ID,
    exclude_credentials: [{ id: "AQI", type: "public-key" }],
    operation_id: OPERATION_ID,
    public_key_parameters: [{ algorithm: -7, type: "public-key" }],
    relying_party_id: "node.example",
    relying_party_name: "MeshSpan",
    resident_key: "required",
    timeout_milliseconds: 30_000,
    user_display_name: "Administrator",
    user_id: "AQIDBAUGBwgJCgsMDQ4PEA",
    user_name: "Administrator",
    user_verification: "required",
  };
}

function assertionCredentials(overrides: Readonly<{ signature: Uint8Array }>) {
  return {
    create: vi.fn<CredentialsContainer["create"]>(),
    get: vi.fn<CredentialsContainer["get"]>(async () =>
      Promise.resolve(
        credential({
          authenticatorData: bytes(3, 4).buffer,
          clientDataJSON: bytes(5, 6).buffer,
          signature: overrides.signature.buffer,
          userHandle: null,
        }),
      ),
    ),
    preventSilentAccess: vi.fn<CredentialsContainer["preventSilentAccess"]>(),
    store: vi.fn<CredentialsContainer["store"]>(),
  } satisfies CredentialsContainer;
}

function registrationCredentials(
  transports: readonly string[] = ["internal", "hybrid"],
) {
  return {
    create: vi.fn<CredentialsContainer["create"]>(async () =>
      Promise.resolve(
        credential({
          attestationObject: bytes(10, 11).buffer,
          clientDataJSON: bytes(12, 13).buffer,
          getTransports: () => transports,
        }),
      ),
    ),
    get: vi.fn<CredentialsContainer["get"]>(),
    preventSilentAccess: vi.fn<CredentialsContainer["preventSilentAccess"]>(),
    store: vi.fn<CredentialsContainer["store"]>(),
  } satisfies CredentialsContainer;
}

function credential(response: Readonly<Record<string, unknown>>): Credential {
  return {
    id: "credential",
    rawId: bytes(1, 2).buffer,
    response,
    type: "public-key",
  } as unknown as Credential;
}

function bytes(...values: number[]): Uint8Array<ArrayBuffer> {
  return Uint8Array.from(values);
}
