// SPDX-License-Identifier: GPL-2.0-only
// @vitest-environment jsdom

import { render } from "@solidjs/web";
import { flush } from "solid-js";
import { afterEach, describe, expect, it, vi } from "vitest";

import { AuthenticationSecurityPanel } from "../src/features/authentication/AuthenticationSecurityPanel";
import type { AuthenticationSecurityClient } from "../src/features/authentication/model";
import type { CreateRecoveryCodesResponse } from "../src/generated/types.gen";

const CSRF_TOKEN = `meshspan-csrf-v1.${"5".repeat(32)}.${"6".repeat(64)}`;
const CHALLENGE_ID = "00000000-0000-4000-8000-000000000002";
const METHOD_ID = "00000000-0000-4000-8000-000000000003";
const OPERATION_ID = "00000000-0000-4000-8000-000000000001";
const API_KEY = `meshspan-key-v1.${"3".repeat(32)}.${"4".repeat(64)}`;
const mountedRoots = new Set<() => void>();
const credentialsDescriptor = Object.getOwnPropertyDescriptor(
  navigator,
  "credentials",
);

afterEach(() => {
  for (const dispose of mountedRoots) {
    dispose();
  }
  mountedRoots.clear();
  document.body.replaceChildren();
  restoreCredentials();
  vi.restoreAllMocks();
});

describe("authentication method management", () => {
  it("lists and revokes a current authentication method", async () => {
    const fixture = createFixture();
    mountPanel(fixture.client);
    await waitForText("Automation");

    clickButton("Revoke method");
    setInput("Reason", "Lost device");
    clickButton("Revoke access");
    await waitForCalls(fixture.revoke, 1);

    expect(fixture.revoke).toHaveBeenCalledWith(
      METHOD_ID,
      expect.objectContaining({ reason: "Lost device" }),
      CSRF_TOKEN,
    );
  });

  it("registers a passkey with browser-produced evidence", async () => {
    installRegistrationCredential();
    const fixture = createFixture();
    mountPanel(fixture.client);
    await waitForText("Add a passkey");

    clickButton("Add passkey");
    await waitForCalls(fixture.createPasskey, 1);

    expect(fixture.createPasskey).toHaveBeenCalledWith(
      expect.objectContaining({
        attestation_object: "Cgs",
        challenge_id: CHALLENGE_ID,
        client_data_json: "DA0",
        credential_id: "AQI",
        label: "This device",
        transports: ["internal"],
      }),
      CSRF_TOKEN,
    );
  });
});

describe("authentication secret enrolment", () => {
  it("confirms TOTP setup after showing the one-time secret", async () => {
    const fixture = createFixture();
    mountPanel(fixture.client);
    await waitForText("Authenticator codes");

    clickButton("Set up authenticator");
    await waitForText("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    setInput("Current six-digit code", "123456");
    clickButton("Confirm authenticator");
    await waitForCalls(fixture.createTotp, 1);

    expect(fixture.createTotp).toHaveBeenCalledWith(
      expect.objectContaining({
        challenge_id: CHALLENGE_ID,
        code: "123456",
      }),
      CSRF_TOKEN,
    );
  });

  it("presents replacement recovery codes only after generation", async () => {
    const fixture = createFixture();
    mountPanel(fixture.client);
    await waitForText("Recovery codes");

    expect(
      document.querySelector("[aria-label='New recovery codes']"),
    ).toBeNull();
    clickButton("Generate new recovery codes");
    await waitForText(recoveryCode(0));

    expect(fixture.createRecoveryCodes).toHaveBeenCalledWith(
      expect.objectContaining({ label: "Recovery codes" }),
      CSRF_TOKEN,
    );
  });

  it("issues a scoped API key and displays its secret once", async () => {
    const fixture = createFixture();
    mountPanel(fixture.client);
    await waitForText("Create an API key");

    clickButton("Create API key");
    await waitForText(API_KEY);

    expect(fixture.createApiKey).toHaveBeenCalledWith(
      expect.objectContaining({
        expires_at_epoch_micros: null,
        label: "Automation",
        scopes: ["headless_api"],
      }),
      CSRF_TOKEN,
    );
  });
});

function createFixture() {
  const list = vi.fn(async () => Promise.resolve(methodPage()));
  const revoke = vi.fn(async () => Promise.resolve(revocationResponse()));
  const createApiKey = vi.fn(async () => Promise.resolve(apiKeyResponse()));
  const createPasskey = vi.fn(async () => Promise.resolve(methodResponse()));
  const createRecoveryCodes = vi.fn(async () =>
    Promise.resolve(recoveryCodeResponse()),
  );
  const createTotp = vi.fn(async () => Promise.resolve(methodResponse()));
  const client = {
    createCurrentUserApiKey: createApiKey,
    createCurrentUserPasskey: createPasskey,
    createCurrentUserPasskeyRegistrationChallenge: vi.fn(async () =>
      Promise.resolve(passkeyChallenge()),
    ),
    createCurrentUserRecoveryCodes: createRecoveryCodes,
    createCurrentUserTotp: createTotp,
    createCurrentUserTotpRegistrationChallenge: vi.fn(async () =>
      Promise.resolve(totpChallenge()),
    ),
    listCurrentUserAuthenticationMethods: list,
    listNextCurrentUserAuthenticationMethods: vi.fn(async () =>
      Promise.resolve({ methods: [], next_page_url: null }),
    ),
    revokeCurrentUserAuthenticationMethod: revoke,
  } satisfies AuthenticationSecurityClient;
  return {
    client,
    createApiKey,
    createPasskey,
    createRecoveryCodes,
    createTotp,
    revoke,
  };
}

function mountPanel(client: AuthenticationSecurityClient): void {
  const root = document.createElement("div");
  document.body.append(root);
  mountedRoots.add(
    render(
      () => (
        <AuthenticationSecurityPanel client={client} csrfToken={CSRF_TOKEN} />
      ),
      root,
    ),
  );
}

function clickButton(label: string): void {
  const button = [...document.querySelectorAll("button")].find(
    (candidate) => candidate.textContent.trim() === label,
  );
  if (button === undefined) {
    throw new TypeError(`expected button: ${label}`);
  }
  button.click();
  flush();
}

function setInput(label: string, value: string): void {
  const labelElement = [...document.querySelectorAll("label")].find(
    (candidate) => candidate.querySelector("span")?.textContent === label,
  );
  const input = labelElement?.querySelector("input");
  if (input === null || input === undefined) {
    throw new TypeError(`expected input: ${label}`);
  }
  input.value = value;
  input.dispatchEvent(new InputEvent("input", { bubbles: true }));
  flush();
}

async function waitForText(expected: string): Promise<void> {
  await vi.waitFor(
    () => {
      flush();
      expect(document.body.textContent).toContain(expected);
    },
    { interval: 1, timeout: 1_000 },
  );
}

async function waitForCalls(
  mock: ReturnType<typeof vi.fn>,
  expected: number,
): Promise<void> {
  await vi.waitFor(
    () => {
      flush();
      expect(mock).toHaveBeenCalledTimes(expected);
    },
    { interval: 1, timeout: 1_000 },
  );
}

function installRegistrationCredential(): void {
  const credential = {
    id: "credential",
    rawId: Uint8Array.from([1, 2]).buffer,
    response: {
      attestationObject: Uint8Array.from([10, 11]).buffer,
      clientDataJSON: Uint8Array.from([12, 13]).buffer,
      getTransports: () => ["internal"],
    },
    type: "public-key",
  } as unknown as Credential;
  Object.defineProperty(navigator, "credentials", {
    configurable: true,
    value: {
      create: async () => Promise.resolve(credential),
      get: async () => Promise.resolve(credential),
    },
  });
}

function restoreCredentials(): void {
  if (credentialsDescriptor === undefined) {
    Reflect.deleteProperty(navigator, "credentials");
    return;
  }
  Object.defineProperty(navigator, "credentials", credentialsDescriptor);
}

function methodPage() {
  return {
    methods: [
      {
        created_at_epoch_micros: 10,
        details: {
          key_id: "00000000-0000-4000-8000-000000000005",
          kind: "api_key" as const,
          scopes: ["headless_api" as const],
          valid_from_epoch_micros: 10,
        },
        expires_at_epoch_micros: null,
        label: "Automation",
        last_used_at_epoch_micros: null,
        method_id: METHOD_ID,
        revision: 1,
        state: "active" as const,
      },
    ],
    next_page_url: null,
  };
}

function methodResponse() {
  return {
    created_at_epoch_micros: 80_000_000,
    method_id: METHOD_ID,
    operation_id: OPERATION_ID,
  };
}

function revocationResponse() {
  return {
    method_id: METHOD_ID,
    operation_id: OPERATION_ID,
    revoked_at_epoch_micros: 80_000_000,
  };
}

function apiKeyResponse() {
  return {
    created_at_epoch_micros: 70_000_000,
    expires_at_epoch_micros: null,
    key_id: "00000000-0000-4000-8000-000000000009",
    method_id: METHOD_ID,
    operation_id: OPERATION_ID,
    scopes: ["headless_api" as const],
    secret: API_KEY,
    valid_from_epoch_micros: 70_000_000,
  };
}

function recoveryCodeResponse(): CreateRecoveryCodesResponse {
  return {
    codes: [
      recoveryCode(0),
      recoveryCode(1),
      recoveryCode(2),
      recoveryCode(3),
      recoveryCode(4),
      recoveryCode(5),
      recoveryCode(6),
      recoveryCode(7),
      recoveryCode(8),
      recoveryCode(9),
    ],
    ...methodResponse(),
  };
}

function recoveryCode(index: number): string {
  return `meshspan-recovery-v1.${index.toString(16).padStart(32, "0")}.${"7".repeat(64)}`;
}

function passkeyChallenge() {
  return {
    attestation: "none" as const,
    challenge: "AQID",
    challenge_id: CHALLENGE_ID,
    exclude_credentials: [{ id: "AQ", type: "public-key" as const }],
    operation_id: OPERATION_ID,
    public_key_parameters: [{ algorithm: -7, type: "public-key" as const }],
    relying_party_id: "node.example",
    relying_party_name: "MeshSpan",
    resident_key: "required" as const,
    timeout_milliseconds: 30_000,
    user_display_name: "Administrator",
    user_id: "AQIDBAUGBwgJCgsMDQ4PEA",
    user_name: "Administrator",
    user_verification: "required" as const,
  };
}

function totpChallenge() {
  return {
    algorithm: "SHA1" as const,
    challenge_id: CHALLENGE_ID,
    digits: 6 as const,
    expires_at_epoch_micros: 80_000_000,
    operation_id: OPERATION_ID,
    period_seconds: 30 as const,
    provisioning_uri:
      "otpauth://totp/MeshSpan:Administrator?secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
    secret: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
  };
}
