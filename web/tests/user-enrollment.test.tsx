// SPDX-License-Identifier: GPL-2.0-only
// @vitest-environment jsdom

import { render } from "@solidjs/web";
import type { JSX } from "@solidjs/web";
import { flush } from "solid-js";
import { afterEach, describe, expect, it, vi } from "vitest";

import { EnrollmentForm } from "../src/features/user-enrollment/EnrollmentForm";
import { InvitationPanel } from "../src/features/identity-administration/InvitationPanel";
import type { InvitationClient } from "../src/features/identity-administration/invitation-model";
import type { MeshSpanFetchClient } from "../src/generated/fetch.gen";
import type {
  CreateApiKeyResponse,
  IssueUserEnrollmentResponse,
  ListPrincipalsResponse,
} from "../src/generated/types.gen";

const TOKEN = `meshspan-user-enrollment-v1.${"a".repeat(32)}.${"b".repeat(64)}`;
const KEY = `meshspan-key-v1.${"c".repeat(32)}.${"d".repeat(64)}`;
const PRINCIPAL = "00000000-0000-4000-8000-000000000001";
const CSRF = `meshspan-csrf-v1.${"e".repeat(32)}.${"f".repeat(64)}`;
const mounted = new Set<() => void>();

afterEach(() => {
  for (const dispose of mounted) dispose();
  mounted.clear();
  document.body.replaceChildren();
  vi.restoreAllMocks();
});

describe("recipient enrollment", () => {
  it("rejects an invalid capability locally without sending a mutation", async () => {
    const fixture = recipient();
    mount(() => <EnrollmentForm {...fixture} />);
    input("Invitation token", "wrong token");
    click("Create my key");
    await settle();
    expect(fixture.client.redeemUserEnrollmentApiKey).not.toHaveBeenCalled();
    expect(document.body.textContent).toContain("Nothing was submitted.");
    expect(field("Invitation token").disabled).toBe(false);
  });

  it("locks unknown edits and retries exactly before independent sign-in", async () => {
    const fixture = recipient();
    const storage = vi.spyOn(Storage.prototype, "setItem");
    fixture.client.redeemUserEnrollmentApiKey.mockRejectedValueOnce(
      new TypeError("lost response"),
    );
    mount(() => <EnrollmentForm {...fixture} />);
    input("Invitation token", TOKEN);
    input("Key name", "Bob key");
    click("Create my key");
    await settle();
    expect(document.body.textContent).toContain("The result is unknown.");
    expect(document.body.textContent).not.toContain(KEY);
    expect(field("Invitation token").disabled).toBe(true);
    expect(field("Key name").disabled).toBe(true);
    click("Retry enrollment");
    await settle();
    const calls = fixture.client.redeemUserEnrollmentApiKey.mock.calls;
    expect(calls).toHaveLength(2);
    expect(calls[1]).toEqual(calls[0]);
    expect(document.body.textContent).toContain("Your key was created.");
    expect(field("Invitation token").value).toBe("");
    click("Sign in with my key");
    await settle();
    expect(fixture.signIn).toHaveBeenCalledWith(KEY);
    expect(storage).not.toHaveBeenCalled();
    expect(window.location.search).toBe("");
  });
});

describe("enrollment receipt recovery", () => {
  it("submits only once while an enrollment response is pending", async () => {
    const fixture = recipient();
    const deferred = Promise.withResolvers<CreateApiKeyResponse>();
    fixture.client.redeemUserEnrollmentApiKey.mockReturnValueOnce(
      deferred.promise,
    );
    mount(() => <EnrollmentForm {...fixture} />);
    input("Invitation token", TOKEN);
    click("Create my key");
    click("Retry enrollment");
    await settle();
    expect(fixture.client.redeemUserEnrollmentApiKey).toHaveBeenCalledTimes(1);
    expect(field("Key name").disabled).toBe(true);
    const request =
      fixture.client.redeemUserEnrollmentApiKey.mock.calls[0]?.[0];
    if (request === undefined)
      throw new TypeError("Missing enrollment request");
    deferred.resolve(keyReceipt(request.operation_id));
    await settle();
    expect(document.body.textContent).toContain("Your key was created.");
  });

  it("does not expose a receipt bound to a different operation", async () => {
    const fixture = recipient();
    fixture.client.redeemUserEnrollmentApiKey.mockResolvedValueOnce(
      keyReceipt(PRINCIPAL),
    );
    mount(() => <EnrollmentForm {...fixture} />);
    input("Invitation token", TOKEN);
    click("Create my key");
    await settle();
    expect(document.body.textContent).toContain("The result is unknown.");
    expect(document.body.textContent).not.toContain(KEY);
  });

  it("keeps committed credential truth when sign-in fails", async () => {
    const fixture = recipient();
    fixture.signIn.mockRejectedValueOnce(
      new TypeError("session response lost"),
    );
    mount(() => <EnrollmentForm {...fixture} />);
    input("Invitation token", TOKEN);
    click("Create my key");
    await settle();
    click("Sign in with my key");
    await settle();
    expect(document.body.textContent).toContain(
      "Your key is created, but sign-in could not be confirmed.",
    );
    expect(document.body.textContent).toContain(KEY);
    expect(fixture.client.redeemUserEnrollmentApiKey).toHaveBeenCalledTimes(1);
  });
});

describe("manager invitations", () => {
  it("retains exact recipient, revision and expiration on uncertain issue and revoke", async () => {
    const fixture = manager();
    fixture.client.issueUserEnrollment.mockRejectedValueOnce(
      new TypeError("issue response lost"),
    );
    fixture.client.revokeUserEnrollment.mockRejectedValueOnce(
      new TypeError("revoke response lost"),
    );
    mount(() => <InvitationPanel {...fixture} />);
    click("Issue invitation");
    await settle();
    expect(document.body.textContent).toContain("The result is unknown.");
    expect(fixture.onLocked).toHaveBeenLastCalledWith(true);
    click("Retry invitation");
    await settle();
    const issues = fixture.client.issueUserEnrollment.mock.calls;
    expect(issues).toHaveLength(2);
    expect(issues[1]).toEqual(issues[0]);
    expect(issues[0]?.[0]).toBe(PRINCIPAL);
    expect(issues[0]?.[1].expected_principal_revision).toBe(7);
    expect(issues[0]?.[2]).toBe(CSRF);
    expect(document.body.textContent).toContain(TOKEN);
    expect(fixture.onLocked).toHaveBeenLastCalledWith(false);
    click("Revoke invitation");
    await settle();
    expect(document.body.textContent).not.toContain("Invitation revoked.");
    click("Retry revocation");
    await settle();
    const revocations = fixture.client.revokeUserEnrollment.mock.calls;
    expect(revocations).toHaveLength(2);
    expect(revocations[1]).toEqual(revocations[0]);
    expect(revocations[0]?.[0]).toBe(issues[0]?.[1].operation_id);
    expect(revocations[0]?.[1].expected_revision).toBe(8);
    expect(document.body.textContent).toContain("Invitation revoked.");
    expect(document.body.textContent).not.toContain(TOKEN);
  });

  it("does not expose an invitation returned for another principal", async () => {
    const fixture = manager();
    fixture.client.issueUserEnrollment.mockImplementationOnce(
      async (_principal, request) => ({
        ...invitation(request.operation_id, request.expires_at_epoch_micros),
        principal_id: "00000000-0000-4000-8000-000000000009",
      }),
    );
    mount(() => <InvitationPanel {...fixture} />);
    click("Issue invitation");
    await settle();
    expect(document.body.textContent).toContain("The result is unknown.");
    expect(document.body.textContent).not.toContain(TOKEN);
  });

  it("uses session-owned step-up and retains the same factor when confirmation is unknown", async () => {
    const fixture = manager();
    fixture.stepUp.mockRejectedValueOnce(
      new TypeError("confirmation response lost"),
    );
    mount(() => <InvitationPanel {...fixture} />);
    input("Confirmation code", "123456");
    click("Confirm identity");
    await settle();
    expect(field("Confirmation code").disabled).toBe(true);
    click("Retry confirmation");
    await settle();
    expect(fixture.stepUp.mock.calls).toEqual([
      [{ method: "totp", code: "123456" }],
      [{ method: "totp", code: "123456" }],
    ]);
    expect(document.body.textContent).toContain("Identity confirmed.");
    expect(field("Confirmation code").value).toBe("");
  });
});

function recipient() {
  return {
    client: {
      redeemUserEnrollmentApiKey: vi.fn<
        MeshSpanFetchClient["redeemUserEnrollmentApiKey"]
      >(async (request) => keyReceipt(request.operation_id)),
    },
    signIn: vi.fn<(key: string) => Promise<void>>(async () => undefined),
  };
}

function manager() {
  const principal: ListPrincipalsResponse["principals"][number] = {
    principal_id: PRINCIPAL,
    kind: "user",
    display_name: "Bob",
    state: "active",
    revision: 7,
    created_at_epoch_micros: 1,
  };
  return {
    client: {
      issueUserEnrollment: vi.fn<InvitationClient["issueUserEnrollment"]>(
        async (_principal, request) =>
          invitation(request.operation_id, request.expires_at_epoch_micros),
      ),
      revokeUserEnrollment: vi.fn<InvitationClient["revokeUserEnrollment"]>(
        async (enrollmentId, request) => ({
          operation_id: request.operation_id,
          enrollment_operation_id: enrollmentId,
          committed_revision: 9,
        }),
      ),
    },
    csrfToken: CSRF,
    principal,
    onLocked: vi.fn<(locked: boolean) => void>(),
    stepUp: vi.fn<
      (
        factor: Readonly<{ method: "totp" | "recovery_code"; code: string }>,
      ) => Promise<void>
    >(async () => undefined),
  };
}

function invitation(
  operation: string,
  expiry: number,
): IssueUserEnrollmentResponse {
  return {
    operation_id: operation,
    principal_id: PRINCIPAL,
    token: TOKEN,
    expires_at_epoch_micros: expiry,
    committed_revision: 8,
  };
}

function keyReceipt(operation: string): CreateApiKeyResponse {
  return {
    operation_id: operation,
    secret: KEY,
    method_id: PRINCIPAL,
    key_id: "c".repeat(32),
    scopes: ["https_session", "headless_api"],
    created_at_epoch_micros: 1,
    valid_from_epoch_micros: 1,
    expires_at_epoch_micros: null,
  };
}

function mount(component: () => JSX.Element): void {
  const root = document.createElement("div");
  document.body.append(root);
  mounted.add(render(component, root));
}

function field(label: string): HTMLInputElement {
  const result = [...document.querySelectorAll("label")]
    .find((candidate) => candidate.textContent.includes(label))
    ?.querySelector("input");
  if (result === null || result === undefined)
    throw new TypeError(`Missing input ${label}`);
  return result;
}

function input(label: string, value: string): void {
  const element = field(label);
  element.value = value;
  element.dispatchEvent(new InputEvent("input", { bubbles: true }));
  flush();
}

function click(label: string): void {
  const button = [...document.querySelectorAll("button")].find(
    (candidate) => candidate.textContent.trim() === label,
  );
  if (button === undefined) throw new TypeError(`Missing button ${label}`);
  button.click();
  flush();
}

async function settle(): Promise<void> {
  for (let turn = 0; turn < 8; turn += 1) {
    await Promise.resolve();
    flush();
  }
}
