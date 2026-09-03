// SPDX-License-Identifier: GPL-2.0-only

import { render } from "@solidjs/web";
import { flush } from "solid-js";
import { afterEach, describe, expect, it, vi } from "vitest";

import { CertificateAdministrationPanel } from "../src/features/certificate-administration/CertificateAdministrationPanel";
import type { CertificateAdministrationClient } from "../src/features/certificate-administration/model";

const CSRF_TOKEN = `meshspan-csrf-v1.${"5".repeat(32)}.${"6".repeat(64)}`;
const disposals = new Set<() => void>();

afterEach(() => {
  for (const dispose of disposals) dispose();
  disposals.clear();
  document.body.replaceChildren();
});

describe("certificate administration panel", () => {
  it("queues HTTP-01 and shows exact manual DNS work", async () => {
    const provisionCertificate = vi.fn<
      CertificateAdministrationClient["provisionCertificate"]
    >(async (request) => ({
      certificate_names: request.certificate_names,
      configuration_id: "00000000-0000-4000-8000-000000000004",
      operation_id: request.operation_id,
      order_id: "00000000-0000-4000-8000-000000000002",
      revision: 3,
    }));
    const listManualDnsTasks = vi.fn<
      CertificateAdministrationClient["listManualDnsTasks"]
    >(async () => ({ next_page_url: null, tasks: [manualDnsTask()] }));
    mount({
      listManualDnsTasks,
      listNextManualDnsTasks: async () => ({
        next_page_url: null,
        tasks: [],
      }),
      provisionCertificate,
    });
    await settle();

    enter("DNS names", "B.example.test., a.example.test");
    click("Request certificate");
    await settle();

    expect(provisionCertificate).toHaveBeenCalledWith(
      expect.objectContaining({
        certificate_names: ["a.example.test", "b.example.test"],
        challenge: { kind: "http01" },
      }),
      CSRF_TOKEN,
    );
    expect(listManualDnsTasks).toHaveBeenCalledTimes(2);
    expect(document.body.textContent).toContain(
      "_acme-challenge.files.example.test",
    );
    expect(document.body.textContent).toContain("challenge_value");
  });
});

function mount(client: CertificateAdministrationClient): void {
  const root = document.createElement("div");
  document.body.append(root);
  disposals.add(
    render(
      () => (
        <CertificateAdministrationPanel
          client={client}
          csrfToken={CSRF_TOKEN}
        />
      ),
      root,
    ),
  );
}

function manualDnsTask() {
  return {
    action: "publish" as const,
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

function enter(label: string, value: string): void {
  const input = labelledTextArea(label);
  input.value = value;
  input.dispatchEvent(new InputEvent("input", { bubbles: true }));
  flush();
}

function labelledTextArea(label: string): HTMLTextAreaElement {
  const element = [...document.querySelectorAll("label")]
    .find((candidate) => candidate.textContent.includes(label))
    ?.querySelector("textarea");
  if (element === undefined || element === null) {
    throw new TypeError(`expected ${label}`);
  }
  return element;
}

function click(label: string): void {
  const element = [...document.querySelectorAll<HTMLElement>("button")].find(
    (candidate) => candidate.textContent.trim().includes(label),
  );
  if (element === undefined) throw new TypeError(`expected ${label}`);
  element.click();
  flush();
}

async function settle(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
  flush();
}
