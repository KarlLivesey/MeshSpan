// SPDX-License-Identifier: GPL-2.0-only
// @vitest-environment jsdom

import { render } from "@solidjs/web";
import { flush } from "solid-js";
import { afterEach, describe, expect, it, vi } from "vitest";

import { OperationAdministrationPanel } from "../src/features/operation-administration/OperationAdministrationPanel";
import type { OperationAdministrationClient } from "../src/features/operation-administration/model";
import type { MetricsClient } from "../src/features/metrics-administration/model";

const operationId = "00000000-0000-4000-8000-000000000001";
const disposals = new Set<() => void>();

afterEach(() => {
  for (const dispose of disposals) dispose();
  disposals.clear();
  document.body.replaceChildren();
});

describe("operation administration panel", () => {
  it("shows committed status and follows the server-provided next page", async () => {
    const listNextOperations = vi.fn<
      OperationAdministrationClient["listNextOperations"]
    >(async () => ({ next_page_url: null, operations: [] }));
    const client: OperationAdministrationClient & MetricsClient = {
      getMetricsExporter: async () => ({ configuration: null }),
      configureMetricsExporter:
        vi.fn<MetricsClient["configureMetricsExporter"]>(),
      listUsers: vi.fn<MetricsClient["listUsers"]>(),
      listNextPrincipals: vi.fn<MetricsClient["listNextPrincipals"]>(),
      readDiagnosticsBundle:
        vi.fn<OperationAdministrationClient["readDiagnosticsBundle"]>(),
      listNextOperations,
      listOperations: async () => ({
        next_page_url:
          "/api/latest/admin/operations?limit=50&cursor=v1.1.proof",
        operations: [
          {
            cancellation_available: false,
            completed_at_epoch_micros: 2_000_000,
            failure: null,
            kind: "metadata_mutation",
            operation_id: operationId,
            progress: null,
            result_url: null,
            revision: 1,
            started_at_epoch_micros: 1_000_000,
            state: "succeeded",
            status_url: `/api/latest/operations/${operationId}`,
            updated_at_epoch_micros: 2_000_000,
          },
        ],
      }),
    };
    const root = document.createElement("div");
    document.body.append(root);
    disposals.add(
      render(
        () => <OperationAdministrationPanel client={client} csrfToken="" />,
        root,
      ),
    );
    await settle();

    expect(document.body.textContent).toContain("metadata mutation");
    expect(document.body.textContent).toContain("succeeded");
    click("Load more operations");
    await settle();

    expect(listNextOperations).toHaveBeenCalledWith(
      "/api/latest/admin/operations?limit=50&cursor=v1.1.proof",
    );
  });
});

function click(label: string): void {
  const button = [...document.querySelectorAll("button")].find(
    (candidate) => candidate.textContent.trim() === label,
  );
  if (button === undefined) throw new TypeError(`expected button: ${label}`);
  button.click();
  flush();
}

async function settle(): Promise<void> {
  await Promise.resolve();
  await Promise.resolve();
  flush();
}
