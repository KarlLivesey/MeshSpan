// SPDX-License-Identifier: GPL-2.0-only
// @vitest-environment jsdom

import { render } from "@solidjs/web";
import { flush } from "solid-js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { MeshLocalCertificateForm } from "../src/features/certificate-administration/MeshLocalCertificateForm";
import { createMeshSpanFetchClient } from "../src/generated/fetch.gen";
import type { ProvisionMeshLocalCertificateResponse } from "../src/generated";

const ID = "11111111-1111-4111-8111-111111111111";
const CSRF = `meshspan-csrf-v1.${"5".repeat(32)}.${"6".repeat(64)}`;
const TRUST = `-----BEGIN CERTIFICATE-----\n${"A".repeat(80)}\n-----END CERTIFICATE-----\n`;
const created = vi.fn<(blob: Blob) => string>(() => "blob:local-ca-test");
const revoked = vi.fn<(url: string) => void>();
const disposals = new Set<() => void>();

class DownloadURL extends URL {
  static override readonly createObjectURL = created;
  static override readonly revokeObjectURL = revoked;
}

beforeEach(() => {
  vi.stubGlobal("URL", DownloadURL);
  vi.spyOn(crypto, "randomUUID").mockReturnValue(ID);
});
afterEach(() => {
  for (const dispose of disposals) dispose();
  disposals.clear();
  document.body.replaceChildren();
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  vi.clearAllMocks();
});

function response(operationId = ID): ProvisionMeshLocalCertificateResponse {
  return {
    operation_id: operationId,
    authority_id: ID,
    certificate_id: ID,
    issuance_id: ID,
    certificate_names: ["files.internal", "meshspan.local"],
    generation: "1",
    not_before_epoch_micros: 100,
    not_after_epoch_micros: 200,
    public_key_fingerprint: "a".repeat(64),
    revision: 3,
    trust_anchor_pem: TRUST,
  };
}

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status: 201,
    headers: {
      "Content-Type": "application/json",
      "MeshSpan-API-Version": "latest",
      "MeshSpan-API-Schema": `sha256:${"a".repeat(64)}`,
    },
  });
}

function mount(fetcher: typeof fetch): () => void {
  const client = createMeshSpanFetchClient({
    baseUrl: "https://node.example/api/latest/",
    fetch: fetcher,
  });
  const root = document.createElement("div");
  document.body.append(root);
  const dispose = render(
    () => <MeshLocalCertificateForm client={client} csrfToken={CSRF} />,
    root,
  );
  disposals.add(dispose);
  return dispose;
}

function submit(): void {
  const input = document.querySelector("textarea");
  const form = document.querySelector("form");
  if (!input || !form) throw new TypeError("Missing local certificate form");
  input.value = "MeshSpan.local., files.internal, meshspan.local";
  input.dispatchEvent(new InputEvent("input", { bubbles: true }));
  flush();
  form.dispatchEvent(
    new SubmitEvent("submit", { bubbles: true, cancelable: true }),
  );
  flush();
}

async function blobText(blob: Blob): Promise<string> {
  return new Promise((resolve, reject) => {
    const reader = new FileReader();
    reader.onload = (): void => {
      if (typeof reader.result === "string") resolve(reader.result);
      else reject(new TypeError("Expected certificate text"));
    };
    reader.onerror = (): void => {
      reject(reader.error ?? new Error("Certificate read failed"));
    };
    reader.readAsText(blob);
  });
}

function assertProvisionRequest(
  call: Parameters<typeof fetch> | undefined,
): void {
  if (!call) throw new TypeError("Expected a provisioning request");
  const [input, init] = call;
  expect(input instanceof Request ? input.url : input.toString()).toBe(
    "https://node.example/api/latest/admin/certificates/local",
  );
  expect(init?.method).toBe("POST");
  expect(new Headers(init?.headers).get("MeshSpan-CSRF-Token")).toBe(CSRF);
  const body: unknown = JSON.parse(
    typeof init?.body === "string" ? init.body : "null",
  );
  expect(body).toEqual({
    certificate_names: ["files.internal", "meshspan.local"],
    operation_id: ID,
  });
}

describe("mesh-local trust download", () => {
  it("sends canonical names and CSRF, then offers only the validated public anchor", async () => {
    const fetcher = vi.fn<typeof fetch>(async () => jsonResponse(response()));
    const dispose = mount(fetcher);
    expect(fetcher).not.toHaveBeenCalled();
    submit();
    await vi.waitFor(() => {
      flush();
      expect(created).toHaveBeenCalledOnce();
    });
    assertProvisionRequest(fetcher.mock.calls[0]);
    const anchor = document.querySelector("a[download]");
    expect(anchor?.getAttribute("href")).toBe("blob:local-ca-test");
    expect(anchor?.getAttribute("download")).toBe("meshspan-local-ca.pem");
    expect(document.body.textContent).toContain(
      "Gateway installation is reported separately",
    );
    const blob = created.mock.calls[0]?.[0];
    expect(blob?.type).toBe("application/x-pem-file");
    if (!blob) throw new TypeError("Missing trust download");
    expect(await blobText(blob)).toBe(TRUST);
    dispose();
    disposals.delete(dispose);
    expect(revoked).toHaveBeenCalledWith("blob:local-ca-test");
  });
});

describe("mesh-local request and response failures", () => {
  it("keeps one operation identity after an uncertain result and rejects unknown response data", async () => {
    const bodies: unknown[] = [];
    const fetcher = vi.fn<typeof fetch>(async (_input, init) => {
      bodies.push(
        JSON.parse(typeof init?.body === "string" ? init.body : "null"),
      );
      if (bodies.length === 1) throw new TypeError("Connection lost");
      return jsonResponse({ ...response(), private_key: "must-not-pass" });
    });
    mount(fetcher);
    submit();
    await vi.waitFor(() => {
      flush();
      expect(document.body.textContent).toContain("was not confirmed");
    });
    submit();
    await vi.waitFor(() => {
      flush();
      expect(fetcher).toHaveBeenCalledTimes(2);
      expect(document.body.textContent).toContain("was not confirmed");
    });
    expect(bodies[1]).toEqual(bodies[0]);
    expect(created).not.toHaveBeenCalled();
    expect(document.querySelector("a[download]")).toBeNull();
  });

  it("rejects invalid requests before invoking fetch", async () => {
    const fetcher = vi.fn<typeof fetch>();
    const client = createMeshSpanFetchClient({
      baseUrl: "https://node.example/api/latest/",
      fetch: fetcher,
    });
    await expect(
      client.provisionMeshLocalCertificate({
        operation_id: ID,
        certificate_names: [],
      }),
    ).rejects.toThrow();
    expect(fetcher).not.toHaveBeenCalled();
  });

  it("never offers a valid response belonging to another operation", async () => {
    mount(async () =>
      jsonResponse(response("22222222-2222-4222-8222-222222222222")),
    );
    submit();
    await vi.waitFor(() => {
      flush();
      expect(document.body.textContent).toContain("was not confirmed");
    });
    expect(created).not.toHaveBeenCalled();
  });

  it("ignores a response after the panel has been closed", async () => {
    const deferred = Promise.withResolvers<Response>();
    const fetcher = vi.fn<typeof fetch>(async () => deferred.promise);
    const dispose = mount(fetcher);
    submit();
    dispose();
    disposals.delete(dispose);
    deferred.resolve(jsonResponse(response()));
    await deferred.promise;
    await Promise.resolve();
    flush();
    expect(created).not.toHaveBeenCalled();
  });
});
