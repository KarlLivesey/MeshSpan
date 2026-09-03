// SPDX-License-Identifier: GPL-2.0-only

import { describe, expect, it } from "vitest";

import { buildCertificateRequest } from "../src/features/certificate-administration/certificate-request";

const OPERATION_ID = "00000000-0000-4000-8000-000000000003";

describe("certificate request construction", () => {
  it("canonicalises and de-duplicates names without redefining contract validation", () => {
    const form = baseForm("http01");
    form.set(
      "certificate_names",
      " B.example.test., a.example.test\na.example.test ",
    );

    expect(buildCertificateRequest(form, OPERATION_ID)).toEqual({
      certificate_names: ["a.example.test", "b.example.test"],
      challenge: { kind: "http01" },
      directory_url: "https://acme.example.test/directory",
      operation_id: OPERATION_ID,
    });
  });

  it("keeps RFC 2136 credentials in the selected challenge only", () => {
    const form = baseForm("dns01_rfc2136");
    form.set("rfc2136_algorithm", "hmac_sha512");
    form.set("rfc2136_key_name", "ACME-KEY.EXAMPLE.TEST.");
    form.set("rfc2136_secret", "printable-secret-material");
    form.set("rfc2136_server", "192.0.2.53:53");
    form.set("rfc2136_zone", "EXAMPLE.TEST.");

    expect(buildCertificateRequest(form, OPERATION_ID).challenge).toEqual({
      algorithm: "hmac_sha512",
      key_name: "acme-key.example.test",
      kind: "dns01_rfc2136",
      secret: "printable-secret-material",
      server: "192.0.2.53:53",
      zone: "example.test",
    });
  });

  it("constructs manual, Cloudflare and webhook challenges exactly", () => {
    expect(
      buildCertificateRequest(baseForm("dns01_manual"), OPERATION_ID).challenge,
    ).toEqual({ kind: "dns01_manual" });

    const cloudflare = baseForm("dns01_cloudflare");
    cloudflare.set("cloudflare_api_token", "scoped-cloudflare-token");
    cloudflare.set("cloudflare_zone_id", "ABCDEF0123456789ABCDEF0123456789");
    expect(buildCertificateRequest(cloudflare, OPERATION_ID).challenge).toEqual(
      {
        api_token: "scoped-cloudflare-token",
        kind: "dns01_cloudflare",
        zone_id: "abcdef0123456789abcdef0123456789",
      },
    );

    const webhook = baseForm("dns01_webhook");
    webhook.set("webhook_bearer_token", "webhook-bearer-token");
    webhook.set("webhook_endpoint", "https://dns.example.test/acme");
    expect(buildCertificateRequest(webhook, OPERATION_ID).challenge).toEqual({
      bearer_token: "webhook-bearer-token",
      endpoint: "https://dns.example.test/acme",
      kind: "dns01_webhook",
    });
  });
});

function baseForm(kind: string): FormData {
  const form = new FormData();
  form.set("certificate_names", "files.example.test");
  form.set("challenge_kind", kind);
  form.set("directory_url", "https://acme.example.test/directory");
  return form;
}
