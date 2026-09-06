// SPDX-License-Identifier: GPL-2.0-only

import type { ProvisionCertificateRequest } from "../../generated";

export type CertificateChallengeKind =
  ProvisionCertificateRequest["challenge"]["kind"];

export function buildCertificateRequest(
  form: FormData,
  operationId: string,
): ProvisionCertificateRequest {
  return {
    certificate_names: readCertificateNames(
      readText(form, "certificate_names"),
    ),
    challenge: readChallenge(form),
    directory_url: readText(form, "directory_url").trim(),
    operation_id: operationId,
  };
}

function readChallenge(
  form: FormData,
): ProvisionCertificateRequest["challenge"] {
  const kind = readText(form, "challenge_kind");
  if (kind === "http01" || kind === "dns01_manual") return { kind };
  if (kind === "dns01_cloudflare") {
    return {
      api_token: readText(form, "cloudflare_api_token"),
      kind,
      zone_id: readText(form, "cloudflare_zone_id").trim().toLowerCase(),
    };
  }
  if (kind === "dns01_webhook") {
    return {
      bearer_token: readText(form, "webhook_bearer_token"),
      endpoint: readText(form, "webhook_endpoint").trim(),
      kind,
    };
  }
  if (kind === "dns01_rfc2136") return readRfc2136Challenge(form);
  throw new TypeError("Choose a supported certificate challenge method.");
}

function readRfc2136Challenge(
  form: FormData,
): ProvisionCertificateRequest["challenge"] {
  const algorithm = readText(form, "rfc2136_algorithm");
  if (algorithm !== "hmac_sha256" && algorithm !== "hmac_sha512") {
    throw new TypeError("Choose a supported RFC 2136 TSIG algorithm.");
  }
  return {
    algorithm,
    key_name: canonicalDnsName(readText(form, "rfc2136_key_name")),
    kind: "dns01_rfc2136",
    secret: readText(form, "rfc2136_secret"),
    server: readText(form, "rfc2136_server").trim(),
    zone: canonicalDnsName(readText(form, "rfc2136_zone")),
  };
}

/** Normalises form input; the generated schema and server still validate the request. */
export function readCertificateNames(value: string): string[] {
  const names = value
    .split(/[\s,]+/u)
    .map(canonicalDnsName)
    .filter((name) => name.length > 0);
  return [...new Set(names)].toSorted((left, right) =>
    left.localeCompare(right),
  );
}

function canonicalDnsName(value: string): string {
  return value.trim().replace(/\.$/u, "").toLowerCase();
}

function readText(form: FormData, name: string): string {
  const value = form.get(name);
  if (typeof value !== "string") throw new TypeError(`Missing ${name}.`);
  return value;
}
