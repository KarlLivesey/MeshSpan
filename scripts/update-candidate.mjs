// SPDX-License-Identifier: GPL-2.0-only

import { createPublicKey, sign, verify } from "node:crypto";
import { open } from "node:fs/promises";

import { nativeTargets } from "./local-package.mjs";

const domain = Buffer.from("MeshSpan update manifest v1\0");
const maximumManifestBytes = 16 * 1_024;
const digestPattern = /^[a-f0-9]{64}$/;

/** One canonical JSON representation; unknown or duplicate fields cannot survive re-encoding. */
export function encodeCandidate(manifest) {
  validateCandidate(manifest);
  const bytes = Buffer.from(JSON.stringify(canonical(manifest)));
  if (bytes.length > maximumManifestBytes)
    throw new Error("Update manifest exceeds its size limit");
  return bytes;
}

export function decodeCandidate(bytes) {
  if (bytes.length === 0 || bytes.length > maximumManifestBytes)
    throw new Error("Invalid update manifest size");
  const manifest = JSON.parse(bytes.toString("utf8"));
  if (!encodeCandidate(manifest).equals(bytes))
    throw new Error("Update manifest must use canonical JSON");
  return manifest;
}

/** Sign only explicit local candidates; this does not tag, publish or accept a release. */
export function signCandidate(bytes, privateKey) {
  decodeCandidate(bytes);
  requireSigningKey(createPublicKey(privateKey));
  return sign("sha256", Buffer.concat([domain, bytes]), privateKey);
}

export function verifyCandidate(bytes, signature, trustedPublicKey) {
  requireSigningKey(trustedPublicKey);
  if (
    signature.length > 72 ||
    !verify(
      "sha256",
      Buffer.concat([domain, bytes]),
      trustedPublicKey,
      signature,
    )
  ) {
    throw new Error("Update candidate signature was not verified");
  }
  return decodeCandidate(bytes);
}

export function publicKeySec1(publicKey) {
  requireSigningKey(publicKey);
  const jwk = publicKey.export({ format: "jwk" });
  return Buffer.concat([
    Buffer.from([4]),
    Buffer.from(jwk.x, "base64url"),
    Buffer.from(jwk.y, "base64url"),
  ]);
}

function requireSigningKey(key) {
  if (
    key.asymmetricKeyType !== "ec" ||
    key.asymmetricKeyDetails.namedCurve !== "prime256v1"
  ) {
    throw new Error("Update signing requires a dedicated P-256 key");
  }
}

function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.keys(value)
        .sort()
        .map((key) => [key, canonical(value[key])]),
    );
  }
  return value;
}

function fields(value, names) {
  if (
    value === null ||
    typeof value !== "object" ||
    Array.isArray(value) ||
    Object.keys(value).sort().join(",") !== [...names].sort().join(",")
  ) {
    throw new Error("Unknown or missing update manifest field");
  }
}

function validateCandidate(manifest) {
  fields(manifest, [
    "format",
    "version",
    "licence",
    "source_commit",
    "api_sha256",
    "artifacts",
    "compatibility",
  ]);
  validateIdentity(manifest);
  validateCompatibility(manifest.compatibility);
  validateArtifacts(manifest.artifacts);
}

function validateIdentity(manifest) {
  if (
    manifest.format !== 1 ||
    manifest.licence !== "GPL-2.0-only" ||
    typeof manifest.version !== "string" ||
    !/^(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})\.(0|[1-9][0-9]{0,8})$/.test(
      manifest.version,
    ) ||
    typeof manifest.source_commit !== "string" ||
    !/^[a-f0-9]{40}$/.test(manifest.source_commit) ||
    typeof manifest.api_sha256 !== "string" ||
    !digestPattern.test(manifest.api_sha256)
  )
    throw new Error("Invalid update candidate identity");
}

function validateArtifacts(artifacts) {
  if (!Array.isArray(artifacts) || artifacts.length < 1 || artifacts.length > 4)
    throw new Error("Expected one to four native update artifacts");
  const targets = new Set();
  for (const artifact of artifacts) {
    validateArtifact(artifact);
    if (targets.has(artifact.target))
      throw new Error("Duplicate update target");
    targets.add(artifact.target);
  }
}

function validateCompatibility(value) {
  fields(value, [
    "private_protocol_major",
    "partition_schema_min",
    "partition_schema_max",
    "partition_schema_target",
    "rollback_supported",
  ]);
  if (value.rollback_supported !== false)
    throw new Error("Pre-1.0 candidates cannot claim rollback support");
  for (const key of [
    "private_protocol_major",
    "partition_schema_min",
    "partition_schema_max",
    "partition_schema_target",
  ]) {
    if (
      !Number.isSafeInteger(value[key]) ||
      value[key] < 1 ||
      value[key] > 4_294_967_295
    )
      throw new Error("Invalid update compatibility bound");
  }
  if (
    value.partition_schema_min > value.partition_schema_max ||
    value.partition_schema_target < value.partition_schema_max
  )
    throw new Error("Invalid update migration range");
}

function validateArtifact(value) {
  fields(value, ["target", "size", "sha256"]);
  if (
    !nativeTargets.has(value.target) ||
    typeof value.sha256 !== "string" ||
    !digestPattern.test(value.sha256) ||
    typeof value.size !== "string" ||
    !/^[1-9][0-9]{0,10}$/.test(value.size) ||
    BigInt(value.size) > 8n * 1_024n ** 3n
  )
    throw new Error("Invalid update executable identity");
}

/** Read a bounded regular file through the same handle used for the size check. */
export async function readCandidateFile(file, maximumBytes) {
  const handle = await open(file, "r");
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.size > maximumBytes)
      throw new Error("Invalid candidate input file");
    const bytes = Buffer.alloc(maximumBytes + 1);
    let length = 0;
    while (length < bytes.length) {
      const result = await handle.read(
        bytes,
        length,
        bytes.length - length,
        null,
      );
      if (result.bytesRead === 0) break;
      length += result.bytesRead;
    }
    if (length > maximumBytes)
      throw new Error("Candidate input grew beyond its bound");
    return bytes.subarray(0, length);
  } finally {
    await handle.close();
  }
}
