// SPDX-License-Identifier: GPL-2.0-only

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { createHash, generateKeyPairSync, sign } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import { prepareUpdate } from "./prepare-update-local.mjs";
import {
  decodeCandidate,
  encodeCandidate,
  publicKeySec1,
  signCandidate,
  verifyCandidate,
} from "./update-candidate.mjs";

const target = "aarch64-apple-darwin";
const executable = Buffer.from("independent candidate executable fixture\n");
const compatibility = {
  private_protocol_major: 1,
  partition_schema_min: 90,
  partition_schema_max: 90,
  partition_schema_target: 91,
  rollback_supported: false,
};

function manifest() {
  return {
    format: 1,
    licence: "GPL-2.0-only",
    version: "0.1.0",
    source_commit: "a".repeat(40),
    api_sha256: "b".repeat(64),
    compatibility,
    artifacts: [
      {
        target,
        size: executable.length.toString(),
        sha256: createHash("sha256").update(executable).digest("hex"),
      },
    ],
  };
}

function keys() {
  return generateKeyPairSync("ec", { namedCurve: "prime256v1" });
}

test("candidate signature binds exact bytes and the update-only domain", () => {
  const { privateKey, publicKey } = keys();
  const bytes = encodeCandidate(manifest());
  const signature = signCandidate(bytes, privateKey);
  assert.deepEqual(verifyCandidate(bytes, signature, publicKey), manifest());
  assert.equal(publicKeySec1(publicKey).length, 65);
  assert.throws(
    () => verifyCandidate(bytes, signature, keys().publicKey),
    /signature/,
  );
  assert.throws(
    () =>
      verifyCandidate(
        Buffer.concat([bytes, Buffer.from(" ")]),
        signature,
        publicKey,
      ),
    /signature/,
  );
  assert.throws(
    () => verifyCandidate(bytes, sign("sha256", bytes, privateKey), publicKey),
    /signature/,
  );
});

test("manifest refuses ambiguity, unknown fields, duplicate targets and unsupported claims", () => {
  const original = manifest();
  const bytes = encodeCandidate(original);
  assert.throws(
    () =>
      decodeCandidate(
        Buffer.from(
          bytes.toString().replace('"format":1', '"format":1,"format":1'),
        ),
      ),
    /canonical/,
  );
  assert.throws(
    () => decodeCandidate(Buffer.concat([bytes, Buffer.from("\n")])),
    /canonical/,
  );
  const invalid = [
    { ...original, unknown: true },
    { ...original, licence: "MIT" },
    { ...original, version: "00.1.0" },
    {
      ...original,
      compatibility: { ...compatibility, rollback_supported: true },
    },
    {
      ...original,
      compatibility: { ...compatibility, partition_schema_min: 92 },
    },
    { ...original, artifacts: [...original.artifacts, ...original.artifacts] },
    { ...original, artifacts: [{ ...original.artifacts[0], size: "00" }] },
    {
      ...original,
      artifacts: [{ ...original.artifacts[0], target: "../../outside" }],
    },
  ];
  for (const value of invalid) assert.throws(() => encodeCandidate(value));
});

async function packageFixture(context) {
  const root = await mkdtemp(join(tmpdir(), "meshspan-update-proof-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const bundle = join(root, "package");
  await mkdir(join(bundle, "bin"), { recursive: true });
  await writeFile(join(bundle, "bin", "meshspan-daemon"), executable);
  await writeFile(
    join(bundle, "provenance.json"),
    JSON.stringify({
      licence: "GPL-2.0-only",
      version: "0.1.0",
      target,
      sourceCommit: "a".repeat(40),
      apiSha256: "b".repeat(64),
      workingTreeDirty: false,
    }),
  );
  const pair = keys();
  const options = {
    packages: [bundle],
    compatibility,
    privateKey: pair.privateKey,
    output: join(root, "output"),
  };
  return { root, pair, options };
}

test("local assembly preserves executable bytes, signs an exact manifest and never publishes or overwrites", async (context) => {
  const { pair, options } = await packageFixture(context);
  const first = await prepareUpdate(options);
  const second = await prepareUpdate(options);
  assert.notEqual(first.directory, second.directory);
  assert.equal(first.publication, "prohibited");
  assert.equal(first.acceptance, "not established");
  const bytes = await readFile(join(first.directory, "manifest.json"));
  const signature = await readFile(join(first.directory, "manifest.sig"));
  assert.deepEqual(
    verifyCandidate(bytes, signature, pair.publicKey),
    manifest(),
  );
  assert.deepEqual(
    await readFile(join(first.directory, "artifacts", target)),
    executable,
  );
  await assert.rejects(
    prepareUpdate({
      ...options,
      packages: [options.packages[0], options.packages[0]],
    }),
    /Duplicate/,
  );
});

test(
  "Rust daemon verifies Node-signed local candidates without opening daemon state",
  {
    skip: !process.env.MESHSPAN_UPDATE_VERIFY_BINARY,
  },
  async (context) => {
    const { root, pair, options } = await packageFixture(context);
    const { directory } = await prepareUpdate(options);
    const trusted = join(root, "independently-pinned.sec1");
    await writeFile(trusted, publicKeySec1(pair.publicKey));
    const binary = join(directory, "artifacts", target);
    const arguments_ = [
      "verify-update",
      join(directory, "manifest.json"),
      join(directory, "manifest.sig"),
      trusted,
      binary,
      target,
    ];
    const execute = promisify(execFile);
    const { stdout } = await execute(
      process.env.MESHSPAN_UPDATE_VERIFY_BINARY,
      arguments_,
      { timeout: 10_000 },
    );
    const report = JSON.parse(stdout);
    assert.equal(report.verified, true);
    assert.equal(report.version, "0.1.0");
    assert.equal(report.sha256, manifest().artifacts[0].sha256);
    assert.equal(report.target, target);
    assert.equal(report.publication, "prohibited");
    await writeFile(binary, Buffer.alloc(executable.length, 42));
    await assert.rejects(
      execute(process.env.MESHSPAN_UPDATE_VERIFY_BINARY, arguments_, {
        timeout: 10_000,
      }),
      /does not match|Artifact/,
    );
    await writeFile(binary, executable);
    await writeFile(trusted, publicKeySec1(keys().publicKey));
    await assert.rejects(
      execute(process.env.MESHSPAN_UPDATE_VERIFY_BINARY, arguments_, {
        timeout: 10_000,
      }),
      /signature|Signature/,
    );
  },
);
