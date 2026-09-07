// SPDX-License-Identifier: GPL-2.0-only

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import {
  assemblePackage,
  dependencyInventory,
  packageBuildSteps,
  packageOptions,
  sha256,
} from "./local-package.mjs";

const host = "aarch64-apple-darwin";

test("local packaging validates target/profile and has no publication commands", () => {
  const options = packageOptions(["--profile", "dev", "--plan"], host);
  assert.deepEqual(options, { target: host, profile: "dev", plan: true });
  const steps = packageBuildSteps(options, host);
  assert.deepEqual(steps[1], [
    "cargo",
    [
      "build",
      "--locked",
      "--offline",
      "-p",
      "meshspan-daemon",
      "--profile",
      "dev",
    ],
  ]);
  const cross = packageBuildSteps(
    packageOptions(["--target", "x86_64-unknown-linux-musl"], host),
    host,
  );
  assert.deepEqual(cross[1][1].slice(-4), [
    "--target",
    "x86_64-unknown-linux-musl",
    "--profile",
    "release",
  ]);
  for (const arguments_ of [
    ["--publish"],
    ["--target", "../outside"],
    ["--profile", "fast"],
    ["--output"],
    ["--plan", "--plan"],
    ["--target", "--plan"],
  ]) {
    assert.throws(() => packageOptions(arguments_, host));
  }
});

test("inventory follows normal/build closure, excludes tests and removes local paths", () => {
  const packages = ["meshspan-daemon", "normal", "build", "test-only"].map(
    (name) => ({
      id: name,
      name,
      version: "1.0.0",
      license: "MIT",
      manifest_path: "/private/never-publish",
    }),
  );
  const deps = [
    { pkg: "normal", dep_kinds: [{ kind: null }] },
    { pkg: "build", dep_kinds: [{ kind: "build" }] },
    { pkg: "test-only", dep_kinds: [{ kind: "dev" }] },
  ];
  const nodes = packages.map(({ id }) => ({
    id,
    features: [],
    deps: id === "meshspan-daemon" ? deps : [],
  }));
  const inventory = dependencyInventory(
    { packages, resolve: { nodes } },
    {
      MIT: [
        {
          name: "web-package",
          versions: ["4.0.0"],
          license: "MIT",
          path: "/private/another",
        },
      ],
    },
  );
  assert.deepEqual(
    inventory.rust.map(({ name }) => name),
    ["build", "meshspan-daemon", "normal"],
  );
  assert.deepEqual(inventory.web, [
    { name: "web-package", version: "4.0.0", licence: "MIT" },
  ]);
  assert.ok(!JSON.stringify(inventory).includes("/private"));
  assert.throws(
    () => dependencyInventory({ packages: [], resolve: { nodes } }, {}),
    /Missing daemon/,
  );
});

test("assembly preserves exact bytes, hashes every shipped file and never overwrites", async (context) => {
  const root = await mkdtemp(join(tmpdir(), "meshspan-package-proof-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, "packaging"));
  for (const file of [
    "LICENSE",
    "packaging/RUNNING.md",
    "packaging/Dockerfile",
  ]) {
    await writeFile(join(root, file), `fixture ${file}\n`);
  }
  const binary = join(root, "input-binary");
  await writeFile(binary, "independent executable fixture\n");
  const inputs = {
    repository: root,
    output: join(root, "output"),
    binary,
    provenance: { version: "0.1.0", target: host, profile: "dev" },
    inventory: { rust: [], web: [] },
  };
  const first = await assemblePackage(inputs);
  const second = await assemblePackage(inputs);
  assert.notEqual(first.directory, second.directory);
  assert.equal(
    await readFile(join(first.bundle, "bin/meshspan-daemon"), "utf8"),
    "independent executable fixture\n",
  );
  const lines = (await readFile(join(first.bundle, "SHA256SUMS"), "utf8"))
    .trim()
    .split("\n");
  assert.equal(lines.length, 6);
  for (const line of lines) {
    const [expected, file] = line.split("  ");
    const actual = createHash("sha256")
      .update(await readFile(join(first.bundle, file)))
      .digest("hex");
    assert.equal(expected, actual);
  }
  const provenance = JSON.parse(
    await readFile(join(first.bundle, "provenance.json"), "utf8"),
  );
  assert.equal(provenance.licence, "GPL-2.0-only");
  assert.equal(provenance.publication, "prohibited");
  assert.equal(provenance.acceptance, "not established by packaging");
  const before = await sha256(binary);
  await writeFile(binary, "changed\n");
  assert.notEqual(await sha256(binary), before);
  await assert.rejects(
    assemblePackage({
      ...inputs,
      provenance: { ...inputs.provenance, profile: "../../outside" },
    }),
    /Invalid package identity/,
  );
});
