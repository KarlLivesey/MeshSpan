// SPDX-License-Identifier: GPL-2.0-only

import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import {
  mkdir,
  mkdtemp,
  readFile,
  rm,
  symlink,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { dependencyInventory } from "./local-package.mjs";
import {
  collectPackageNotices,
  renderPackageNotices,
} from "./package-notices.mjs";
import { packageSbom } from "./package-sbom.mjs";

async function fixture(context) {
  const root = await mkdtemp(join(tmpdir(), "meshspan-notice-proof-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  await mkdir(join(root, "dependency", "LICENSES"), { recursive: true });
  await mkdir(join(root, "web"));
  await writeFile(join(root, "LICENSE"), "MeshSpan licence fixture\n");
  await writeFile(
    join(root, "dependency", "LICENSES", "MIT.txt"),
    "Upstream © notice\r\n",
  );
  await writeFile(join(root, "web", "LICENSE"), "Web notice\n");
  await writeFile(
    join(root, "web", "package.json"),
    JSON.stringify({ name: "web-fixture", version: "2.0.0" }),
  );
  const packages = [
    {
      id: "daemon",
      name: "meshspan-daemon",
      version: "0.1.0",
      license: "GPL-2.0-only",
      manifest_path: join(root, "Cargo.toml"),
    },
    {
      id: "dependency",
      name: "dependency",
      version: "1.0.0",
      license: "MIT",
      manifest_path: join(root, "dependency", "Cargo.toml"),
    },
  ];
  return {
    repository: root,
    metadata: {
      packages,
      workspace_members: ["daemon"],
      resolve: {
        nodes: [
          {
            id: "daemon",
            features: [],
            deps: [{ pkg: "dependency", dep_kinds: [{ kind: null }] }],
          },
          { id: "dependency", features: [], deps: [] },
        ],
      },
    },
    javascript: {
      MIT: [
        {
          name: "web-fixture",
          versions: ["2.0.0"],
          license: "MIT",
          paths: [join(root, "web")],
        },
      ],
    },
  };
}

test("source notices retain upstream bytes and nested licence files without local paths", async (context) => {
  const inputs = await fixture(context);
  const records = await collectPackageNotices(inputs);
  assert.equal(records.length, 3);
  const notice = records.find((item) => item.name === "dependency").notices[0];
  const bytes = await readFile(
    join(inputs.repository, "dependency", "LICENSES", "MIT.txt"),
  );
  assert.equal(notice.text, "Upstream © notice\r\n");
  assert.equal(notice.sha256, createHash("sha256").update(bytes).digest("hex"));
  assert.equal(notice.file, "LICENSES/MIT.txt");
  const rendered = renderPackageNotices(records);
  assert.ok(rendered.includes("Upstream © notice\r\n"));
  assert.ok(!rendered.includes(inputs.repository));
});

test("notices refuse missing sources, package substitution and escaping symlinks", async (context) => {
  const inputs = await fixture(context);
  const licence = join(inputs.repository, "dependency", "LICENSES", "MIT.txt");
  await rm(licence);
  await assert.rejects(
    collectPackageNotices(inputs),
    /No upstream licence notice/,
  );
  await symlink(join(inputs.repository, "LICENSE"), licence);
  await assert.rejects(collectPackageNotices(inputs), /escapes its source/);
  await rm(licence);
  await writeFile(licence, "Restored upstream notice\n");
  inputs.javascript.MIT[0].name = "substituted";
  await assert.rejects(collectPackageNotices(inputs), /identity mismatch/);
});

test("SBOM records exact component closure, dependency edges, notices and executable identity", async (context) => {
  const inputs = await fixture(context);
  const notices = await collectPackageNotices(inputs);
  const options = {
    metadata: inputs.metadata,
    inventory: dependencyInventory(inputs.metadata, inputs.javascript),
    notices,
    provenance: {
      version: "0.1.0",
      target: "aarch64-apple-darwin",
      sourceCommit: "a".repeat(40),
    },
    binarySha256: "b".repeat(64),
  };
  const sbom = packageSbom(options);
  assert.equal(sbom.bomFormat, "CycloneDX");
  assert.equal(sbom.specVersion, "1.6");
  assert.equal(sbom.metadata.component.licenses[0].license.id, "GPL-2.0-only");
  assert.deepEqual(sbom.metadata.component.hashes, [
    { alg: "SHA-256", content: "b".repeat(64) },
  ]);
  assert.deepEqual(
    sbom.dependencies.find(
      (item) => item.ref === "cargo:meshspan-daemon@0.1.0",
    ),
    {
      ref: "cargo:meshspan-daemon@0.1.0",
      dependsOn: ["cargo:dependency@1.0.0"],
    },
  );
  assert.equal(sbom.components.length, 3);
  assert.equal(sbom.compositions[0].aggregate, "incomplete");
  assert.ok(!JSON.stringify(sbom).includes(inputs.repository));
  assert.throws(
    () => packageSbom({ ...options, notices: notices.slice(1) }),
    /exact dependency inventory/,
  );
  assert.throws(
    () => packageSbom({ ...options, binarySha256: "invalid" }),
    /SHA-256/,
  );
});

test("recovered upstream notices bind the exact reviewed package and source", async (context) => {
  const inputs = await fixture(context);
  await rm(join(inputs.repository, "dependency", "LICENSES", "MIT.txt"));
  const dependency = inputs.metadata.packages[1];
  Object.assign(dependency, {
    name: "asn1-rs-impl",
    version: "0.2.0",
    license: "MIT/Apache-2.0",
    repository: "https://github.com/rusticata/asn1-rs.git",
  });
  await mkdir(join(inputs.repository, "packaging", "notices"), {
    recursive: true,
  });
  await writeFile(
    join(
      inputs.repository,
      "packaging",
      "notices",
      "asn1-rs-impl-0.2.0-MIT.txt",
    ),
    "Recovered upstream fixture\n",
  );
  const records = await collectPackageNotices(inputs);
  const recovered = records.find((item) => item.name === "asn1-rs-impl");
  assert.equal(recovered.notices[0].text, "Recovered upstream fixture\n");
  assert.ok(
    recovered.notices[0].upstream.includes(
      "a20e5f7319c896737ad0f2557037817b91ad854f",
    ),
  );
  dependency.version = "0.3.0";
  await assert.rejects(
    collectPackageNotices(inputs),
    /No upstream licence notice/,
  );
});
