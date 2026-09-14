// SPDX-License-Identifier: GPL-2.0-only

import { dependencyPackages } from "./local-package.mjs";

/** CycloneDX 1.6 source-package inventory, deliberately not a linked-symbol claim. */
export function packageSbom({
  metadata,
  inventory,
  notices,
  provenance,
  binarySha256,
}) {
  const selected = dependencyPackages(metadata);
  const references = new Map(
    selected.map((item) => [item.id, reference("cargo", item)]),
  );
  if (new Set(references.values()).size !== selected.length)
    throw new Error("Ambiguous Cargo package identities in SBOM");
  const components = notices.map(component);
  const expected = [
    ...inventory.rust.map((item) => reference("cargo", item)),
    ...inventory.web.map((item) => reference("npm", item)),
  ].sort();
  const actual = components.map((item) => item["bom-ref"]).sort();
  if (JSON.stringify(expected) !== JSON.stringify(actual))
    throw new Error("SBOM notices do not cover the exact dependency inventory");
  if (!/^[a-f0-9]{64}$/.test(binarySha256))
    throw new Error("SBOM requires the exact executable SHA-256");
  const dependencies = metadata.resolve.nodes
    .filter((node) => references.has(node.id))
    .map((node) => ({
      ref: references.get(node.id),
      dependsOn: [
        ...new Set(
          node.deps
            .filter((edge) =>
              edge.dep_kinds.some((kind) => kind.kind !== "dev"),
            )
            .map((edge) => references.get(edge.pkg)),
        ),
      ].sort(),
    }));
  return {
    bomFormat: "CycloneDX",
    specVersion: "1.6",
    version: 1,
    metadata: {
      component: {
        type: "application",
        "bom-ref": "meshspan-artifact",
        name: "MeshSpan",
        version: provenance.version,
        hashes: [{ alg: "SHA-256", content: binarySha256 }],
        licenses: [{ license: { id: "GPL-2.0-only" } }],
        properties: [
          { name: "meshspan:target", value: provenance.target },
          { name: "meshspan:source-commit", value: provenance.sourceCommit },
          { name: "meshspan:inventory-scope", value: inventory.scope },
          { name: "meshspan:publication", value: "prohibited" },
        ],
      },
    },
    components,
    dependencies,
    compositions: [
      { aggregate: "incomplete", assemblies: ["meshspan-artifact"] },
    ],
  };
}

function component(record) {
  if (typeof record.licence !== "string" || record.licence.length === 0)
    throw new Error("SBOM package has no declared licence");
  return {
    type: "library",
    "bom-ref": reference(record.ecosystem, record),
    name: record.name,
    version: record.version,
    // Preserve Cargo's legacy slash expressions as upstream text, not invalid SPDX syntax.
    licenses: [{ license: { name: record.licence } }],
    properties: record.notices.map((notice) => ({
      name: `meshspan:notice-sha256:${notice.file}`,
      value: notice.sha256,
    })),
  };
}

function reference(ecosystem, item) {
  return `${ecosystem}:${item.name}@${item.version}`;
}
