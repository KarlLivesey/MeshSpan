// SPDX-License-Identifier: GPL-2.0-only

import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import {
  chmod,
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  writeFile,
} from "node:fs/promises";
import { join } from "node:path";

export const nativeTargets = new Set([
  "aarch64-apple-darwin",
  "x86_64-apple-darwin",
  "aarch64-unknown-linux-musl",
  "x86_64-unknown-linux-musl",
]);

/** Local artefacts are not release candidates or evidence that acceptance passed. */
export function packageOptions(arguments_, host) {
  const options = { target: host, profile: "release", plan: false };
  const seen = new Set();
  for (let index = 0; index < arguments_.length; index += 1) {
    const flag = arguments_[index];
    if (seen.has(flag)) throw new Error(`Repeated packaging option: ${flag}`);
    seen.add(flag);
    if (flag === "--plan") {
      options.plan = true;
    } else if (["--target", "--profile", "--output"].includes(flag)) {
      const value = arguments_[++index];
      if (!value || value.startsWith("--"))
        throw new Error(`Missing value for ${flag}`);
      options[flag.slice(2)] = value;
    } else {
      throw new Error(`Unknown packaging option: ${flag}`);
    }
  }
  if (!nativeTargets.has(options.target))
    throw new Error(
      "Unsupported native target; select a documented macOS or static Linux target",
    );
  if (!["dev", "release"].includes(options.profile))
    throw new Error("Profile must be dev or release");
  return options;
}

export function packageBuildSteps(options, host) {
  const target = options.target === host ? [] : ["--target", options.target];
  return [
    [process.execPath, ["web/node_modules/vite/bin/vite.js", "build", "web"]],
    [
      "cargo",
      [
        "build",
        "--locked",
        "--offline",
        "-p",
        "meshspan-daemon",
        ...target,
        "--profile",
        options.profile,
      ],
    ],
  ];
}

/** A conservative dependency inventory, not a claim about individual linked symbols. */
export function dependencyInventory(metadata, javascript) {
  const root = metadata.packages.find(
    (item) => item.name === "meshspan-daemon",
  );
  if (!root || !metadata.resolve)
    throw new Error("Missing daemon dependency graph");
  const nodes = new Map(metadata.resolve.nodes.map((item) => [item.id, item]));
  const selected = new Set();
  const pending = [root.id];
  while (pending.length > 0) {
    const id = pending.pop();
    if (selected.has(id)) continue;
    const node = nodes.get(id);
    if (!node) throw new Error("Incomplete daemon dependency graph");
    selected.add(id);
    for (const dependency of node.deps) {
      if (dependency.dep_kinds.some((kind) => kind.kind !== "dev"))
        pending.push(dependency.pkg);
    }
  }
  const rust = metadata.packages
    .filter((item) => selected.has(item.id))
    .map((item) => ({
      name: item.name,
      version: item.version,
      licence: item.license,
      sourceKind: item.source?.split("+")[0] ?? "MeshSpan workspace",
      features: nodes.get(item.id).features,
    }));
  const web = Object.entries(javascript).flatMap(([licence, records]) =>
    records.flatMap((record) => {
      if (
        record.license !== licence ||
        typeof record.name !== "string" ||
        !Array.isArray(record.versions)
      ) {
        throw new Error("Invalid JavaScript dependency inventory");
      }
      return record.versions.map((version) => ({
        name: record.name,
        version,
        licence,
      }));
    }),
  );
  const byIdentity = (left, right) =>
    `${left.name}@${left.version}`.localeCompare(
      `${right.name}@${right.version}`,
      "en",
    );
  return {
    schema: 1,
    scope:
      "Rust normal/build dependency closure plus production web packages; Cargo feature unification may over-include dependencies. Not a link-level SBOM.",
    rust: rust.sort(byIdentity),
    web: web.sort(byIdentity),
  };
}

export async function sha256(file) {
  const digest = createHash("sha256");
  for await (const block of createReadStream(file)) digest.update(block);
  return digest.digest("hex");
}

/** Assemble into a new owned directory; never overwrite a previous local package. */
export async function assemblePackage({
  repository,
  output,
  binary,
  provenance,
  inventory,
}) {
  if (
    !/^[0-9]+\.[0-9]+\.[0-9]+$/.test(provenance.version) ||
    !nativeTargets.has(provenance.target) ||
    !["dev", "release"].includes(provenance.profile)
  ) {
    throw new Error("Invalid package identity");
  }
  await mkdir(output, { recursive: true });
  const name = `meshspan-${provenance.version}-${provenance.target}-${provenance.profile}`;
  const directory = await mkdtemp(join(output, `${name}-`));
  const bundle = join(directory, name);
  await mkdir(join(bundle, "bin"), { recursive: true });
  await copyFile(binary, join(bundle, "bin", "meshspan-daemon"));
  await chmod(join(bundle, "bin", "meshspan-daemon"), 0o755);
  await copyFile(join(repository, "LICENSE"), join(bundle, "LICENSE"));
  await copyFile(
    join(repository, "packaging", "RUNNING.md"),
    join(bundle, "RUNNING.md"),
  );
  await copyFile(
    join(repository, "packaging", "Dockerfile"),
    join(bundle, "Dockerfile"),
  );
  await writeJson(join(bundle, "dependencies.json"), inventory);
  await writeJson(join(bundle, "provenance.json"), {
    ...provenance,
    schema: 1,
    licence: "GPL-2.0-only",
    publication: "prohibited",
    acceptance: "not established by packaging",
    signature: "unsigned local development artefact",
  });
  const names = [
    "Dockerfile",
    "LICENSE",
    "RUNNING.md",
    "bin/meshspan-daemon",
    "dependencies.json",
    "provenance.json",
  ];
  const checksums = await Promise.all(
    names.map(async (file) => `${await sha256(join(bundle, file))}  ${file}\n`),
  );
  await writeFile(join(bundle, "SHA256SUMS"), checksums.join(""), {
    flag: "wx",
  });
  return { directory, bundle, name };
}

export async function writeJson(file, value) {
  await writeFile(file, `${JSON.stringify(value, null, 2)}\n`, { flag: "wx" });
}

export async function workspaceVersion(repository) {
  const manifest = await readFile(join(repository, "Cargo.toml"), "utf8");
  const section = manifest
    .split("[workspace.package]")[1]
    ?.split("[workspace.dependencies]")[0];
  const version = section?.match(
    /^version = "([0-9]+\.[0-9]+\.[0-9]+)"$/m,
  )?.[1];
  if (!version) throw new Error("Missing workspace package version");
  return version;
}
