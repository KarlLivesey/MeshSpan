// SPDX-License-Identifier: GPL-2.0-only

import { createHash } from "node:crypto";
import { lstat, readFile, readdir, realpath } from "node:fs/promises";
import { basename, dirname, isAbsolute, join, relative } from "node:path";

import { dependencyPackages } from "./local-package.mjs";

const noticeName =
  /^(?:licen[cs]es?|copying|copyright|notices?|unlicense)(?:[._-]|$)/i;
const skippedDirectories = new Set([".git", "target", "node_modules"]);
const maximumNoticeBytes = 4 * 1_024 * 1_024;
const recoveredNotices = [
  {
    ecosystem: "cargo",
    names: ["asn1-rs-impl"],
    version: "0.2.0",
    licence: "MIT/Apache-2.0",
    repository: "https://github.com/rusticata/asn1-rs.git",
    file: "asn1-rs-impl-0.2.0-MIT.txt",
    upstream:
      "https://raw.githubusercontent.com/rusticata/asn1-rs/a20e5f7319c896737ad0f2557037817b91ad854f/LICENSE-MIT",
  },
  {
    ecosystem: "npm",
    names: ["solid-js", "@solidjs/web"],
    version: "2.0.0-rc.3",
    licence: "MIT",
    repository: "git+https://github.com/solidjs/solid.git",
    file: "solid-2.0.0-rc.3-MIT.txt",
    upstream:
      "https://raw.githubusercontent.com/solidjs/solid/af6fee86e6dcfbf41869da2c607c82b1fd0939ce/LICENSE",
  },
];

/** Preserve upstream notice bytes. Missing source evidence refuses package assembly. */
export async function collectPackageNotices({
  repository,
  metadata,
  javascript,
}) {
  const sources = dependencyPackages(metadata).map((item) => ({
    ecosystem: "cargo",
    name: item.name,
    version: item.version,
    licence: item.license,
    root: dirname(item.manifest_path),
    explicit: item.license_file,
    repository: item.repository,
    workspace: metadata.workspace_members.includes(item.id),
  }));
  sources.push(...(await webSources(javascript)));
  const records = [];
  const missing = [];
  for (const source of sources) {
    const root = source.workspace ? repository : source.root;
    const files = source.workspace
      ? [join(repository, "LICENSE")]
      : await findNotices(root);
    if (source.explicit) files.push(source.explicit);
    const notices = [];
    for (const file of [...new Set(files)].sort())
      notices.push(await readNotice(root, file));
    if (notices.length === 0) {
      const recovered = await recoveredUpstreamNotice(repository, source);
      if (recovered) notices.push(recovered);
      else missing.push(`${source.name}@${source.version}`);
    }
    records.push({
      ecosystem: source.ecosystem,
      name: source.name,
      version: source.version,
      licence: source.licence,
      notices,
    });
  }
  if (missing.length > 0)
    throw new Error(`No upstream licence notice for ${missing.join(", ")}`);
  return records.sort((left, right) =>
    identity(left).localeCompare(identity(right), "en"),
  );
}

async function recoveredUpstreamNotice(repository, source) {
  const recovered = recoveredNotices.find(
    (item) =>
      item.ecosystem === source.ecosystem &&
      item.names.includes(source.name) &&
      item.version === source.version &&
      item.licence === source.licence &&
      item.repository === source.repository,
  );
  if (!recovered) return undefined;
  const notice = await readNotice(
    repository,
    join(repository, "packaging", "notices", recovered.file),
  );
  return {
    ...notice,
    upstream: recovered.upstream,
  };
}

async function webSources(report) {
  const sources = new Map();
  for (const [licence, records] of Object.entries(report)) {
    for (const record of records) {
      if (record.license !== licence || !Array.isArray(record.paths))
        throw new Error(
          "JavaScript notice sources do not match the licence report",
        );
      const versions = new Set();
      for (const root of record.paths) {
        const manifest = JSON.parse(
          await readFile(join(root, "package.json"), "utf8"),
        );
        if (
          manifest.name !== record.name ||
          !record.versions.includes(manifest.version)
        )
          throw new Error("JavaScript notice source identity mismatch");
        const source = {
          ecosystem: "npm",
          name: record.name,
          version: manifest.version,
          licence,
          root,
          repository: manifest.repository?.url ?? manifest.repository,
        };
        sources.set(identity(source), source);
        versions.add(manifest.version);
      }
      if (record.versions.some((version) => !versions.has(version)))
        throw new Error(
          "JavaScript notice source missing for a reported version",
        );
    }
  }
  return [...sources.values()];
}

async function findNotices(root) {
  const pending = [root];
  const files = [];
  let entriesVisited = 0;
  while (pending.length > 0) {
    const directory = pending.pop();
    const entries = await readdir(directory, { withFileTypes: true });
    entriesVisited += entries.length;
    if (entriesVisited > 100_000)
      throw new Error("Package notice scan exceeds its entry bound");
    for (const entry of entries) {
      const file = join(directory, entry.name);
      if (entry.isDirectory() && !skippedDirectories.has(entry.name)) {
        pending.push(file);
      } else if (
        relative(root, file)
          .split(/[\\/]/)
          .some((part) => noticeName.test(part))
      ) {
        files.push(file);
      }
    }
  }
  return files;
}

async function readNotice(root, file) {
  const source = await realpath(file);
  const parent = await realpath(root);
  const local = relative(parent, source);
  if (isAbsolute(local) || local === ".." || local.startsWith("../"))
    throw new Error("Package notice escapes its source directory");
  const info = await lstat(source);
  if (!info.isFile() || info.size === 0 || info.size > maximumNoticeBytes)
    throw new Error(`Invalid notice file: ${basename(file)}`);
  const bytes = await readFile(source);
  if (bytes.length > maximumNoticeBytes)
    throw new Error("Package notice grew beyond its size bound");
  const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  return {
    file: local.split("\\").join("/"),
    sha256: createHash("sha256").update(bytes).digest("hex"),
    text,
  };
}

function identity(source) {
  return `${source.ecosystem}:${source.name}@${source.version}`;
}

export function renderPackageNotices(records) {
  return [
    "MeshSpan — third-party source notices",
    "MeshSpan licence: GPL-2.0-only",
    "Upstream declarations below are preserved, not a selection of licensing alternatives.",
    "Scope: Cargo normal/build closure and production web packages; source-level, not linked-symbol evidence.",
    ...records.map((record) =>
      [
        `\n=== ${identity(record)} ===`,
        `Declared licence: ${record.licence}`,
        ...record.notices.map(
          (notice) =>
            `\n--- ${notice.file} (SHA-256 ${notice.sha256}) ---\n${notice.upstream ? `Source: ${notice.upstream}\n` : ""}${notice.text}`,
        ),
      ].join("\n"),
    ),
    "",
  ].join("\n");
}
