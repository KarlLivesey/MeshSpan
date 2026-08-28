// SPDX-License-Identifier: GPL-2.0-only

import { readFile, readdir } from "node:fs/promises";
import { relative } from "node:path";
import { fileURLToPath } from "node:url";

import { commandFailure, runProcess } from "./process.mjs";

const repositoryRoot = fileURLToPath(new URL("../", import.meta.url));
const generatedRoots = [
  fileURLToPath(new URL("../contracts/openapi/", import.meta.url)),
  fileURLToPath(new URL("../web/src/generated/", import.meta.url)),
];

const before = await snapshotGeneratedFiles();
const generation = await runProcess(
  process.execPath,
  ["scripts/generate-api.mjs"],
  {
    cwd: repositoryRoot,
  },
);
if (generation.exitCode !== 0) {
  process.stderr.write(generation.output);
  throw commandFailure("API generation", generation);
}
const after = await snapshotGeneratedFiles();
const drift = compareSnapshots(before, after);

if (drift.length > 0) {
  throw new Error(
    `generated API artefacts are stale:\n${drift.map((item) => `- ${item}`).join("\n")}`,
  );
}

async function snapshotGeneratedFiles() {
  const snapshot = new Map();
  for (const root of generatedRoots) {
    for (const fileName of await listFiles(root)) {
      const repositoryName = relative(repositoryRoot, fileName);
      snapshot.set(repositoryName, await readFile(fileName));
    }
  }
  return snapshot;
}

async function listFiles(directory) {
  const entries = await readdir(directory, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const fileName = `${directory}/${entry.name}`;
    if (entry.isDirectory()) {
      files.push(...(await listFiles(fileName)));
    } else if (entry.isFile()) {
      files.push(fileName);
    }
  }
  return files.sort();
}

function compareSnapshots(beforeSnapshot, afterSnapshot) {
  const names = new Set([...beforeSnapshot.keys(), ...afterSnapshot.keys()]);
  return [...names].sort().flatMap((name) => {
    const oldValue = beforeSnapshot.get(name);
    const newValue = afterSnapshot.get(name);
    if (oldValue === undefined) {
      return [`added ${name}`];
    }
    if (newValue === undefined) {
      return [`removed ${name}`];
    }
    return oldValue.equals(newValue) ? [] : [`changed ${name}`];
  });
}
