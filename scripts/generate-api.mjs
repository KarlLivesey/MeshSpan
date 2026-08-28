// SPDX-License-Identifier: GPL-2.0-only

import { fileURLToPath } from "node:url";

import { commandFailure, runProcess } from "./process.mjs";

const repositoryRoot = fileURLToPath(new URL("../", import.meta.url));
const codegenRoot = fileURLToPath(
  new URL("../tooling/api-codegen/", import.meta.url),
);

const steps = [
  {
    arguments: [
      "run",
      "--quiet",
      "-p",
      "meshspan-api-contract",
      "--bin",
      "generate-openapi",
    ],
    command: "cargo",
    cwd: repositoryRoot,
  },
  {
    arguments: ["--file", "openapi-ts.config.ts"],
    command: "node_modules/.bin/openapi-ts",
    cwd: codegenRoot,
  },
  {
    arguments: ["generate-fetch.mjs"],
    command: process.execPath,
    cwd: codegenRoot,
  },
  {
    arguments: ["--write", "../../web/src/generated"],
    command: "node_modules/.bin/prettier",
    cwd: codegenRoot,
  },
];

for (const step of steps) {
  const result = await runProcess(step.command, step.arguments, {
    cwd: step.cwd,
  });
  if (result.exitCode !== 0) {
    process.stderr.write(result.output);
    throw commandFailure(step.command, result);
  }
}
