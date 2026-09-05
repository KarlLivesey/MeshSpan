// SPDX-License-Identifier: GPL-2.0-only

import { fileURLToPath } from "node:url";

import { commandFailure, runProcess } from "./process.mjs";

const repositoryRoot = fileURLToPath(new URL("../", import.meta.url));
for (const [command, arguments_] of [
  [process.execPath, ["web/node_modules/vite/bin/vite.js", "build", "web"]],
  ["cargo", ["build", "-p", "meshspan-daemon"]],
]) {
  const result = await runProcess(command, arguments_, { cwd: repositoryRoot });
  process.stdout.write(result.output);
  if (result.exitCode !== 0) {
    throw commandFailure(command, result);
  }
}
