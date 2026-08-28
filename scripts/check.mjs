// SPDX-License-Identifier: GPL-2.0-only

import { availableParallelism } from "node:os";
import { fileURLToPath } from "node:url";

import { runProcess } from "./process.mjs";

const repositoryRoot = fileURLToPath(new URL("../", import.meta.url));
const workerCount = readWorkerCount(process.env.MESHSPAN_CHECK_WORKERS);

const generation = await runLane({
  name: "generated contract drift",
  steps: [[process.execPath, ["scripts/verify-generated.mjs"]]],
});
report(generation);
if (!generation.passed) {
  process.exitCode = 1;
} else {
  const lanes = [
    {
      name: "Rust format",
      steps: [["cargo", ["fmt", "--all", "--", "--check"]]],
    },
    {
      name: "Rust lint and tests",
      steps: [
        [
          "cargo",
          [
            "clippy",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
          ],
        ],
        ["cargo", ["test", "--workspace", "--all-targets", "--all-features"]],
      ],
    },
    {
      name: "workspace format",
      steps: [
        [
          "web/node_modules/.bin/prettier",
          [
            "--check",
            "web",
            "scripts",
            "tooling",
            "package.json",
            "pnpm-workspace.yaml",
          ],
        ],
      ],
    },
    {
      name: "web lint",
      steps: [
        [
          "tooling/eslint/node_modules/.bin/eslint",
          [
            "web/src",
            "web/tests",
            "scripts",
            "tooling",
            "--config",
            "tooling/eslint/eslint.config.mjs",
            "--max-warnings",
            "0",
            "--report-unused-disable-directives",
          ],
        ],
      ],
    },
    {
      name: "web typecheck",
      steps: [
        [
          "web/node_modules/.bin/tsc",
          ["--project", "web/tsconfig.json", "--noEmit"],
        ],
      ],
    },
    {
      name: "web tests",
      steps: [["web/node_modules/.bin/vitest", ["run", "--root", "web"]]],
    },
  ];
  const results = await runWithLimit(lanes, workerCount);
  results.forEach(report);
  process.exitCode = results.some((result) => !result.passed) ? 1 : 0;
}

async function runWithLimit(lanes, limit) {
  const results = new Array(lanes.length);
  let nextIndex = 0;

  async function worker() {
    for (;;) {
      const index = nextIndex;
      nextIndex += 1;
      if (index >= lanes.length) {
        return;
      }
      results[index] = await runLane(lanes[index]);
    }
  }

  await Promise.all(
    Array.from({ length: Math.min(limit, lanes.length) }, () => worker()),
  );
  return results;
}

async function runLane(lane) {
  const startedAt = performance.now();
  for (const [command, arguments_] of lane.steps) {
    const result = await runProcess(command, arguments_, {
      cwd: repositoryRoot,
    });
    if (result.exitCode !== 0) {
      return {
        durationMs: performance.now() - startedAt,
        name: lane.name,
        output: result.output,
        passed: false,
      };
    }
  }
  return {
    durationMs: performance.now() - startedAt,
    name: lane.name,
    output: "",
    passed: true,
  };
}

function report(result) {
  const mark = result.passed ? "PASS" : "FAIL";
  process.stdout.write(
    `${mark.padEnd(4)} ${result.name} (${(result.durationMs / 1_000).toFixed(2)}s)\n`,
  );
  if (!result.passed) {
    process.stdout.write(result.output);
  }
}

function readWorkerCount(value) {
  if (value === undefined) {
    return Math.min(4, availableParallelism());
  }
  if (!/^[1-9][0-9]*$/.test(value)) {
    throw new Error("MESHSPAN_CHECK_WORKERS must be an integer from 1 to 32");
  }
  const workers = Number(value);
  if (workers > 32) {
    throw new Error("MESHSPAN_CHECK_WORKERS must be an integer from 1 to 32");
  }
  return workers;
}
