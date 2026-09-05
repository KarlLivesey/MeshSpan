// SPDX-License-Identifier: GPL-2.0-only

import { fileURLToPath } from "node:url";

import { runProcess } from "./process.mjs";
import { readWorkerCount, runWithLimit } from "./scheduler.mjs";

const repositoryRoot = fileURLToPath(new URL("../", import.meta.url));
const workerCount = readWorkerCount(process.env.MESHSPAN_CHECK_WORKERS);
const checkStartedAt = performance.now();

const generation = await runLane({
  name: "generated contract drift",
  steps: [[process.execPath, ["scripts/verify-generated.mjs"]]],
});
report(generation);
if (!generation.passed) {
  process.exitCode = 1;
} else {
  const buildAndRustLanes = [
    {
      name: "embedded web bundle",
      steps: [
        [
          process.execPath,
          ["web/node_modules/vite/bin/vite.js", "build", "web"],
        ],
      ],
    },
    {
      name: "Rust format",
      steps: [["cargo", ["fmt", "--all", "--", "--check"]]],
    },
    {
      name: "Rust lint",
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
      ],
    },
    {
      name: "Rust dependency licences",
      steps: [["cargo", ["deny", "check", "licenses"]]],
    },
  ];
  const independentStaticLanes = [
    {
      name: "JavaScript dependency licences",
      steps: [[process.execPath, ["scripts/check-javascript-licences.mjs"]]],
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
      name: "tooling tests",
      steps: [
        [
          process.execPath,
          [
            "--test",
            "scripts/javascript-licence-policy.test.mjs",
            "scripts/scheduler.test.mjs",
            "tooling/eslint/compatibility.test.mjs",
          ],
        ],
      ],
    },
  ];
  const testLanes = [
    {
      name: "Rust workspace tests",
      steps: [
        [
          "cargo",
          ["test", "--workspace", "--all-targets", "--all-features", "--quiet"],
        ],
      ],
    },
    {
      name: "web tests",
      steps: [["web/node_modules/.bin/vitest", ["run", "--root", "web"]]],
    },
  ];
  const results = [];
  for (const lane of buildAndRustLanes) {
    const result = await runLane(lane);
    results.push(result);
    report(result);
    if (!result.passed) {
      break;
    }
  }
  if (results.every((result) => result.passed)) {
    const staticResults = await runWithLimit(
      independentStaticLanes,
      workerCount,
      runLane,
    );
    results.push(...staticResults);
    staticResults.forEach(report);
  }
  if (results.every((result) => result.passed)) {
    const testResults = await runWithLimit(testLanes, workerCount, runLane);
    results.push(...testResults);
    testResults.forEach(report);
  }
  process.exitCode = results.some((result) => !result.passed) ? 1 : 0;
}
process.stdout.write(
  `DONE ${((performance.now() - checkStartedAt) / 1_000).toFixed(2)}s with ${workerCount} workers\n`,
);

async function runLane(lane) {
  const startedAt = performance.now();
  try {
    for (const [command, arguments_] of lane.steps) {
      const result = await runProcess(command, arguments_, {
        cwd: repositoryRoot,
      });
      if (result.exitCode !== 0) {
        return failedLane(lane.name, startedAt, result.output);
      }
    }
  } catch (error) {
    return failedLane(lane.name, startedAt, errorMessage(error));
  }
  return {
    durationMs: performance.now() - startedAt,
    name: lane.name,
    output: "",
    passed: true,
  };
}

function failedLane(name, startedAt, output) {
  return {
    durationMs: performance.now() - startedAt,
    name,
    output: output.endsWith("\n") ? output : `${output}\n`,
    passed: false,
  };
}

function errorMessage(error) {
  return error instanceof Error ? error.message : String(error);
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
