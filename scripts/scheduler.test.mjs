// SPDX-License-Identifier: GPL-2.0-only

import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import {
  copyFile,
  mkdir,
  mkdtemp,
  readFile,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { promisify } from "node:util";

import {
  readWorkerCount,
  runWithLimit,
  rustTestArguments,
} from "./scheduler.mjs";

test("Rust harness receives the same budget without dropping any test target", () => {
  for (const workers of [1, 4, 12, 32]) {
    assert.deepEqual(rustTestArguments(workers), [
      "test",
      "--workspace",
      "--all-targets",
      "--all-features",
      "--quiet",
      "--",
      "--test-threads",
      String(workers),
    ]);
  }
});

test("Rust harness budget rejects invalid limits instead of falling back", () => {
  for (const invalid of [0, -1, 1.5, 33, NaN, Infinity]) {
    assert.throws(() => rustTestArguments(invalid), /integer from 1 to 32/);
  }
});

test("worker override accepts only the documented bounded integer", () => {
  assert.equal(readWorkerCount("1"), 1);
  assert.equal(readWorkerCount("32"), 32);
  for (const invalid of ["0", "33", "1.5", "-1", "four", ""]) {
    assert.throws(() => readWorkerCount(invalid), /integer from 1 to 32/);
  }
});

test("scheduler preserves order and never exceeds its worker limit", async () => {
  let active = 0;
  let maximumActive = 0;
  const release = Promise.withResolvers();
  let started = 0;

  const scheduled = runWithLimit([1, 2, 3, 4], 2, async (value) => {
    active += 1;
    started += 1;
    maximumActive = Math.max(maximumActive, active);
    if (started === 2) {
      release.resolve();
    }
    await release.promise;
    active -= 1;
    return value * 2;
  });

  assert.deepEqual(await scheduled, [2, 4, 6, 8]);
  assert.equal(maximumActive, 2);
});

test("scheduler rejects invalid limits before starting work", async () => {
  let started = false;
  await assert.rejects(
    runWithLimit([1], 0, async () => {
      started = true;
    }),
    /positive safe integer/,
  );
  assert.equal(started, false);
});

// Execute the real launcher with only its process boundary replaced. No command below
// runs a build or a nested test suite; recording preserves its actual argument composition.
async function recordCheckCommands(context, workers) {
  const root = await mkdtemp(join(tmpdir(), "meshspan-check-budget-"));
  context.after(async () => rm(root, { recursive: true, force: true }));
  const scripts = join(root, "scripts");
  await mkdir(scripts);
  for (const name of ["check.mjs", "scheduler.mjs"]) {
    await copyFile(new URL(name, import.meta.url), join(scripts, name));
  }
  await writeFile(
    join(scripts, "process.mjs"),
    String.raw`// SPDX-License-Identifier: GPL-2.0-only
import { appendFile } from "node:fs/promises";
export async function runProcess(command, arguments_) {
  await appendFile(new URL("commands.jsonl", import.meta.url), JSON.stringify([command, arguments_]) + "\n");
  return { exitCode: 0, output: "" };
}
`,
  );
  const { stdout } = await promisify(execFile)(
    process.execPath,
    [join(scripts, "check.mjs")],
    {
      env: { ...process.env, MESHSPAN_CHECK_WORKERS: String(workers) },
      timeout: 10_000,
      maxBuffer: 1_048_576,
    },
  );
  assert.match(stdout, new RegExp(`with ${workers} workers`));
  const records = await readFile(join(scripts, "commands.jsonl"), "utf8");
  return records
    .trim()
    .split("\n")
    .map((line) => JSON.parse(line));
}

test("actual check launcher bounds every test runner without omitting lanes", async (context) => {
  for (const workers of [2, 32]) {
    const commands = await recordCheckCommands(context, workers);
    assert.equal(
      commands.length,
      12,
      "all generation, build, static and test lanes run",
    );
    assert.deepEqual(
      commands.find(([command]) => command === "web/node_modules/.bin/vitest"),
      [
        "web/node_modules/.bin/vitest",
        ["run", "--root", "web", "--maxWorkers", String(workers)],
      ],
    );
    assert.deepEqual(
      commands.find(
        ([command, arguments_]) =>
          command === process.execPath && arguments_[0] === "--test",
      ),
      [
        process.execPath,
        [
          "--test",
          `--test-concurrency=${workers}`,
          "scripts/javascript-licence-policy.test.mjs",
          "scripts/scheduler.test.mjs",
          "scripts/local-package.test.mjs",
          "scripts/package-compliance.test.mjs",
          "scripts/update-candidate.test.mjs",
          "tooling/eslint/compatibility.test.mjs",
          "tooling/api-codegen/fetch-contract.test.mjs",
        ],
      ],
    );
    assert.deepEqual(
      commands.find(
        ([command, arguments_]) =>
          command === "cargo" && arguments_[0] === "test",
      ),
      [
        "cargo",
        [
          "test",
          "--workspace",
          "--all-targets",
          "--all-features",
          "--quiet",
          "--",
          "--test-threads",
          String(workers),
        ],
      ],
    );
  }
});
