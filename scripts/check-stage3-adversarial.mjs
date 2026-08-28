// SPDX-License-Identifier: GPL-2.0-only

import { fileURLToPath } from "node:url";

import { runProcess } from "./process.mjs";
import { readWorkerCount, runWithLimit } from "./scheduler.mjs";

const repositoryRoot = fileURLToPath(new URL("../", import.meta.url));
const workerCount = readWorkerCount(process.env.MESHSPAN_CHECK_WORKERS);
const startedAt = performance.now();
const cases = [
  cargoCase(
    "multi-way partition authority",
    "meshspan-consensus",
    "core::simulation_tests::every_multi_way_partition_for_one_to_nine_voters_has_at_most_one_leader",
  ),
  cargoCase(
    "stale incarnation fencing",
    "meshspan-consensus",
    "core::tests::stale_identity_epoch_and_persistence_fail_closed",
  ),
  cargoCase(
    "corrupt snapshot rejection",
    "meshspan-transport",
    "snapshot::tests::corrupt_reordered_and_excessive_chunks_do_not_advance_stage",
  ),
  cargoCase(
    "saturated bulk-stream isolation",
    "meshspan-transport",
    "tests::saturated_data_stream_does_not_block_consensus_control",
  ),
];

const results = await runWithLimit(cases, workerCount, runCase);
for (const result of results) {
  const mark = result.passed ? "PASS" : "FAIL";
  process.stdout.write(
    `${mark} ${result.name} (${(result.durationMs / 1_000).toFixed(2)}s)\n`,
  );
  if (!result.passed) {
    process.stderr.write(result.output);
  }
}
if (results.some((result) => !result.passed)) {
  process.exitCode = 1;
}
process.stdout.write(
  `DONE ${((performance.now() - startedAt) / 1_000).toFixed(2)}s with ${workerCount} workers\n`,
);

function cargoCase(name, packageName, testName) {
  return {
    arguments: ["test", "-p", packageName, testName, "--", "--exact"],
    name,
  };
}

async function runCase(testCase) {
  const caseStartedAt = performance.now();
  const result = await runProcess("cargo", testCase.arguments, {
    cwd: repositoryRoot,
  });
  const exactTestPassed = result.output.includes(
    "test result: ok. 1 passed; 0 failed; 0 ignored",
  );
  return {
    durationMs: performance.now() - caseStartedAt,
    name: testCase.name,
    output: exactTestPassed
      ? result.output
      : `${result.output}\nexact test did not report one passing case\n`,
    passed: result.exitCode === 0 && exactTestPassed,
  };
}
