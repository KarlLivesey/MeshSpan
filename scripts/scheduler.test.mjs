// SPDX-License-Identifier: GPL-2.0-only

import assert from "node:assert/strict";
import test from "node:test";

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
