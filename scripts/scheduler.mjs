// SPDX-License-Identifier: GPL-2.0-only

import { availableParallelism, totalmem } from "node:os";

const MAXIMUM_WORKERS = 32;
const DEFAULT_MAXIMUM_WORKERS = 4;
const RESERVED_MEMORY_BYTES = 1_073_741_824;
const MEMORY_BYTES_PER_WORKER = 805_306_368;

export function defaultWorkerCount() {
  const processorLimit = availableParallelism();
  const usableMemory = Math.max(0, totalmem() - RESERVED_MEMORY_BYTES);
  const memoryLimit = Math.max(
    1,
    Math.floor(usableMemory / MEMORY_BYTES_PER_WORKER),
  );
  return Math.max(
    1,
    Math.min(DEFAULT_MAXIMUM_WORKERS, processorLimit, memoryLimit),
  );
}

export function readWorkerCount(value) {
  if (value === undefined) {
    return defaultWorkerCount();
  }
  if (!/^[1-9][0-9]*$/.test(value)) {
    throw new Error("MESHSPAN_CHECK_WORKERS must be an integer from 1 to 32");
  }
  const workers = Number(value);
  if (workers > MAXIMUM_WORKERS) {
    throw new Error("MESHSPAN_CHECK_WORKERS must be an integer from 1 to 32");
  }
  return workers;
}

// Cargo otherwise starts an independent CPU-sized harness inside the bounded
// Rust lane. Multi-daemon cases multiply that demand again through child processes.
export function rustTestArguments(workers) {
  if (
    !Number.isSafeInteger(workers) ||
    workers < 1 ||
    workers > MAXIMUM_WORKERS
  ) {
    throw new Error("Rust test workers must be an integer from 1 to 32");
  }
  return [
    "test",
    "--workspace",
    "--all-targets",
    "--all-features",
    "--quiet",
    "--",
    "--test-threads",
    String(workers),
  ];
}

export async function runWithLimit(items, limit, execute) {
  if (!Number.isSafeInteger(limit) || limit < 1) {
    throw new Error("scheduler limit must be a positive safe integer");
  }
  const results = new Array(items.length);
  let nextIndex = 0;

  async function worker() {
    for (;;) {
      const index = nextIndex;
      nextIndex += 1;
      if (index >= items.length) {
        return;
      }
      results[index] = await execute(items[index], index);
    }
  }

  const activeWorkers = Math.min(limit, items.length);
  await Promise.all(Array.from({ length: activeWorkers }, () => worker()));
  return results;
}
