// SPDX-License-Identifier: GPL-2.0-only

import { spawn } from "node:child_process";

const MAX_CAPTURED_BYTES = 1_048_576;

export async function runProcess(command, arguments_, options = {}) {
  const startedAt = performance.now();
  const child = spawn(command, arguments_, {
    cwd: options.cwd,
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"],
  });
  const output = [];
  let capturedBytes = 0;
  let truncated = false;

  const capture = (chunk) => {
    if (capturedBytes >= MAX_CAPTURED_BYTES) {
      truncated = true;
      return;
    }
    const remaining = MAX_CAPTURED_BYTES - capturedBytes;
    const captured = chunk.subarray(0, remaining);
    output.push(captured);
    capturedBytes += captured.byteLength;
    truncated ||= captured.byteLength < chunk.byteLength;
  };

  child.stdout.on("data", capture);
  child.stderr.on("data", capture);

  const exitCode = await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => {
      if (signal !== null) {
        reject(new Error(`${command} terminated by ${signal}`));
        return;
      }
      resolve(code ?? 1);
    });
  });
  const suffix = truncated ? "\n[output truncated]\n" : "";

  return {
    durationMs: performance.now() - startedAt,
    exitCode,
    output: `${Buffer.concat(output).toString("utf8")}${suffix}`,
  };
}

export function commandFailure(command, result) {
  const error = new Error(`${command} exited with code ${result.exitCode}`);
  error.output = result.output;
  return error;
}
