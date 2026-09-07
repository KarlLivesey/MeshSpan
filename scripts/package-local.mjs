// SPDX-License-Identifier: GPL-2.0-only

import { execFile } from "node:child_process";
import { realpath, writeFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

import {
  assemblePackage,
  dependencyInventory,
  packageBuildSteps,
  packageOptions,
  sha256,
  workspaceVersion,
} from "./local-package.mjs";
import { commandFailure, runProcess } from "./process.mjs";

const repository = fileURLToPath(new URL("../", import.meta.url));
const execute = promisify(execFile);

// An ambient Node executable must never silently replace the selected NVM runtime.
if (
  !process.env.NVM_BIN ||
  (await realpath(dirname(process.execPath))) !==
    (await realpath(process.env.NVM_BIN))
) {
  throw new Error("Activate NVM before running local packaging");
}
const rustc = await capture("rustc", ["-vV"]);
const host = rustc.match(/^host: (.+)$/m)?.[1];
const options = packageOptions(process.argv.slice(2), host);
const steps = packageBuildSteps(options, host);
if (options.plan) {
  process.stdout.write(
    `${JSON.stringify({ ...options, publication: "prohibited", steps }, null, 2)}\n`,
  );
} else {
  await packageLocal();
}

async function packageLocal() {
  const commit = (await capture("git", ["rev-parse", "HEAD"])).trim();
  const dirty = (await capture("git", ["status", "--porcelain"])).length > 0;
  await run("cargo", ["deny", "check", "licenses"]);
  await run(process.execPath, ["scripts/check-javascript-licences.mjs"]);
  for (const [command, arguments_] of steps) await run(command, arguments_);
  const binary = join(
    repository,
    "target",
    options.target === host ? "" : options.target,
    options.profile === "dev" ? "debug" : "release",
    "meshspan-daemon",
  );
  const linkage = await inspectBinary(binary, options.target);
  const [metadata, javascript] = await Promise.all([
    capture("cargo", [
      "metadata",
      "--format-version",
      "1",
      "--locked",
      "--offline",
      "--filter-platform",
      options.target,
    ]),
    capture("pnpm", ["licenses", "list", "--prod", "--json"]),
  ]);
  const result = await assemblePackage({
    repository,
    output: resolve(
      options.output ?? join(repository, "target", "local-packages"),
    ),
    binary,
    provenance: {
      version: await workspaceVersion(repository),
      target: options.target,
      profile: options.profile,
      sourceCommit: commit,
      apiSha256: await sha256(
        join(repository, "contracts", "openapi", "latest.json"),
      ),
      workingTreeDirty: dirty,
      rustc,
      node: process.version,
      linkage,
      reproducibility: "Not asserted; local build and inventory only",
    },
    inventory: dependencyInventory(
      JSON.parse(metadata),
      JSON.parse(javascript),
    ),
  });
  const archive = join(result.directory, `${result.name}.tar.gz`);
  await run("tar", ["-czf", archive, "-C", result.directory, result.name]);
  await writeFile(
    `${archive}.sha256`,
    `${await sha256(archive)}  ${result.name}.tar.gz\n`,
    { flag: "wx" },
  );
  process.stdout.write(
    `${JSON.stringify({ ...result, archive, publication: "prohibited" }, null, 2)}\n`,
  );
}

async function inspectBinary(binary, target) {
  const description = await capture("file", ["-b", binary]);
  const architecture = target.startsWith("aarch64")
    ? /arm64|aarch64|ARM aarch64/
    : /x86[_-]64/;
  if (!architecture.test(description))
    throw new Error("Packaged binary architecture does not match target");
  if (target.includes("linux")) {
    if (
      !/ELF/.test(description) ||
      !/statically linked|static-pie linked/.test(description)
    ) {
      throw new Error(
        "Linux package requires a static musl executable; refusing hidden runtime libraries",
      );
    }
    return description.trim();
  }
  if (!/Mach-O/.test(description))
    throw new Error("macOS package requires a Mach-O executable");
  const linkage = await capture("otool", ["-L", binary]);
  const dependencies = linkage
    .split("\n")
    .slice(1)
    .map((line) => line.trim())
    .filter(Boolean);
  if (
    dependencies.some(
      (line) =>
        !line.startsWith("/usr/lib/") && !line.startsWith("/System/Library/"),
    )
  ) {
    throw new Error("macOS package links a non-system library");
  }
  return { format: description.trim(), systemLibraries: dependencies };
}

async function capture(command, arguments_) {
  const { stdout } = await execute(command, arguments_, {
    cwd: repository,
    encoding: "utf8",
    maxBuffer: 32 * 1_024 * 1_024,
  });
  return stdout;
}

async function run(command, arguments_) {
  const result = await runProcess(command, arguments_, { cwd: repository });
  process.stdout.write(result.output);
  if (result.exitCode !== 0) throw commandFailure(command, result);
}
