// SPDX-License-Identifier: GPL-2.0-only

// Real daemons use their normal resolver and fixed HTTPS origins inside separate offline networks.
import { readFile } from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { homedir } from "node:os";
import { join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { commandFailure, runProcess } from "./process.mjs";
import { readWorkerCount, runWithLimit } from "./scheduler.mjs";

const repositoryRoot = fileURLToPath(new URL("../", import.meta.url));
if (
  !process.env.NVM_BIN ||
  resolve(process.env.NVM_BIN, "node") !== process.execPath
) {
  throw new Error(
    "Initialise NVM and select its Node before running this proof.",
  );
}
const toolchain = await readFile(
  join(repositoryRoot, "rust-toolchain.toml"),
  "utf8",
);
const version = /^channel = "(\d+\.\d+\.\d+)"$/m.exec(toolchain)?.[1];
if (!version) throw new Error("Missing exact project Rust toolchain.");
const imageReference =
  process.env.MESHSPAN_DNS_PROOF_IMAGE ?? `rust:${version}-bookworm`;
const inspected = await docker([
  "image",
  "inspect",
  imageReference,
  "--format",
  "{{.Id}}",
]);
const image = inspected.output.trim();
if (!/^sha256:[a-f0-9]{64}$/.test(image))
  throw new Error("Expected one local immutable image ID.");
const workers = readWorkerCount(process.env.MESHSPAN_CHECK_WORKERS);
const registry = join(
  process.env.CARGO_HOME ?? join(homedir(), ".cargo"),
  "registry",
);
const mounts = [
  "--mount",
  `type=bind,src=${repositoryRoot},dst=/meshspan,readonly`,
  "--mount",
  "type=volume,src=meshspan-dns-provider-proof-target,dst=/meshspan/target",
  "--mount",
  `type=bind,src=${registry},dst=/usr/local/cargo/registry,readonly`,
  "--workdir",
  "/meshspan",
];
process.stdout.write(
  `Building offline DNS-provider proof with ${image} and ${workers} workers.\n`,
);
const build = await docker([
  "run",
  "--rm",
  "--network",
  "none",
  ...mounts,
  "--env",
  `CARGO_BUILD_JOBS=${workers}`,
  "--entrypoint",
  "rustup",
  image,
  "run",
  version,
  "cargo",
  "test",
  "--offline",
  "--locked",
  "-p",
  "meshspan-daemon",
  "--test",
  "headless_process",
  "--all-features",
  "--no-run",
  "--message-format=json",
]);
const executable = builtExecutable(build.output);
process.stdout.write(
  `PASS Linux proof build (${(build.durationMs / 1_000).toFixed(2)}s).\n`,
);
const cases = [
  "acme_lifecycle::dns_providers::cloudflare_dns01_issues_cleans_and_reuses_one_certificate",
  "acme_lifecycle::dns_providers::webhook_dns01_issues_cleans_and_reuses_one_certificate",
  "acme_lifecycle::dns_providers::manual::manual_dns01_tasks_drive_issuance_and_exact_cleanup",
];
const results = await runWithLimit(cases, workers, async (testName) => {
  // Each case owns its port-53/443 listeners without serialising otherwise independent tests.
  const container = `meshspan-dns-proof-${randomUUID()}`;
  const result = await runProcess(
    "docker",
    [
      "run",
      "--name",
      container,
      "--network",
      "none",
      ...mounts,
      "--dns",
      "127.0.0.1",
      "--add-host",
      "api.cloudflare.com:127.0.0.1",
      "--add-host",
      "ns.meshspan.test:127.0.0.1",
      "--env",
      "MESHSPAN_DNS_PROVIDER_PROOF=1",
      "--entrypoint",
      executable,
      image,
      testName,
      "--ignored",
      "--exact",
      "--test-threads=4",
    ],
    { cwd: repositoryRoot },
  );
  const passed =
    result.exitCode === 0 &&
    result.output.includes("test result: ok. 1 passed; 0 failed; 0 ignored");
  process.stdout.write(
    `${passed ? "PASS" : "FAIL"} ${testName} (${(result.durationMs / 1_000).toFixed(2)}s)\n`,
  );
  if (passed) {
    await docker(["rm", container]);
  } else {
    process.stderr.write(
      `${result.output}\nPrivate fixture state retained in ${container}.\n`,
    );
  }
  return passed;
});
process.exitCode = results.every(Boolean) ? 0 : 1;

async function docker(arguments_) {
  const result = await runProcess("docker", arguments_, {
    cwd: repositoryRoot,
  });
  if (result.exitCode !== 0) {
    process.stderr.write(result.output);
    throw commandFailure("docker", result);
  }
  return result;
}

function builtExecutable(output) {
  const artefacts = output
    .split("\n")
    .filter((line) => line.startsWith("{"))
    .map((line) => JSON.parse(line));
  const binaries = artefacts.filter(
    (item) =>
      item.reason === "compiler-artifact" &&
      item.target?.name === "headless_process" &&
      item.profile?.test === true &&
      item.executable,
  );
  if (
    binaries.length !== 1 ||
    !/^\/meshspan\/target\/debug\/deps\/headless_process-[a-f0-9]+$/.test(
      binaries[0].executable,
    )
  ) {
    throw new Error(
      "Cargo did not identify exactly one bounded headless proof executable.",
    );
  }
  return binaries[0].executable;
}
