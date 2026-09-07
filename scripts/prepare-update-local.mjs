// SPDX-License-Identifier: GPL-2.0-only

import { createPrivateKey, createPublicKey } from "node:crypto";
import { constants } from "node:fs";
import {
  copyFile,
  mkdir,
  mkdtemp,
  realpath,
  stat,
  writeFile,
} from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { sha256 } from "./local-package.mjs";
import {
  encodeCandidate,
  publicKeySec1,
  readCandidateFile,
  signCandidate,
} from "./update-candidate.mjs";

/** Assemble and sign already-built local packages, without rebuilding or publishing them. */
export async function prepareUpdate({
  packages,
  compatibility,
  privateKey,
  output,
}) {
  if (packages.length < 1 || packages.length > 4)
    throw new Error("Select one to four native packages");
  const records = await Promise.all(packages.map(inspectPackage));
  const first = records[0].provenance;
  if (
    records.some(
      ({ provenance }) =>
        provenance.version !== first.version ||
        provenance.sourceCommit !== first.sourceCommit ||
        provenance.apiSha256 !== first.apiSha256,
    )
  )
    throw new Error(
      "Candidate packages must share version, source commit and API digest",
    );
  const manifest = {
    format: 1,
    licence: "GPL-2.0-only",
    version: first.version,
    source_commit: first.sourceCommit,
    api_sha256: first.apiSha256,
    artifacts: records
      .map(({ artifact }) => artifact)
      .sort((left, right) => left.target.localeCompare(right.target, "en")),
    compatibility,
  };
  encodeCandidate(manifest);
  await mkdir(output, { recursive: true });
  const directory = await mkdtemp(join(output, "meshspan-update-local-"));
  await mkdir(join(directory, "artifacts"));
  for (const { artifact, binary } of records) {
    const destination = join(directory, "artifacts", artifact.target);
    await copyFile(binary, destination, constants.COPYFILE_EXCL);
    if (
      (await stat(destination)).size.toString() !== artifact.size ||
      (await sha256(destination)) !== artifact.sha256
    )
      throw new Error("Packaged executable changed during candidate assembly");
  }
  const bytes = encodeCandidate(manifest);
  const signature = signCandidate(bytes, privateKey);
  await writeFile(join(directory, "manifest.json"), bytes, { flag: "wx" });
  await writeFile(join(directory, "manifest.sig"), signature, { flag: "wx" });
  await writeFile(
    join(directory, "signer.sec1"),
    publicKeySec1(createPublicKey(privateKey)),
    { flag: "wx" },
  );
  await writeFile(
    join(directory, "LOCAL-ONLY.txt"),
    "Unpublished local update candidate. Signature is not acceptance or installation authority.\nPin the trusted signer separately; never trust this candidate's signer.sec1 automatically.\nNo rollback compatibility is promised.\n",
    { flag: "wx" },
  );
  return {
    directory,
    publication: "prohibited",
    acceptance: "not established",
  };
}

async function inspectPackage(directory) {
  const provenance = JSON.parse(
    (
      await readCandidateFile(join(directory, "provenance.json"), 64 * 1_024)
    ).toString("utf8"),
  );
  if (
    provenance.licence !== "GPL-2.0-only" ||
    provenance.workingTreeDirty !== false
  )
    throw new Error(
      "Candidate requires an explicitly GPL-2.0-only clean-source package",
    );
  const binary = join(directory, "bin", "meshspan-daemon");
  const metadata = await stat(binary);
  if (!metadata.isFile() || metadata.size < 1 || metadata.size > 8 * 1_024 ** 3)
    throw new Error("Candidate executable must be a bounded regular file");
  return {
    provenance,
    binary,
    artifact: {
      target: provenance.target,
      size: metadata.size.toString(),
      sha256: await sha256(binary),
    },
  };
}

async function main() {
  if (
    !process.env.NVM_BIN ||
    (await realpath(dirname(process.execPath))) !==
      (await realpath(process.env.NVM_BIN))
  )
    throw new Error("Activate NVM before preparing an update candidate");
  const arguments_ = process.argv.slice(2);
  const options = { packages: [] };
  if (!arguments_.length || arguments_.length % 2 !== 0)
    throw new Error(
      "Expected --package DIR (repeatable), --compatibility FILE, --key PKCS8_PEM and --output DIR",
    );
  for (let index = 0; index < arguments_.length; index += 2) {
    const flag = arguments_[index];
    const value = arguments_[index + 1];
    if (flag === "--package") options.packages.push(resolve(value));
    else if (
      ["--compatibility", "--key", "--output"].includes(flag) &&
      !Object.hasOwn(options, flag.slice(2))
    )
      options[flag.slice(2)] = resolve(value);
    else throw new Error("Unknown or repeated update preparation option");
  }
  if (!options.key || !options.compatibility || !options.output)
    throw new Error("Missing required update preparation option");
  const encodedKey = await readCandidateFile(options.key, 8 * 1_024);
  try {
    const result = await prepareUpdate({
      packages: options.packages,
      output: options.output,
      privateKey: createPrivateKey(encodedKey),
      compatibility: JSON.parse(
        (await readCandidateFile(options.compatibility, 4 * 1_024)).toString(
          "utf8",
        ),
      ),
    });
    process.stdout.write(`${JSON.stringify(result)}\n`);
  } finally {
    encodedKey.fill(0);
  }
}

if (
  process.argv[1] &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url)
) {
  await main();
}
