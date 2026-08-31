// SPDX-License-Identifier: GPL-2.0-only

import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { validateJavascriptLicences } from "./javascript-licence-policy.mjs";

const execute = promisify(execFile);
const commandOptions = {
  cwd: new URL("../", import.meta.url),
  encoding: "utf8",
  maxBuffer: 16 * 1_024 * 1_024,
};

const [allReport, productionReport] = await Promise.all([
  licenceReport([]),
  licenceReport(["--prod"]),
]);
const result = validateJavascriptLicences(allReport, productionReport);
process.stdout.write(
  `JavaScript licences ok: ${result.productionPackages} production; ` +
    `${result.toolOnlyPackages} tool-only\n`,
);

async function licenceReport(arguments_) {
  const { stdout } = await execute(
    "pnpm",
    ["licenses", "list", ...arguments_, "--json"],
    commandOptions,
  );
  try {
    return JSON.parse(stdout);
  } catch (error) {
    throw new Error("pnpm returned an invalid licence report", {
      cause: error,
    });
  }
}
