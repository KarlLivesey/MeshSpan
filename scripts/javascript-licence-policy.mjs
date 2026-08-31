// SPDX-License-Identifier: GPL-2.0-only

const productionLicences = new Set([
  "GPL-2.0-only",
  "MIT",
  "MIT-0",
  "BSD-1-Clause",
  "BSD-2-Clause",
  "BSD-3-Clause",
  "ISC",
  "Zlib",
  "CC0-1.0",
  "Unlicense",
  "Unicode-3.0",
  "Apache-2.0 WITH LLVM-exception",
]);

// These licences are accepted only for executable build, lint and test tools.
// Their code must never enter a production dependency graph or shipped bundle.
const developmentToolLicences = new Set([
  "Apache-2.0",
  "BlueOak-1.0.0",
  "LGPL-3.0-only",
  "MPL-2.0",
  "Python-2.0",
]);

export function validateJavascriptLicences(allReport, productionReport) {
  const all = readReport(allReport, "complete");
  const production = readReport(productionReport, "production");
  const allPackages = packageIdentities(all);
  const productionPackages = packageIdentities(production);

  for (const dependency of production) {
    if (!productionLicences.has(dependency.licence)) {
      throw new Error(
        `${dependency.identity} has production-incompatible licence ${dependency.licence}`,
      );
    }
    if (!allPackages.has(dependency.identity)) {
      throw new Error(
        `${dependency.identity} is absent from the complete licence report`,
      );
    }
  }

  let toolOnlyPackages = 0;
  for (const dependency of all) {
    if (productionLicences.has(dependency.licence)) {
      continue;
    }
    if (!developmentToolLicences.has(dependency.licence)) {
      throw new Error(
        `${dependency.identity} has unreviewed licence ${dependency.licence}`,
      );
    }
    if (productionPackages.has(dependency.identity)) {
      throw new Error(`${dependency.identity} is not permitted in production`);
    }
    toolOnlyPackages += 1;
  }

  return {
    productionPackages: productionPackages.size,
    toolOnlyPackages,
  };
}

function readReport(report, label) {
  if (report === null || typeof report !== "object" || Array.isArray(report)) {
    throw new Error(`${label} licence report is not an object`);
  }
  const dependencies = [];
  for (const [licence, records] of Object.entries(report)) {
    if (
      typeof licence !== "string" ||
      licence.length === 0 ||
      !Array.isArray(records)
    ) {
      throw new Error(`${label} licence report has an invalid group`);
    }
    for (const record of records) {
      dependencies.push(...readRecord(record, licence, label));
    }
  }
  return dependencies;
}

function readRecord(record, licence, label) {
  if (record === null || typeof record !== "object" || Array.isArray(record)) {
    throw new Error(`${label} licence report has an invalid package record`);
  }
  if (record.license !== licence) {
    throw new Error(`${label} licence report has a mismatched package licence`);
  }
  if (typeof record.name !== "string" || record.name.length === 0) {
    throw new Error(`${label} licence report has an invalid package name`);
  }
  if (!Array.isArray(record.versions) || record.versions.length === 0) {
    throw new Error(`${label} licence report has no package versions`);
  }
  return record.versions.map((version) => {
    if (typeof version !== "string" || version.length === 0) {
      throw new Error(`${label} licence report has an invalid package version`);
    }
    return {
      identity: `${record.name}@${version}`,
      licence,
    };
  });
}

function packageIdentities(dependencies) {
  const identities = new Set();
  for (const dependency of dependencies) {
    if (identities.has(dependency.identity)) {
      throw new Error(
        `${dependency.identity} appears more than once in a licence report`,
      );
    }
    identities.add(dependency.identity);
  }
  return identities;
}
