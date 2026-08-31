// SPDX-License-Identifier: GPL-2.0-only

import assert from "node:assert/strict";
import test from "node:test";

import { validateJavascriptLicences } from "./javascript-licence-policy.mjs";

test("compatible production and explicit tool-only licences pass", () => {
  const production = report("MIT", "solid-js", "2.0.0");
  const all = {
    ...production,
    ...report("Apache-2.0", "typescript", "6.0.3"),
  };
  assert.deepEqual(validateJavascriptLicences(all, production), {
    productionPackages: 1,
    toolOnlyPackages: 1,
  });
});

test("tool-only and unknown licences fail in production", () => {
  for (const licence of ["Apache-2.0", "LGPL-3.0-only", "UNKNOWN"]) {
    const dependency = report(licence, "unsafe-runtime", "1.0.0");
    assert.throws(
      () => validateJavascriptLicences(dependency, dependency),
      /production-incompatible/,
    );
  }
});

test("an unreviewed development licence fails closed", () => {
  assert.throws(
    () => validateJavascriptLicences(report("UNKNOWN", "mystery", "1.0.0"), {}),
    /unreviewed licence/,
  );
});

test("reports reject malformed, duplicate and absent package evidence", () => {
  assert.throws(() => validateJavascriptLicences([], {}), /not an object/);
  assert.throws(
    () =>
      validateJavascriptLicences(
        {
          MIT: [
            { license: "MIT", name: "same", versions: ["1.0.0"] },
            { license: "MIT", name: "same", versions: ["1.0.0"] },
          ],
        },
        {},
      ),
    /appears more than once/,
  );
  assert.throws(
    () =>
      validateJavascriptLicences(
        {},
        report("MIT", "missing-production-record", "1.0.0"),
      ),
    /absent from the complete licence report/,
  );
});

function report(licence, name, version) {
  return {
    [licence]: [{ license: licence, name, versions: [version] }],
  };
}
