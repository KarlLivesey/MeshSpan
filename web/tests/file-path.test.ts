// SPDX-License-Identifier: GPL-2.0-only

import { describe, expect, it } from "vitest";

import { childPath, parentPath } from "../src/features/file-browser/path";

describe("logical browser paths", () => {
  it("joins a validated hostile leaf without host path interpretation", () => {
    expect(childPath("reports/2026", " September.csv ")).toBe(
      "reports/2026/September.csv",
    );
    expect(parentPath("reports/2026")).toBe("reports");
    expect(parentPath("reports")).toBe("");
  });

  it.each([
    "",
    " ",
    ".",
    "..",
    "../secret",
    "a/b",
    "bad\u0000name",
    "bad\u007fname",
  ])("rejects the unsafe leaf %j", (name) => {
    expect(() => childPath("reports", name)).toThrow("invalid");
  });
});
