// SPDX-License-Identifier: GPL-2.0-only

import { readFile, readdir } from "node:fs/promises";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";
import ts from "typescript";

import fixtureDocument from "../../contracts/fixtures/create-session.json" with { type: "json" };
import {
  zCreateSessionBody,
  zCreateSessionResponse2,
} from "../src/generated/zod.gen";

const generatedDirectory = fileURLToPath(
  new URL("../src/generated/", import.meta.url),
);

describe("Rust and generated Zod contract parity", () => {
  it("uses the exact project licence identifier", () => {
    expect(fixtureDocument.license).toBe("GPL-2.0-only");
  });

  it.each(fixtureDocument.cases)("matches the $name fixture", (fixture) => {
    const schema =
      fixture.direction === "request"
        ? zCreateSessionBody
        : zCreateSessionResponse2;
    const result = schema.safeParse(fixture.value);

    expect(result.success).toBe(fixture.accepted);
    expect(result.success ? result.data : fixture.value).toEqual(fixture.value);
  });

  it("keeps the generated source free of the any type", async () => {
    const sourceNames = (await readdir(generatedDirectory)).filter((name) =>
      name.endsWith(".ts"),
    );

    for (const sourceName of sourceNames) {
      const source = await readFile(
        `${generatedDirectory}/${sourceName}`,
        "utf8",
      );
      expect({
        sourceName,
        unsafeType: hasAnyType(sourceName, source),
      }).toEqual({
        sourceName,
        unsafeType: false,
      });
    }
  });

  it("detects unsafe type syntax without rejecting comments, strings or identifiers", () => {
    for (const source of [
      "type Unsafe = any;",
      "type Nested = { values: Array<any> };",
      "declare function read(): Promise<any>;",
    ]) {
      expect(hasAnyType("unsafe.ts", source)).toBe(true);
    }
    expect(
      hasAnyType(
        "safe.ts",
        `
      // Recorded terminal time, if any.
      type Safe = { any: unknown; description: "any" };
    `,
      ),
    ).toBe(false);
  });
});

function hasAnyType(filename: string, source: string): boolean {
  const file = ts.createSourceFile(
    filename,
    source,
    ts.ScriptTarget.Latest,
    true,
    ts.ScriptKind.TS,
  );
  function visit(node: ts.Node): boolean {
    return (
      node.kind === ts.SyntaxKind.AnyKeyword ||
      (ts.forEachChild(node, visit) ?? false)
    );
  }
  return visit(file);
}
