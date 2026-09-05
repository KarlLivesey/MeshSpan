// SPDX-License-Identifier: GPL-2.0-only

import assert from "node:assert/strict";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

import { readBoundedUtf8 } from "./fetch-contract.mjs";

test("OpenAPI source accepts the measured schema size but enforces its 2 MiB ceiling", async () => {
  const directory = await mkdtemp(join(tmpdir(), "meshspan-contract-bound-"));
  try {
    const source = join(directory, "openapi.json");
    const maximum = 2 * 1024 * 1024;
    const valid = "a".repeat(maximum);
    await writeFile(source, valid);
    assert.equal(await readBoundedUtf8(source), valid);
    await writeFile(source, `${valid}a`);
    await assert.rejects(readBoundedUtf8(source), /no larger than 2 MiB/);
    await writeFile(source, Buffer.from([0xff]));
    await assert.rejects(readBoundedUtf8(source), TypeError);
    await assert.rejects(readBoundedUtf8(directory), /regular file/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});
