// SPDX-License-Identifier: GPL-2.0-only

import assert from "node:assert/strict";
import { test } from "node:test";

import { Linter } from "eslint";
import jsxA11y from "eslint-plugin-jsx-a11y";

const configuration = {
  ...jsxA11y.flatConfigs.strict,
  languageOptions: {
    ecmaVersion: "latest",
    sourceType: "module",
    parserOptions: { ecmaFeatures: { jsx: true } },
  },
};

test("the current accessibility plugin runs its strict rules on ESLint 10", () => {
  assert.match(Linter.version, /^10\./u);
  const source = `const form = <form>
    <label htmlFor="email">Email</label><input id="email" type="email" />
    <button type="submit">Save</button><img src="icon.png" alt="Storage" />
    <a href="/files">Files</a>
  </form>;`;
  assert.deepEqual(new Linter().verify(source, configuration), []);
});

test("invalid markup still produces the expected accessibility findings", () => {
  const source = `const form = <form>
    <img src="icon.png" /><a href="#">Files</a>
    <div onClick={() => {}}>Save</div><label>Unassociated</label>
  </form>;`;
  const messages = new Linter().verify(source, configuration);
  assert.ok(messages.every((message) => !message.fatal));
  assert.deepEqual(
    messages.map((message) => message.ruleId).sort(),
    [
      "jsx-a11y/alt-text",
      "jsx-a11y/anchor-is-valid",
      "jsx-a11y/click-events-have-key-events",
      "jsx-a11y/label-has-associated-control",
      "jsx-a11y/no-static-element-interactions",
    ].sort(),
  );
});
