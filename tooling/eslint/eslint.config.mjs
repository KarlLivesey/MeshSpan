// SPDX-License-Identifier: GPL-2.0-only

import { fileURLToPath } from "node:url";

import eslintComments from "@eslint-community/eslint-plugin-eslint-comments";
import eslint from "@eslint/js";
import vitest from "@vitest/eslint-plugin";
import importX from "eslint-plugin-import-x";
import jsxA11y from "eslint-plugin-jsx-a11y";
import regexp from "eslint-plugin-regexp";
import solid from "eslint-plugin-solid";
import sonarjs from "eslint-plugin-sonarjs";
import globals from "globals";
import typescriptEslint from "typescript-eslint";

const webRoot = fileURLToPath(new URL("../../web/", import.meta.url));
const webFiles = ["web/**/*.ts", "web/**/*.tsx"];
const generatedFiles = ["web/src/generated/**/*.ts"];
const testFiles = ["web/tests/**/*.ts"];
const toolingFiles = ["scripts/**/*.mjs", "tooling/**/*.mjs"];

function forWeb(config) {
  return { ...config, files: webFiles };
}

export default typescriptEslint.config(
  {
    ignores: ["**/node_modules/**", "web/coverage/**"],
  },
  {
    ...eslint.configs.recommended,
    files: toolingFiles,
    languageOptions: {
      globals: globals.node,
    },
    plugins: {
      "@eslint-community/eslint-comments": eslintComments,
    },
    rules: {
      ...eslintComments.configs.recommended.rules,
      complexity: ["error", 12],
      eqeqeq: ["error", "always"],
      "max-depth": ["error", 4],
      "max-lines": [
        "error",
        { max: 500, skipBlankLines: true, skipComments: true },
      ],
      "max-lines-per-function": [
        "error",
        { max: 80, skipBlankLines: true, skipComments: true },
      ],
      "max-nested-callbacks": ["error", 3],
      "max-params": ["error", 5],
      "max-statements": ["error", 40],
      "no-console": "error",
      "no-eval": "error",
      "no-warning-comments": [
        "error",
        { terms: ["fixme"], location: "anywhere" },
      ],
    },
  },
  forWeb(eslint.configs.recommended),
  ...typescriptEslint.configs.strictTypeChecked.map(forWeb),
  ...typescriptEslint.configs.stylisticTypeChecked.map(forWeb),
  forWeb(regexp.configs["flat/recommended"]),
  forWeb(sonarjs.configs.recommended),
  forWeb(importX.flatConfigs.recommended),
  {
    files: webFiles,
    settings: {
      "import-x/resolver": {
        node: { extensions: [".js", ".jsx", ".ts", ".tsx"] },
      },
    },
    languageOptions: {
      globals: {
        ...globals.browser,
        ...globals.es2025,
        ...globals.node,
      },
      parserOptions: {
        projectService: true,
        tsconfigRootDir: webRoot,
      },
    },
    plugins: {
      "@eslint-community/eslint-comments": eslintComments,
      solid,
    },
    rules: {
      ...eslintComments.configs.recommended.rules,
      ...solid.configs.typescript.rules,
      "@typescript-eslint/consistent-type-exports": "error",
      "@typescript-eslint/consistent-type-imports": [
        "error",
        { fixStyle: "inline-type-imports", prefer: "type-imports" },
      ],
      "@typescript-eslint/explicit-module-boundary-types": "error",
      "@typescript-eslint/no-explicit-any": "error",
      "@typescript-eslint/no-floating-promises": "error",
      "@typescript-eslint/no-misused-promises": "error",
      "@typescript-eslint/no-non-null-assertion": "error",
      "@typescript-eslint/no-unnecessary-type-assertion": "error",
      "@typescript-eslint/no-unsafe-argument": "error",
      "@typescript-eslint/no-unsafe-assignment": "error",
      "@typescript-eslint/no-unsafe-call": "error",
      "@typescript-eslint/no-unsafe-member-access": "error",
      "@typescript-eslint/no-unsafe-return": "error",
      "@typescript-eslint/only-throw-error": "error",
      "@typescript-eslint/promise-function-async": "error",
      "@typescript-eslint/require-await": "error",
      "@typescript-eslint/switch-exhaustiveness-check": "error",
      complexity: ["error", 12],
      eqeqeq: ["error", "always"],
      "import-x/no-cycle": ["error", { maxDepth: Infinity }],
      "import-x/no-duplicates": "error",
      "import-x/no-self-import": "error",
      "max-classes-per-file": ["error", 1],
      "max-depth": ["error", 4],
      "max-lines": [
        "error",
        { max: 500, skipBlankLines: true, skipComments: true },
      ],
      "max-lines-per-function": [
        "error",
        { max: 80, skipBlankLines: true, skipComments: true },
      ],
      "max-nested-callbacks": ["error", 3],
      "max-params": ["error", 5],
      "max-statements": ["error", 40],
      "no-alert": "error",
      "no-console": "error",
      "no-debugger": "error",
      "no-eval": "error",
      "no-restricted-globals": [
        "error",
        {
          name: "Date",
          message: "Use Temporal for domain date and time values.",
        },
      ],
      "no-warning-comments": [
        "error",
        { terms: ["fixme"], location: "anywhere" },
      ],
      "sonarjs/cognitive-complexity": ["error", 15],
    },
  },
  {
    files: ["web/**/*.tsx"],
    ...jsxA11y.flatConfigs.strict,
  },
  {
    files: testFiles,
    ...vitest.configs.recommended,
    rules: {
      ...vitest.configs.recommended.rules,
      "vitest/consistent-test-it": ["error", { fn: "it" }],
      "vitest/no-disabled-tests": "error",
      "vitest/no-focused-tests": "error",
      // Promise-returning test doubles deliberately preserve the Fetch signature.
      "@typescript-eslint/require-await": "off",
      // Test credentials are inert fixtures, never deployable secrets.
      "sonarjs/no-hardcoded-passwords": "off",
    },
  },
  {
    files: generatedFiles,
    rules: {
      "@typescript-eslint/array-type": "off",
      "@typescript-eslint/consistent-indexed-object-style": "off",
      "@typescript-eslint/consistent-type-definitions": "off",
      "@typescript-eslint/no-misused-spread": "off",
      "@typescript-eslint/prefer-optional-chain": "off",
      "max-lines": "off",
      "max-lines-per-function": "off",
      "max-statements": "off",
      "no-control-regex": "off",
      "sonarjs/cognitive-complexity": "off",
    },
  },
);
