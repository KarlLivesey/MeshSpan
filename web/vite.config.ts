// SPDX-License-Identifier: GPL-2.0-only

import solid from "@solidjs/vite-plugin";
import { defineConfig } from "vitest/config";

export default defineConfig({
  build: {
    manifest: true,
    sourcemap: true,
  },
  plugins: [solid()],
  server: {
    strictPort: true,
  },
  test: {
    projects: [
      {
        extends: true,
        test: {
          environment: "node",
          include: ["tests/**/*.test.ts"],
          name: "unit",
        },
      },
      {
        extends: true,
        test: {
          environment: "jsdom",
          include: ["tests/**/*.test.tsx"],
          name: "component",
        },
      },
    ],
  },
});
