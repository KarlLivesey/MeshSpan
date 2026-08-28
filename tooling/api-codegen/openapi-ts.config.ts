// SPDX-License-Identifier: GPL-2.0-only

import { defineConfig } from "@hey-api/openapi-ts";

export default defineConfig({
  input: "../../contracts/openapi/latest.json",
  output: {
    clean: true,
    header: [
      "// SPDX-License-Identifier: GPL-2.0-only",
      "// Generated from the Rust-authored MeshSpan OpenAPI contract. Do not edit.",
    ],
    path: "../../web/src/generated",
  },
  plugins: [
    {
      $resolvers: {
        object: (context) =>
          context.schema.properties
            ? context.nodes.shape(context)
            : context.nodes.base(context),
      },
      name: "@hey-api/typescript",
      topType: "unknown",
    },
    {
      $resolvers: {
        object: (context) => {
          const object = context.nodes.base(context);
          return context.schema.properties
            ? object.attr("strict").call()
            : object;
        },
      },
      compatibilityVersion: 4,
      definitions: true,
      name: "zod",
      requests: true,
      responses: true,
    },
  ],
});
