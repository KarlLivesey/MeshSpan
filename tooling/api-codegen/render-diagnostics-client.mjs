// SPDX-License-Identifier: GPL-2.0-only

/** Derives the diagnostic route and independent response budget from Rust's OpenAPI. */
export function renderDiagnosticsClientMethods(routes) {
  return [
    renderMethod(routes.readMetadataDiagnostics, "MetadataDiagnosticsResponse"),
    renderMethod(routes.readDiagnosticsBundle, "DiagnosticsBundleResponse"),
  ].join("\n");
}

function renderMethod(route, responseType) {
  const maximumBytes = route.operation["x-meshspan-response-max-bytes"];
  if (
    !Number.isSafeInteger(maximumBytes) ||
    maximumBytes < 1 ||
    maximumBytes > 1_048_576
  ) {
    throw new Error(
      "diagnostic response requires a bounded Rust-authored byte limit",
    );
  }
  return `async ${route.operation.operationId}(signal): Promise<${responseType}> {
      return requestJson(context, ${JSON.stringify(route.route)}, {
        method: ${JSON.stringify(route.method)},
        ...(signal === undefined ? {} : { signal }),
      }, z${responseType}, ${String(maximumBytes)});
    },`;
}
