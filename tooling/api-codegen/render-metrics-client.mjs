// SPDX-License-Identifier: GPL-2.0-only

/** Renders the replicated exporter configuration surface, not an implicit telemetry sink. */
export function renderMetricsClientInterface() {
  return `getMetricsExporter(): Promise<MetricsExporterResponse>;
  configureMetricsExporter(request: ConfigureMetricsExporterRequest, csrfToken?: string): Promise<ConfigureMetricsExporterResponse>;`;
}

/** Reads routes and validators from the Rust-authored OpenAPI contract. */
export function renderMetricsClientMethods(routes) {
  return `async getMetricsExporter(): Promise<MetricsExporterResponse> {
      return requestJson(context, ${JSON.stringify(routes.getMetricsExporter.route)},
        { method: ${JSON.stringify(routes.getMetricsExporter.method)} }, zGetMetricsExporterResponse);
    },
    async configureMetricsExporter(request, csrfToken): Promise<ConfigureMetricsExporterResponse> {
      const body = zConfigureMetricsExporterBody.parse(request);
      return requestJson(context, ${JSON.stringify(routes.configureMetricsExporter.route)},
        { body: JSON.stringify(body), headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.configureMetricsExporter.method)} }, zConfigureMetricsExporterResponse2);
    },`;
}
