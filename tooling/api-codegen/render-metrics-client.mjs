// SPDX-License-Identifier: GPL-2.0-only

/** Renders the replicated exporter configuration surface, not an implicit telemetry sink. */
export function renderMetricsClientInterface() {
  return `getMetricsExporter(): Promise<MetricsExporterResponse>;
  configureMetricsExporter(request: ConfigureMetricsExporterRequest, csrfToken?: string): Promise<ConfigureMetricsExporterResponse>;
  getMetricHistory(query?: GetMetricHistoryData["query"]): Promise<MetricHistoryResponse>;
  getNextMetricHistory(nextPageUrl: string): Promise<MetricHistoryResponse>;`;
}

/** Reads routes and validators from the Rust-authored OpenAPI contract. */
export function renderMetricsClientMethods(routes) {
  const maximumBytes =
    routes.getMetricHistory.operation["x-meshspan-response-max-bytes"];
  if (
    !Number.isSafeInteger(maximumBytes) ||
    maximumBytes < 1 ||
    maximumBytes > 1_048_576
  ) {
    throw new Error(
      "metric history requires a bounded Rust-authored response limit",
    );
  }
  return `async getMetricsExporter(): Promise<MetricsExporterResponse> {
      return requestJson(context, ${JSON.stringify(routes.getMetricsExporter.route)},
        { method: ${JSON.stringify(routes.getMetricsExporter.method)} }, zGetMetricsExporterResponse);
    },
    async configureMetricsExporter(request, csrfToken): Promise<ConfigureMetricsExporterResponse> {
      const body = zConfigureMetricsExporterBody.parse(request);
      return requestJson(context, ${JSON.stringify(routes.configureMetricsExporter.route)},
        { body: JSON.stringify(body), headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.configureMetricsExporter.method)} }, zConfigureMetricsExporterResponse2);
    },
    async getMetricHistory(query = {}): Promise<MetricHistoryResponse> {
      const input = zGetMetricHistoryQuery.parse(query);
      const parameters = new URLSearchParams();
      if (input.resolution !== undefined) parameters.set("resolution", input.resolution);
      if (input.history_id !== undefined) parameters.set("history_id", input.history_id);
      if (input.before !== undefined) parameters.set("before", input.before);
      const suffix = parameters.toString();
      return requestJson(context, ${JSON.stringify(routes.getMetricHistory.route)} + (suffix ? "?" + suffix : ""),
        { method: ${JSON.stringify(routes.getMetricHistory.method)} }, zGetMetricHistoryResponse, ${String(maximumBytes)});
    },
    async getNextMetricHistory(nextPageUrl): Promise<MetricHistoryResponse> {
      return requestJson(context, validateMetricHistoryPageUrl(context.apiRoot, nextPageUrl),
        { method: "GET" }, zGetMetricHistoryResponse, ${String(maximumBytes)});
    },`;
}

/** Rejects substituted hosts, routes and query fields before any credentials are attached. */
export function renderMetricHistoryRuntime(routes) {
  return `function validateMetricHistoryPageUrl(apiRoot: URL, value: string): string {
  if (!value.startsWith("/") || value.startsWith("//") || value.length > 180) throw new TypeError("metric history page URL is invalid");
  const route = new URL(value, apiRoot.origin);
  if (route.origin !== apiRoot.origin || route.username !== "" || route.password !== "" ||
      route.hash !== "" || route.pathname !== ${JSON.stringify(`/api/latest${routes.getMetricHistory.route}`)}) {
    throw new TypeError("metric history page URL is outside the administration API");
  }
  const names = [...route.searchParams.keys()];
  if (names.length !== 3 || !names.includes("resolution") || !names.includes("history_id") || !names.includes("before")) {
    throw new TypeError("metric history page URL has invalid query fields");
  }
  zGetMetricHistoryQuery.parse({ resolution: route.searchParams.get("resolution"),
    history_id: route.searchParams.get("history_id"), before: route.searchParams.get("before") });
  return route.pathname + route.search;
}`;
}
