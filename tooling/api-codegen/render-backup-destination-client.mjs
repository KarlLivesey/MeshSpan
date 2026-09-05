// SPDX-License-Identifier: GPL-2.0-only

/** Renders registered backup destination controls. */
export function renderBackupDestinationClientInterface() {
  return `listBackupDestinations(query?: ListBackupDestinationsQuery): Promise<ListBackupDestinationsResponse>;
  listNextBackupDestinations(nextPageUrl: string): Promise<ListBackupDestinationsResponse>;
  configureBackupDestination(request: ConfigureBackupDestinationRequest, csrfToken?: string): Promise<ConfigureBackupDestinationResponse>;`;
}

/** Uses Rust-generated routes and request/response validators. */
export function renderBackupDestinationClientMethods(routes) {
  return `async listBackupDestinations(query = {}): Promise<ListBackupDestinationsResponse> {
      const input = zListBackupDestinationsQuery.parse(query);
      const parameters = new URLSearchParams();
      if (input.limit !== undefined) parameters.set("limit", String(input.limit));
      if (input.cursor !== undefined) parameters.set("cursor", input.cursor);
      const suffix = parameters.toString();
      return requestJson(context,
        ${JSON.stringify(routes.listBackupDestinations.route)} + (suffix ? "?" + suffix : ""),
        { method: ${JSON.stringify(routes.listBackupDestinations.method)} }, zListBackupDestinationsResponse2);
    },
    async listNextBackupDestinations(nextPageUrl): Promise<ListBackupDestinationsResponse> {
      return requestJson(context, validateBackupDestinationPageUrl(context.apiRoot, nextPageUrl),
        { method: "GET" }, zListBackupDestinationsResponse2);
    },
    async configureBackupDestination(request, csrfToken): Promise<ConfigureBackupDestinationResponse> {
      const body = zConfigureBackupDestinationBody.parse(request);
      return requestJson(context, ${JSON.stringify(routes.configureBackupDestination.route)},
        { body: JSON.stringify(body), headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.configureBackupDestination.method)} }, zConfigureBackupDestinationResponse2);
    },`;
}

/** Validates an exact server-provided continuation before sending credentials. */
export function renderBackupDestinationRuntime(routes) {
  return `function validateBackupDestinationPageUrl(apiRoot: URL, value: string): string {
  if (value.length === 0 || value.length > 16_384 || !value.startsWith("/")) {
    throw new TypeError("backup destination page URL is invalid");
  }
  const route = new URL(value, apiRoot.origin);
  if (route.origin !== apiRoot.origin || route.username !== "" || route.password !== "" ||
      route.hash !== "" || route.pathname !== ${JSON.stringify(`/api/latest${routes.listBackupDestinations.route}`)}) {
    throw new TypeError("backup destination page URL is outside the administration API");
  }
  const names = [...route.searchParams.keys()];
  if (names.some((name) => name !== "cursor" && name !== "limit") || new Set(names).size !== names.length) {
    throw new TypeError("backup destination page URL has invalid query fields");
  }
  const rawLimit = route.searchParams.get("limit");
  zListBackupDestinationsQuery.parse({
    cursor: route.searchParams.get("cursor") ?? undefined,
    limit: rawLimit === null ? undefined : parseSafeDecimalHeader(rawLimit),
  });
  return route.pathname + route.search;
}`;
}
