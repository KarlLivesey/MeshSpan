// SPDX-License-Identifier: GPL-2.0-only

/** Renders the native administration history client. */
export function renderBackupHistoryClientInterface() {
  return `listBackupRuns(query?: ListBackupRunsQuery): Promise<ListBackupRunsResponse>;
  listNextBackupRuns(nextPageUrl: string): Promise<ListBackupRunsResponse>;`;
}

/** Uses generated structural validators on both sides of the request. */
export function renderBackupHistoryClientMethods(routes) {
  return `async listBackupRuns(query = {}): Promise<ListBackupRunsResponse> {
      const input = zListBackupRunsQuery.parse(query);
      const parameters = new URLSearchParams();
      if (input.limit !== undefined) parameters.set("limit", String(input.limit));
      if (input.cursor !== undefined) parameters.set("cursor", input.cursor);
      const suffix = parameters.toString();
      return requestJson(context, ${JSON.stringify(routes.listBackupRuns.route)} + (suffix ? "?" + suffix : ""),
        { method: ${JSON.stringify(routes.listBackupRuns.method)} }, zListBackupRunsResponse2);
    },
    async listNextBackupRuns(nextPageUrl): Promise<ListBackupRunsResponse> {
      return requestJson(context, validateBackupHistoryPageUrl(context.apiRoot, nextPageUrl),
        { method: "GET" }, zListBackupRunsResponse2);
    },`;
}

/** Rejects external and substituted continuation routes before attaching credentials. */
export function renderBackupHistoryRuntime(routes) {
  return `function validateBackupHistoryPageUrl(apiRoot: URL, value: string): string {
  if (!value.startsWith("/") || value.length > 512) throw new TypeError("backup history page URL is invalid");
  const route = new URL(value, apiRoot.origin);
  if (route.origin !== apiRoot.origin || route.username !== "" || route.password !== "" ||
      route.hash !== "" || route.pathname !== ${JSON.stringify(`/api/latest${routes.listBackupRuns.route}`)}) {
    throw new TypeError("backup history page URL is outside the administration API");
  }
  const names = [...route.searchParams.keys()];
  if (names.length !== 2 || !names.includes("cursor") || !names.includes("limit")) {
    throw new TypeError("backup history page URL has invalid query fields");
  }
  const rawLimit = route.searchParams.get("limit");
  zListBackupRunsQuery.parse({
    cursor: route.searchParams.get("cursor"),
    limit: rawLimit === null ? undefined : parseSafeDecimalHeader(rawLimit),
  });
  return route.pathname + route.search;
}`;
}
