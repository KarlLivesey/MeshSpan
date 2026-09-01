// SPDX-License-Identifier: GPL-2.0-only

/** Renders native directory request types. */
export function renderDirectoryRequestTypes() {
  return `export type ListDirectoryRequest = Readonly<{
  volumeId: string;
  path?: string;
  cursor?: string;
  limit?: number;
}>;`;
}

/** Renders native directory client operations. */
export function renderDirectoryClientInterface() {
  return `listDirectory(request: ListDirectoryRequest): Promise<ListDirectoryResponse>;
  listNextDirectory(nextPageUrl: string): Promise<ListDirectoryResponse>;`;
}

/** Renders native directory client implementations. */
export function renderDirectoryClientMethods(routes) {
  return `async listDirectory(request): Promise<ListDirectoryResponse> {
      const path = zListDirectoryPath.parse({ volume_id: request.volumeId });
      const query = zListDirectoryQuery.parse({
        cursor: request.cursor,
        limit: request.limit,
        path: request.path,
      });
      if (query.path !== undefined) {
        validateNamespacePath(query.path);
      }
      return requestJson(
        context,
        appendQuery(
          substitutePathParameter(
            ${JSON.stringify(routes.listDirectory.route)},
            "volume_id",
            path.volume_id,
          ),
          query,
        ),
        { method: ${JSON.stringify(routes.listDirectory.method)} },
        zListDirectoryResponse2,
      );
    },
    async listNextDirectory(nextPageUrl): Promise<ListDirectoryResponse> {
      return requestJson(
        context,
        validateDirectoryPageUrl(context.apiRoot, nextPageUrl),
        { method: ${JSON.stringify(routes.listDirectory.method)} },
        zListDirectoryResponse2,
      );
    },`;
}

/** Renders strict ready-to-follow directory-page validation. */
export function renderDirectoryClientRuntime() {
  return `function validateDirectoryPageUrl(apiRoot: URL, value: string): string {
  if (value.length === 0 || value.length > 16_384 || !value.startsWith("/")) {
    throw new TypeError("directory page URL is invalid");
  }
  const route = new URL(value, apiRoot.origin);
  validateDirectoryPageLocation(apiRoot, route);
  validateDirectoryPageQuery(route);
  return route.pathname + route.search;
}

function validateDirectoryPageLocation(apiRoot: URL, route: URL): void {
  const segments = route.pathname.split("/");
  if (
    route.origin !== apiRoot.origin ||
    route.username !== "" ||
    route.password !== "" ||
    route.hash !== "" ||
    segments.length !== 6 ||
    segments[1] !== "api" ||
    segments[2] !== "latest" ||
    segments[3] !== "volumes" ||
    segments[5] !== "directory-entries"
  ) {
    throw new TypeError("directory page URL is outside the native file API");
  }
  zListDirectoryPath.parse({ volume_id: segments[4] });
}

function validateDirectoryPageQuery(route: URL): void {
  const names = [...route.searchParams.keys()];
  if (
    names.some(
      (name) => name !== "cursor" && name !== "limit" && name !== "path",
    ) ||
    new Set(names).size !== names.length
  ) {
    throw new TypeError("directory page URL has invalid query fields");
  }
  const rawLimit = route.searchParams.get("limit");
  const query = zListDirectoryQuery.parse({
    cursor: route.searchParams.get("cursor") ?? undefined,
    limit: rawLimit === null ? undefined : parseSafeDecimalHeader(rawLimit),
    path: route.searchParams.get("path") ?? undefined,
  });
  if (query.path !== undefined) {
    validateNamespacePath(query.path);
  }
}`;
}
