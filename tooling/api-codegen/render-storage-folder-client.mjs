// SPDX-License-Identifier: GPL-2.0-only

/** Renders local storage-folder request helpers. */
export function renderStorageFolderRequestTypes() {
  return `export type ListStorageFoldersRequest = Readonly<{
  cursor?: string;
  limit?: number;
}>;`;
}

/** Renders manager-only local storage-folder client operations. */
export function renderStorageFolderClientInterface() {
  return `listStorageFolders(
    request?: ListStorageFoldersRequest,
  ): Promise<ListStorageFoldersResponse>;
  listNextStorageFolders(
    nextPageUrl: string,
  ): Promise<ListStorageFoldersResponse>;
  registerStorageFolder(
    request: RegisterStorageFolderRequest,
    csrfToken?: string,
  ): Promise<RegisterStorageFolderResponse>;`;
}

/** Renders local storage-folder client implementations. */
export function renderStorageFolderClientMethods(routes) {
  return `async listStorageFolders(request = {}): Promise<ListStorageFoldersResponse> {
      const query = zListStorageFoldersQuery.parse(request);
      return requestJson(
        context,
        appendQuery(${JSON.stringify(routes.listStorageFolders.route)}, query),
        { method: ${JSON.stringify(routes.listStorageFolders.method)} },
        zListStorageFoldersResponse2,
      );
    },
    async listNextStorageFolders(nextPageUrl): Promise<ListStorageFoldersResponse> {
      return requestJson(
        context,
        validateStorageFolderPageUrl(context.apiRoot, nextPageUrl),
        { method: "GET" },
        zListStorageFoldersResponse2,
      );
    },
    async registerStorageFolder(request, csrfToken): Promise<RegisterStorageFolderResponse> {
      const body = zRegisterStorageFolderBody.parse(request);
      return requestJson(
        context,
        ${JSON.stringify(routes.registerStorageFolder.route)},
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.registerStorageFolder.method)},
        },
        zRegisterStorageFolderResponse2,
      );
    },`;
}

/** Renders validation for server-provided storage-folder continuations. */
export function renderStorageFolderRuntime(routes) {
  return `function validateStorageFolderPageUrl(apiRoot: URL, value: string): string {
  if (value.length === 0 || value.length > 16_384 || !value.startsWith("/")) {
    throw new TypeError("storage-folder page URL is invalid");
  }
  const route = new URL(value, apiRoot.origin);
  if (
    route.origin !== apiRoot.origin ||
    route.username !== "" ||
    route.password !== "" ||
    route.hash !== "" ||
    route.pathname !== ${JSON.stringify(`/api/latest${routes.listStorageFolders.route}`)}
  ) {
    throw new TypeError("storage-folder page URL is outside the administration API");
  }
  const names = [...route.searchParams.keys()];
  if (
    names.some((name) => name !== "cursor" && name !== "limit") ||
    new Set(names).size !== names.length
  ) {
    throw new TypeError("storage-folder page URL has invalid query fields");
  }
  const rawLimit = route.searchParams.get("limit");
  zListStorageFoldersQuery.parse({
    cursor: route.searchParams.get("cursor") ?? undefined,
    limit: rawLimit === null ? undefined : parseSafeDecimalHeader(rawLimit),
  });
  return route.pathname + route.search;
}`;
}
