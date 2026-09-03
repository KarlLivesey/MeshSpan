// SPDX-License-Identifier: GPL-2.0-only

/** Renders storage-drain pagination input. */
export function renderStorageDrainRequestTypes() {
  return `export type ListStorageDrainsRequest = Readonly<{
  cursor?: string;
  limit?: number;
}>;`;
}

/** Renders manager-only storage-drain operations. */
export function renderStorageDrainClientInterface() {
  return `beginStorageDrain(
    request: BeginStorageDrainRequest,
    csrfToken?: string,
  ): Promise<BeginStorageDrainResponse>;
  getStorageDrain(drainId: string): Promise<StorageDrainSummary>;
  listStorageDrains(
    request?: ListStorageDrainsRequest,
  ): Promise<ListStorageDrainsResponse>;
  listNextStorageDrains(
    nextPageUrl: string,
  ): Promise<ListStorageDrainsResponse>;`;
}

/** Renders storage-drain client implementations. */
export function renderStorageDrainClientMethods(routes) {
  return `async beginStorageDrain(request, csrfToken): Promise<BeginStorageDrainResponse> {
      const body = zBeginStorageDrainBody.parse(request);
      return requestJson(
        context,
        ${JSON.stringify(routes.beginStorageDrain.route)},
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.beginStorageDrain.method)},
        },
        zBeginStorageDrainResponse2,
      );
    },
    async getStorageDrain(drainId): Promise<StorageDrainSummary> {
      const path = zGetStorageDrainPath.parse({ drain_id: drainId });
      return requestJson(
        context,
        substitutePathParameter(
          ${JSON.stringify(routes.getStorageDrain.route)},
          "drain_id",
          path.drain_id,
        ),
        { method: ${JSON.stringify(routes.getStorageDrain.method)} },
        zGetStorageDrainResponse,
      );
    },
    async listStorageDrains(request = {}): Promise<ListStorageDrainsResponse> {
      const query = zListStorageDrainsQuery.parse(request);
      return requestJson(
        context,
        appendQuery(${JSON.stringify(routes.listStorageDrains.route)}, query),
        { method: ${JSON.stringify(routes.listStorageDrains.method)} },
        zListStorageDrainsResponse2,
      );
    },
    async listNextStorageDrains(nextPageUrl): Promise<ListStorageDrainsResponse> {
      return requestJson(
        context,
        validateStorageDrainPageUrl(context.apiRoot, nextPageUrl),
        { method: "GET" },
        zListStorageDrainsResponse2,
      );
    },`;
}

/** Renders validation for server-provided storage-drain continuations. */
export function renderStorageDrainRuntime(routes) {
  return `function validateStorageDrainPageUrl(apiRoot: URL, value: string): string {
  if (value.length === 0 || value.length > 16_384 || !value.startsWith("/")) {
    throw new TypeError("storage-drain page URL is invalid");
  }
  const route = new URL(value, apiRoot.origin);
  if (
    route.origin !== apiRoot.origin ||
    route.username !== "" ||
    route.password !== "" ||
    route.hash !== "" ||
    route.pathname !== ${JSON.stringify(`/api/latest${routes.listStorageDrains.route}`)}
  ) {
    throw new TypeError("storage-drain page URL is outside the administration API");
  }
  const names = [...route.searchParams.keys()];
  if (
    names.some((name) => name !== "cursor" && name !== "limit") ||
    new Set(names).size !== names.length
  ) {
    throw new TypeError("storage-drain page URL has invalid query fields");
  }
  const rawLimit = route.searchParams.get("limit");
  zListStorageDrainsQuery.parse({
    cursor: route.searchParams.get("cursor") ?? undefined,
    limit: rawLimit === null ? undefined : parseSafeDecimalHeader(rawLimit),
  });
  return route.pathname + route.search;
}`;
}
