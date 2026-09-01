// SPDX-License-Identifier: GPL-2.0-only

/** Renders typed request helpers for volume permission administration. */
export function renderPermissionAdministrationRequestTypes() {
  return `export type ListVolumePermissionGrantsRequest = Readonly<{
  volumeId: string;
  cursor?: string;
  limit?: number;
}>;`;
}

/** Renders permission-administration client operations. */
export function renderPermissionAdministrationClientInterface() {
  return `createVolumePermissionGrant(
    volumeId: string,
    request: CreateVolumePermissionGrantRequest,
    csrfToken?: string,
  ): Promise<CreateVolumePermissionGrantResponse>;
  listVolumePermissionGrants(
    request: ListVolumePermissionGrantsRequest,
  ): Promise<ListVolumePermissionGrantsResponse>;
  listNextVolumePermissionGrants(
    nextPageUrl: string,
  ): Promise<ListVolumePermissionGrantsResponse>;
  revokePermissionGrant(
    volumeId: string,
    grantId: string,
    request: RevokePermissionGrantRequest,
    csrfToken?: string,
  ): Promise<RevokePermissionGrantResponse>;`;
}

/** Renders permission-administration client implementations. */
export function renderPermissionAdministrationClientMethods(routes) {
  return `async createVolumePermissionGrant(
      volumeId,
      request,
      csrfToken,
    ): Promise<CreateVolumePermissionGrantResponse> {
      const path = zCreateVolumePermissionGrantPath.parse({
        volume_id: volumeId,
      });
      const body = zCreateVolumePermissionGrantBody.parse(request);
      return requestJson(
        context,
        substitutePathParameter(
          ${JSON.stringify(routes.createVolumePermissionGrant.route)},
          "volume_id",
          path.volume_id,
        ),
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.createVolumePermissionGrant.method)},
        },
        zCreateVolumePermissionGrantResponse2,
      );
    },
    async listVolumePermissionGrants(
      request,
    ): Promise<ListVolumePermissionGrantsResponse> {
      const path = zListVolumePermissionGrantsPath.parse({
        volume_id: request.volumeId,
      });
      const query = zListVolumePermissionGrantsQuery.parse({
        cursor: request.cursor,
        limit: request.limit,
      });
      return requestJson(
        context,
        appendQuery(
          substitutePathParameter(
            ${JSON.stringify(routes.listVolumePermissionGrants.route)},
            "volume_id",
            path.volume_id,
          ),
          query,
        ),
        { method: ${JSON.stringify(routes.listVolumePermissionGrants.method)} },
        zListVolumePermissionGrantsResponse2,
      );
    },
    async listNextVolumePermissionGrants(
      nextPageUrl,
    ): Promise<ListVolumePermissionGrantsResponse> {
      return requestJson(
        context,
        validatePermissionGrantPageUrl(context.apiRoot, nextPageUrl),
        { method: "GET" },
        zListVolumePermissionGrantsResponse2,
      );
    },
    async revokePermissionGrant(
      volumeId,
      grantId,
      request,
      csrfToken,
    ): Promise<RevokePermissionGrantResponse> {
      const path = zRevokePermissionGrantPath.parse({
        grant_id: grantId,
        volume_id: volumeId,
      });
      const body = zRevokePermissionGrantBody.parse(request);
      return requestJson(
        context,
        substitutePathParameter(
          substitutePathParameter(
            ${JSON.stringify(routes.revokePermissionGrant.route)},
            "volume_id",
            path.volume_id,
          ),
          "grant_id",
          path.grant_id,
        ),
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.revokePermissionGrant.method)},
        },
        zRevokePermissionGrantResponse2,
      );
    },`;
}

/** Renders validation for server-provided grant-page continuations. */
export function renderPermissionAdministrationRuntime() {
  return `function validatePermissionGrantPageUrl(
  apiRoot: URL,
  value: string,
): string {
  if (value.length === 0 || value.length > 16_384 || !value.startsWith("/")) {
    throw new TypeError("permission-grant page URL is invalid");
  }
  const route = new URL(value, apiRoot.origin);
  const prefix = "/api/latest/admin/volumes/";
  const suffix = "/permission-grants";
  if (
    route.origin !== apiRoot.origin ||
    route.username !== "" ||
    route.password !== "" ||
    route.hash !== "" ||
    !route.pathname.startsWith(prefix) ||
    !route.pathname.endsWith(suffix)
  ) {
    throw new TypeError("permission-grant page URL is outside the administration API");
  }
  const volumeId = route.pathname.slice(prefix.length, -suffix.length);
  zListVolumePermissionGrantsPath.parse({ volume_id: volumeId });
  const names = [...route.searchParams.keys()];
  if (
    names.some((name) => name !== "cursor" && name !== "limit") ||
    new Set(names).size !== names.length
  ) {
    throw new TypeError("permission-grant page URL has invalid query fields");
  }
  const rawLimit = route.searchParams.get("limit");
  zListVolumePermissionGrantsQuery.parse({
    cursor: route.searchParams.get("cursor") ?? undefined,
    limit: rawLimit === null ? undefined : parseSafeDecimalHeader(rawLimit),
  });
  return route.pathname + route.search;
}`;
}
