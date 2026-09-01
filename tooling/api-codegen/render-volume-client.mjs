// SPDX-License-Identifier: GPL-2.0-only

/** Renders permission-filtered logical-volume client operations. */
export function renderVolumeClientInterface() {
  return `createVolume(
    request: CreateVolumeRequest,
    csrfToken?: string,
  ): Promise<CreateVolumeResponse>;
  listVolumes(
    request?: ListVolumesRequest,
  ): Promise<ListVolumesResponse>;
  listNextVolumes(nextPageUrl: string): Promise<ListVolumesResponse>;`;
}

/** Renders permission-filtered logical-volume client implementations. */
export function renderVolumeClientMethods(routes) {
  return `async createVolume(request, csrfToken): Promise<CreateVolumeResponse> {
      const body = zCreateVolumeBody.parse(request);
      return requestJson(
        context,
        ${JSON.stringify(routes.createVolume.route)},
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.createVolume.method)},
        },
        zCreateVolumeResponse2,
      );
    },
    async listVolumes(request = {}): Promise<ListVolumesResponse> {
      const query = zListVolumesQuery.parse(request);
      return validateVolumePage(
        await requestJson(
          context,
          appendQuery(${JSON.stringify(routes.listVolumes.route)}, query),
          { method: ${JSON.stringify(routes.listVolumes.method)} },
          zListVolumesResponse2,
        ),
      );
    },
    async listNextVolumes(nextPageUrl): Promise<ListVolumesResponse> {
      return validateVolumePage(
        await requestJson(
          context,
          validateVolumePageUrl(context.apiRoot, nextPageUrl),
          { method: "GET" },
          zListVolumesResponse2,
        ),
      );
    },`;
}

/** Renders strict validation for ready-to-follow volume pages. */
export function renderVolumeClientRuntime(routes) {
  return `const VOLUME_RIGHT_ORDER = [
  "traverse",
  "list",
  "read_data",
  "create_child",
  "write_data",
  "append_data",
  "rename",
  "delete",
  "read_attributes",
  "write_attributes",
  "read_permissions",
  "change_permissions",
  "change_owner",
] as const;

function validateVolumePage(page: ListVolumesResponse): ListVolumesResponse {
  for (const volume of page.volumes) {
    validateVolumeRights(volume.effective_rights);
  }
  return page;
}

function validateVolumeRights(rights: readonly string[]): void {
  let previous = -1;
  for (const right of rights) {
    const position = VOLUME_RIGHT_ORDER.indexOf(
      right as (typeof VOLUME_RIGHT_ORDER)[number],
    );
    if (position <= previous) {
      throw new TypeError("volume rights are duplicated or out of order");
    }
    previous = position;
  }
  if (rights[0] !== "traverse" || rights[1] !== "list") {
    throw new TypeError("volume page contains a non-browseable volume");
  }
}

function validateVolumePageUrl(apiRoot: URL, value: string): string {
  if (value.length === 0 || value.length > 16_384 || !value.startsWith("/")) {
    throw new TypeError("volume page URL is invalid");
  }
  const route = new URL(value, apiRoot.origin);
  if (
    route.origin !== apiRoot.origin ||
    route.username !== "" ||
    route.password !== "" ||
    route.hash !== "" ||
    route.pathname !== ${JSON.stringify(`/api/latest${routes.listVolumes.route}`)}
  ) {
    throw new TypeError("volume page URL is outside the volume API");
  }
  validateVolumePageQuery(route);
  return route.pathname + route.search;
}

function validateVolumePageQuery(route: URL): void {
  const names = [...route.searchParams.keys()];
  if (
    names.some((name) => name !== "cursor" && name !== "limit") ||
    new Set(names).size !== names.length
  ) {
    throw new TypeError("volume page URL has invalid query fields");
  }
  const rawLimit = route.searchParams.get("limit");
  zListVolumesQuery.parse({
    cursor: route.searchParams.get("cursor") ?? undefined,
    limit: rawLimit === null ? undefined : parseSafeDecimalHeader(rawLimit),
  });
}`;
}
