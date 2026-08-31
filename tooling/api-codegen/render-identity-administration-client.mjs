// SPDX-License-Identifier: GPL-2.0-only

/** Renders the native principal-administration client interface. */
export function renderIdentityAdministrationClientInterface() {
  return `createGroup(
    request: CreateGroupRequest,
    csrfToken?: string,
  ): Promise<CreatePrincipalResponse>;
  createUser(
    request: CreateUserRequest,
    csrfToken?: string,
  ): Promise<CreatePrincipalResponse>;
  listGroups(request?: ListPrincipalsRequest): Promise<ListPrincipalsResponse>;
  listUsers(request?: ListPrincipalsRequest): Promise<ListPrincipalsResponse>;
  listNextPrincipals(nextPageUrl: string): Promise<ListPrincipalsResponse>;`;
}

/** Renders the native principal-administration client implementations. */
export function renderIdentityAdministrationClientMethods(routes) {
  return `async createGroup(request, csrfToken): Promise<CreatePrincipalResponse> {
      const body = zCreateGroupBody.parse(request);
      return requestJson(
        context,
        ${JSON.stringify(routes.createGroup.route)},
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.createGroup.method)},
        },
        zCreateGroupResponse,
      );
    },
    async createUser(request, csrfToken): Promise<CreatePrincipalResponse> {
      const body = zCreateUserBody.parse(request);
      return requestJson(
        context,
        ${JSON.stringify(routes.createUser.route)},
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.createUser.method)},
        },
        zCreateUserResponse,
      );
    },
    async listGroups(request = {}): Promise<ListPrincipalsResponse> {
      const query = zListGroupsQuery.parse(request);
      return requestJson(
        context,
        appendQuery(${JSON.stringify(routes.listGroups.route)}, query),
        { method: ${JSON.stringify(routes.listGroups.method)} },
        zListGroupsResponse,
      );
    },
    async listUsers(request = {}): Promise<ListPrincipalsResponse> {
      const query = zListUsersQuery.parse(request);
      return requestJson(
        context,
        appendQuery(${JSON.stringify(routes.listUsers.route)}, query),
        { method: ${JSON.stringify(routes.listUsers.method)} },
        zListUsersResponse,
      );
    },
    async listNextPrincipals(nextPageUrl): Promise<ListPrincipalsResponse> {
      return requestJson(
        context,
        validatePrincipalPageUrl(context.apiRoot, nextPageUrl),
        { method: "GET" },
        zListPrincipalsResponse,
      );
    },`;
}

/** Renders validation for ready-to-follow principal page URLs. */
export function renderIdentityAdministrationRuntime(routes) {
  const paths = [routes.listGroups.route, routes.listUsers.route].map((route) =>
    JSON.stringify(`/api/latest${route}`),
  );
  return `function validatePrincipalPageUrl(apiRoot: URL, value: string): string {
  if (value.length === 0 || value.length > 16_384 || !value.startsWith("/")) {
    throw new TypeError("principal page URL is invalid");
  }
  const route = new URL(value, apiRoot.origin);
  validatePrincipalPageLocation(apiRoot, route);
  validatePrincipalPageQuery(route);
  return route.pathname + route.search;
}

function validatePrincipalPageLocation(apiRoot: URL, route: URL): void {
  if (
    route.origin !== apiRoot.origin ||
    route.username !== "" ||
    route.password !== "" ||
    route.hash !== "" ||
    ![${paths.join(", ")}].includes(route.pathname)
  ) {
    throw new TypeError("principal page URL is outside the administration API");
  }
}

function validatePrincipalPageQuery(route: URL): void {
  const names = [...route.searchParams.keys()];
  if (
    names.some((name) => name !== "cursor" && name !== "limit") ||
    new Set(names).size !== names.length
  ) {
    throw new TypeError("principal page URL has invalid query fields");
  }
  const rawLimit = route.searchParams.get("limit");
  const query = {
    cursor: route.searchParams.get("cursor") ?? undefined,
    limit: rawLimit === null ? undefined : parseSafeDecimalHeader(rawLimit),
  };
  if (route.pathname.endsWith("/groups")) {
    zListGroupsQuery.parse(query);
  } else {
    zListUsersQuery.parse(query);
  }
}`;
}
