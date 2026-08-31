// SPDX-License-Identifier: GPL-2.0-only

/** Renders the native principal-administration client interface. */
export function renderIdentityAdministrationClientInterface() {
  return `addGroupMember(
    groupId: string,
    request: AddGroupMemberRequest,
    csrfToken?: string,
  ): Promise<AddGroupMemberResponse>;
  createGroup(
    request: CreateGroupRequest,
    csrfToken?: string,
  ): Promise<CreatePrincipalResponse>;
  createUser(
    request: CreateUserRequest,
    csrfToken?: string,
  ): Promise<CreatePrincipalResponse>;
  listGroups(request?: ListPrincipalsRequest): Promise<ListPrincipalsResponse>;
  listGroupMembers(request: ListGroupMembersRequest): Promise<ListGroupMembershipsResponse>;
  listNextGroupMembers(nextPageUrl: string): Promise<ListGroupMembershipsResponse>;
  listUsers(request?: ListPrincipalsRequest): Promise<ListPrincipalsResponse>;
  listNextPrincipals(nextPageUrl: string): Promise<ListPrincipalsResponse>;
  removeGroupMember(
    groupId: string,
    memberPrincipalId: string,
    request: RemoveGroupMemberRequest,
    csrfToken?: string,
  ): Promise<RemoveGroupMemberResponse>;`;
}

/** Renders the native principal-administration client implementations. */
export function renderIdentityAdministrationClientMethods(routes) {
  return `${renderGroupMembershipClientMethods(routes)}
    ${renderPrincipalClientMethods(routes)}`;
}

function renderGroupMembershipClientMethods(routes) {
  return `async addGroupMember(groupId, request, csrfToken): Promise<AddGroupMemberResponse> {
      const path = zAddGroupMemberPath.parse({ group_id: groupId });
      const body = zAddGroupMemberBody.parse(request);
      return requestJson(
        context,
        substitutePathParameter(
          ${JSON.stringify(routes.addGroupMember.route)},
          "group_id",
          path.group_id,
        ),
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.addGroupMember.method)},
        },
        zAddGroupMemberResponse2,
      );
    },
    async listGroupMembers(request): Promise<ListGroupMembershipsResponse> {
      const path = zListGroupMembersPath.parse({ group_id: request.groupId });
      const query = zListGroupMembersQuery.parse({
        cursor: request.cursor,
        limit: request.limit,
      });
      return requestJson(
        context,
        appendQuery(
          substitutePathParameter(
            ${JSON.stringify(routes.listGroupMembers.route)},
            "group_id",
            path.group_id,
          ),
          query,
        ),
        { method: ${JSON.stringify(routes.listGroupMembers.method)} },
        zListGroupMembersResponse,
      );
    },
    async listNextGroupMembers(nextPageUrl): Promise<ListGroupMembershipsResponse> {
      return requestJson(
        context,
        validateGroupMembershipPageUrl(context.apiRoot, nextPageUrl),
        { method: "GET" },
        zListGroupMembersResponse,
      );
    },
    async removeGroupMember(
      groupId,
      memberPrincipalId,
      request,
      csrfToken,
    ): Promise<RemoveGroupMemberResponse> {
      const path = zRemoveGroupMemberPath.parse({
        group_id: groupId,
        member_principal_id: memberPrincipalId,
      });
      const body = zRemoveGroupMemberBody.parse(request);
      const groupRoute = substitutePathParameter(
        ${JSON.stringify(routes.removeGroupMember.route)},
        "group_id",
        path.group_id,
      );
      return requestJson(
        context,
        substitutePathParameter(
          groupRoute,
          "member_principal_id",
          path.member_principal_id,
        ),
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.removeGroupMember.method)},
        },
        zRemoveGroupMemberResponse2,
      );
    },`;
}

function renderPrincipalClientMethods(routes) {
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
}

function validateGroupMembershipPageUrl(apiRoot: URL, value: string): string {
  if (value.length === 0 || value.length > 16_384 || !value.startsWith("/")) {
    throw new TypeError("group-membership page URL is invalid");
  }
  const route = new URL(value, apiRoot.origin);
  const prefix = "/api/latest/admin/groups/";
  const suffix = "/members";
  if (
    route.origin !== apiRoot.origin ||
    route.username !== "" ||
    route.password !== "" ||
    route.hash !== "" ||
    !route.pathname.startsWith(prefix) ||
    !route.pathname.endsWith(suffix)
  ) {
    throw new TypeError("group-membership page URL is outside the administration API");
  }
  const groupId = route.pathname.slice(prefix.length, -suffix.length);
  zListGroupMembersPath.parse({ group_id: groupId });
  validateGroupMembershipPageQuery(route);
  return route.pathname + route.search;
}

function validateGroupMembershipPageQuery(route: URL): void {
  const names = [...route.searchParams.keys()];
  if (
    names.some((name) => name !== "cursor" && name !== "limit") ||
    new Set(names).size !== names.length
  ) {
    throw new TypeError("group-membership page URL has invalid query fields");
  }
  const rawLimit = route.searchParams.get("limit");
  zListGroupMembersQuery.parse({
    cursor: route.searchParams.get("cursor") ?? undefined,
    limit: rawLimit === null ? undefined : parseSafeDecimalHeader(rawLimit),
  });
}`;
}
