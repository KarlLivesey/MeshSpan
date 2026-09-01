// SPDX-License-Identifier: GPL-2.0-only

/** Renders topology pagination request input. */
export function renderTopologyRequestTypes() {
  return `export type ListTopologyRequest = Readonly<{
  cursor?: string;
  limit?: number;
}>;

export type SetFaultGroupMembershipInput = Readonly<{
  groupId: string;
  hostId: string;
  request: SetFaultGroupMembershipRequest;
}>;`;
}

/** Renders manager-only topology client operations. */
export function renderTopologyClientInterface() {
  return `listTopologyNodes(request?: ListTopologyRequest): Promise<ListTopologyNodesResponse>;
  listNextTopologyNodes(nextPageUrl: string): Promise<ListTopologyNodesResponse>;
  listTopologyTargets(request?: ListTopologyRequest): Promise<ListTopologyTargetsResponse>;
  listNextTopologyTargets(nextPageUrl: string): Promise<ListTopologyTargetsResponse>;
  listFaultGroups(request?: ListTopologyRequest): Promise<ListFaultGroupsResponse>;
  listNextFaultGroups(nextPageUrl: string): Promise<ListFaultGroupsResponse>;
  listFaultGroupMemberships(request?: ListTopologyRequest): Promise<ListFaultGroupMembershipsResponse>;
  listNextFaultGroupMemberships(nextPageUrl: string): Promise<ListFaultGroupMembershipsResponse>;
  createFaultGroup(request: CreateFaultGroupRequest, csrfToken?: string): Promise<CreateFaultGroupResponse>;
  setFaultGroupMembership(input: SetFaultGroupMembershipInput, csrfToken?: string): Promise<SetFaultGroupMembershipResponse>;`;
}

/** Renders topology client implementations. */
export function renderTopologyClientMethods(routes) {
  const listMethod = (
    name,
    nextName,
    route,
    querySchema,
    responseSchema,
  ) => `async ${name}(request = {}) {
      const query = ${querySchema}.parse(request);
      return requestJson(context, appendQuery(${JSON.stringify(route.route)}, query), { method: ${JSON.stringify(route.method)} }, ${responseSchema});
    },
    async ${nextName}(nextPageUrl) {
      return requestJson(context, validateTopologyPageUrl(context.apiRoot, nextPageUrl), { method: "GET" }, ${responseSchema});
    },`;
  return `${listMethod("listTopologyNodes", "listNextTopologyNodes", routes.listTopologyNodes, "zListTopologyNodesQuery", "zListTopologyNodesResponse2")}
    ${listMethod("listTopologyTargets", "listNextTopologyTargets", routes.listTopologyTargets, "zListTopologyTargetsQuery", "zListTopologyTargetsResponse2")}
    ${listMethod("listFaultGroups", "listNextFaultGroups", routes.listFaultGroups, "zListFaultGroupsQuery", "zListFaultGroupsResponse2")}
    ${listMethod("listFaultGroupMemberships", "listNextFaultGroupMemberships", routes.listFaultGroupMemberships, "zListFaultGroupMembershipsQuery", "zListFaultGroupMembershipsResponse2")}
    async createFaultGroup(request, csrfToken) {
      const body = zCreateFaultGroupBody.parse(request);
      return requestJson(context, ${JSON.stringify(routes.createFaultGroup.route)}, {
        body: JSON.stringify(body),
        headers: mutationHeaders("application/json", csrfToken),
        method: ${JSON.stringify(routes.createFaultGroup.method)},
      }, zCreateFaultGroupResponse2);
    },
    async setFaultGroupMembership(input, csrfToken) {
      const path = zSetFaultGroupMembershipPath.parse({ group_id: input.groupId, host_id: input.hostId });
      const body = zSetFaultGroupMembershipBody.parse(input.request);
      const route = substitutePathParameter(
        substitutePathParameter(${JSON.stringify(routes.setFaultGroupMembership.route)}, "group_id", path.group_id),
        "host_id",
        path.host_id,
      );
      return requestJson(context, route, {
        body: JSON.stringify(body),
        headers: mutationHeaders("application/json", csrfToken),
        method: ${JSON.stringify(routes.setFaultGroupMembership.method)},
      }, zSetFaultGroupMembershipResponse2);
    },`;
}

/** Renders strict validation of server-provided topology continuations. */
export function renderTopologyRuntime(routes) {
  const paths = [
    routes.listTopologyNodes.route,
    routes.listTopologyTargets.route,
    routes.listFaultGroups.route,
    routes.listFaultGroupMemberships.route,
  ].map((route) => `/api/latest${route}`);
  return `function validateTopologyPageUrl(apiRoot: URL, value: string): string {
  if (value.length === 0 || value.length > 16_384 || !value.startsWith("/")) {
    throw new TypeError("topology page URL is invalid");
  }
  const route = new URL(value, apiRoot.origin);
  if (
    route.origin !== apiRoot.origin ||
    route.username !== "" ||
    route.password !== "" ||
    route.hash !== "" ||
    !${JSON.stringify(paths)}.includes(route.pathname)
  ) {
    throw new TypeError("topology page URL is outside the administration API");
  }
  const names = [...route.searchParams.keys()];
  if (names.some((name) => name !== "cursor" && name !== "limit") || new Set(names).size !== names.length) {
    throw new TypeError("topology page URL has invalid query fields");
  }
  const rawLimit = route.searchParams.get("limit");
  zListTopologyNodesQuery.parse({
    cursor: route.searchParams.get("cursor") ?? undefined,
    limit: rawLimit === null ? undefined : parseSafeDecimalHeader(rawLimit),
  });
  return route.pathname + route.search;
}`;
}
