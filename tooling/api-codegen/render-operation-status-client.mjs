// SPDX-License-Identifier: GPL-2.0-only

/** Renders typed request helpers for operation administration. */
export function renderOperationStatusRequestTypes() {
  return `export type ListOperationsRequest = Readonly<{
  cursor?: string;
  limit?: number;
}>;`;
}

/** Renders durable-operation client operations. */
export function renderOperationStatusClientInterface() {
  return `getOperationStatus(operationId: string): Promise<OperationStatusResponse>;
  listOperations(request?: ListOperationsRequest): Promise<ListOperationsResponse>;
  listNextOperations(nextPageUrl: string): Promise<ListOperationsResponse>;`;
}

/** Renders the durable-operation client implementation. */
export function renderOperationStatusClientMethods(routes) {
  return `async getOperationStatus(operationId): Promise<OperationStatusResponse> {
      const path = zGetOperationStatusPath.parse({ operation_id: operationId });
      return requestJson(
        context,
        substitutePathParameter(
          ${JSON.stringify(routes.getOperationStatus.route)},
          "operation_id",
          path.operation_id,
        ),
        { method: ${JSON.stringify(routes.getOperationStatus.method)} },
        zGetOperationStatusResponse,
      );
    },
    async listOperations(request = {}): Promise<ListOperationsResponse> {
      const query = zListOperationsQuery.parse(request);
      return requestJson(
        context,
        appendQuery(${JSON.stringify(routes.listOperations.route)}, query),
        { method: ${JSON.stringify(routes.listOperations.method)} },
        zListOperationsResponse,
      );
    },
    async listNextOperations(nextPageUrl): Promise<ListOperationsResponse> {
      return requestJson(
        context,
        validateOperationPageUrl(context.apiRoot, nextPageUrl),
        { method: "GET" },
        zListOperationsResponse,
      );
    },`;
}

/** Renders validation for server-provided operation-page continuations. */
export function renderOperationStatusRuntime() {
  return `function validateOperationPageUrl(apiRoot: URL, value: string): string {
  if (value.length === 0 || value.length > 16_384 || !value.startsWith("/")) {
    throw new TypeError("operation page URL is invalid");
  }
  const route = new URL(value, apiRoot.origin);
  if (!isOperationPageRoute(apiRoot, route)) {
    throw new TypeError("operation page URL is outside the administration API");
  }
  const names = [...route.searchParams.keys()];
  if (
    names.some((name) => name !== "cursor" && name !== "limit") ||
    new Set(names).size !== names.length
  ) {
    throw new TypeError("operation page URL has invalid query fields");
  }
  const rawLimit = route.searchParams.get("limit");
  zListOperationsQuery.parse({
    cursor: route.searchParams.get("cursor") ?? undefined,
    limit: rawLimit === null ? undefined : parseSafeDecimalHeader(rawLimit),
  });
  return route.pathname + route.search;
}

function isOperationPageRoute(apiRoot: URL, route: URL): boolean {
  return (
    route.origin === apiRoot.origin &&
    route.username === "" &&
    route.password === "" &&
    route.hash === "" &&
    route.pathname === "/api/latest/admin/operations"
  );
}`;
}
