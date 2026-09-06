// SPDX-License-Identifier: GPL-2.0-only

/** Renders typed request helpers for certificate administration. */
export function renderCertificateRequestTypes() {
  return `export type ListManualDnsTasksRequest = Readonly<{
  cursor?: string;
  limit?: number;
}>;`;
}

/** Renders certificate-administration client operations. */
export function renderCertificateClientInterface() {
  return `getCertificateStatus(): Promise<CertificateStatusResponse>;
  listManualDnsTasks(
    request?: ListManualDnsTasksRequest,
  ): Promise<ListManualDnsTasksResponse>;
  listNextManualDnsTasks(
    nextPageUrl: string,
  ): Promise<ListManualDnsTasksResponse>;
  provisionCertificate(
    request: ProvisionCertificateRequest,
    csrfToken?: string,
  ): Promise<ProvisionCertificateResponse>;
  provisionMeshLocalCertificate(
    request: ProvisionMeshLocalCertificateRequest,
    csrfToken?: string,
  ): Promise<ProvisionMeshLocalCertificateResponse>;`;
}

/** Renders certificate-administration client implementations. */
export function renderCertificateClientMethods(routes) {
  return `async getCertificateStatus(): Promise<CertificateStatusResponse> {
      return requestJson(
        context,
        ${JSON.stringify(routes.getCertificateStatus.route)},
        { method: ${JSON.stringify(routes.getCertificateStatus.method)} },
        zGetCertificateStatusResponse,
      );
    },
    async listManualDnsTasks(request = {}): Promise<ListManualDnsTasksResponse> {
      const query = zListManualDnsTasksQuery.parse(request);
      return requestJson(
        context,
        appendQuery(${JSON.stringify(routes.listManualDnsTasks.route)}, query),
        { method: ${JSON.stringify(routes.listManualDnsTasks.method)} },
        zListManualDnsTasksResponse2,
      );
    },
    async listNextManualDnsTasks(nextPageUrl): Promise<ListManualDnsTasksResponse> {
      return requestJson(
        context,
        validateManualDnsTaskPageUrl(context.apiRoot, nextPageUrl),
        { method: "GET" },
        zListManualDnsTasksResponse2,
      );
    },
    async provisionCertificate(request, csrfToken): Promise<ProvisionCertificateResponse> {
      const body = zProvisionCertificateBody.parse(request);
      return requestJson(
        context,
        ${JSON.stringify(routes.provisionCertificate.route)},
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.provisionCertificate.method)},
        },
        zProvisionCertificateResponse2,
      );
    },
    async provisionMeshLocalCertificate(request, csrfToken): Promise<ProvisionMeshLocalCertificateResponse> {
      const body = zProvisionMeshLocalCertificateBody.parse(request);
      return requestJson(
        context,
        ${JSON.stringify(routes.provisionMeshLocalCertificate.route)},
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.provisionMeshLocalCertificate.method)},
        },
        zProvisionMeshLocalCertificateResponse2,
      );
    },`;
}

/** Renders validation for server-provided manual-DNS continuations. */
export function renderCertificateRuntime(routes) {
  return `function validateManualDnsTaskPageUrl(apiRoot: URL, value: string): string {
  if (value.length === 0 || value.length > 16_384 || !value.startsWith("/")) {
    throw new TypeError("manual DNS task page URL is invalid");
  }
  const route = new URL(value, apiRoot.origin);
  if (
    route.origin !== apiRoot.origin ||
    route.username !== "" ||
    route.password !== "" ||
    route.hash !== "" ||
    route.pathname !== ${JSON.stringify(`/api/latest${routes.listManualDnsTasks.route}`)}
  ) {
    throw new TypeError("manual DNS task page URL is outside the administration API");
  }
  const names = [...route.searchParams.keys()];
  if (
    names.some((name) => name !== "cursor" && name !== "limit") ||
    new Set(names).size !== names.length
  ) {
    throw new TypeError("manual DNS task page URL has invalid query fields");
  }
  const rawLimit = route.searchParams.get("limit");
  zListManualDnsTasksQuery.parse({
    cursor: route.searchParams.get("cursor") ?? undefined,
    limit: rawLimit === null ? undefined : parseSafeDecimalHeader(rawLimit),
  });
  return route.pathname + route.search;
}`;
}
