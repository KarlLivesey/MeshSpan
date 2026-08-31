// SPDX-License-Identifier: GPL-2.0-only

/** Renders current-user authentication and session client operations. */
export function renderAuthenticationClientInterface() {
  return `createPasskeyChallenge(
    request: CreatePasskeyChallengeRequest,
  ): Promise<CreatePasskeyChallengeResponse>;
  createCurrentUserApiKey(
    request: CreateApiKeyRequest,
    csrfToken: string,
  ): Promise<CreateApiKeyResponse>;
  createCurrentUserPasskey(
    request: CreatePasskeyRegistrationRequestWritable,
    csrfToken: string,
  ): Promise<CreatePasskeyRegistrationResponse>;
  createCurrentUserPasskeyRegistrationChallenge(
    request: CreatePasskeyRegistrationChallengeRequest,
    csrfToken: string,
  ): Promise<CreatePasskeyRegistrationChallengeResponse>;
  createCurrentUserRecoveryCodes(
    request: CreateRecoveryCodesRequest,
    csrfToken: string,
  ): Promise<CreateRecoveryCodesResponse>;
  createCurrentUserTotp(
    request: CreateTotpRegistrationRequestWritable,
    csrfToken: string,
  ): Promise<CreateTotpRegistrationResponse>;
  createCurrentUserTotpRegistrationChallenge(
    request: CreateTotpRegistrationChallengeRequest,
    csrfToken: string,
  ): Promise<CreateTotpRegistrationChallengeResponse>;
  listCurrentUserAuthenticationMethods(
    request?: ListAuthenticationMethodsRequest,
  ): Promise<ListAuthenticationMethodsResponse>;
  listNextCurrentUserAuthenticationMethods(
    nextPageUrl: string,
  ): Promise<ListAuthenticationMethodsResponse>;
  revokeCurrentUserAuthenticationMethod(
    methodId: string,
    request: RevokeAuthenticationMethodRequest,
    csrfToken: string,
  ): Promise<RevokeAuthenticationMethodResponse>;
  stepUpCurrentSession(
    request: StepUpCurrentSessionRequestWritable,
    csrfToken: string,
  ): Promise<CreateSessionResult>;`;
}

/** Renders current-user authentication and session client implementations. */
export function renderAuthenticationClientMethods(routes) {
  return `${renderChallengeMethods(routes)}
    ${renderRegistrationMethods(routes)}
    ${renderInventoryMethods(routes)}
    ${renderLifecycleMethods(routes)}`;
}

function renderChallengeMethods(routes) {
  return `async createPasskeyChallenge(request): Promise<CreatePasskeyChallengeResponse> {
      const body = zCreatePasskeyChallengeBody.parse(request);
      return requestJson(
        context,
        ${JSON.stringify(routes.createPasskeyChallenge.route)},
        {
          body: JSON.stringify(body),
          headers: { "Content-Type": "application/json" },
          method: ${JSON.stringify(routes.createPasskeyChallenge.method)},
        },
        zCreatePasskeyChallengeResponse2,
      );
    },
    async createCurrentUserPasskeyRegistrationChallenge(
      request,
      csrfToken,
    ): Promise<CreatePasskeyRegistrationChallengeResponse> {
      const body = zCreateCurrentUserPasskeyRegistrationChallengeBody.parse(request);
      return requestJson(
        context,
        ${JSON.stringify(routes.createCurrentUserPasskeyRegistrationChallenge.route)},
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.createCurrentUserPasskeyRegistrationChallenge.method)},
        },
        zCreateCurrentUserPasskeyRegistrationChallengeResponse,
      );
    },
    async createCurrentUserTotpRegistrationChallenge(
      request,
      csrfToken,
    ): Promise<CreateTotpRegistrationChallengeResponse> {
      const body = zCreateCurrentUserTotpRegistrationChallengeBody.parse(request);
      return requestJson(
        context,
        ${JSON.stringify(routes.createCurrentUserTotpRegistrationChallenge.route)},
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.createCurrentUserTotpRegistrationChallenge.method)},
        },
        zCreateCurrentUserTotpRegistrationChallengeResponse,
      );
    },`;
}

function renderRegistrationMethods(routes) {
  return `async createCurrentUserApiKey(
      request,
      csrfToken,
    ): Promise<CreateApiKeyResponse> {
      const body = zCreateCurrentUserApiKeyBody.parse(request);
      return requestJson(
        context,
        ${JSON.stringify(routes.createCurrentUserApiKey.route)},
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.createCurrentUserApiKey.method)},
        },
        zCreateCurrentUserApiKeyResponse,
      );
    },
    async createCurrentUserPasskey(
      request,
      csrfToken,
    ): Promise<CreatePasskeyRegistrationResponse> {
      const body = zCreateCurrentUserPasskeyBody.parse(request);
      return requestJson(
        context,
        ${JSON.stringify(routes.createCurrentUserPasskey.route)},
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.createCurrentUserPasskey.method)},
        },
        zCreateCurrentUserPasskeyResponse,
      );
    },
    async createCurrentUserRecoveryCodes(
      request,
      csrfToken,
    ): Promise<CreateRecoveryCodesResponse> {
      const body = zCreateCurrentUserRecoveryCodesBody.parse(request);
      return requestJson(
        context,
        ${JSON.stringify(routes.createCurrentUserRecoveryCodes.route)},
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.createCurrentUserRecoveryCodes.method)},
        },
        zCreateCurrentUserRecoveryCodesResponse,
      );
    },
    async createCurrentUserTotp(
      request,
      csrfToken,
    ): Promise<CreateTotpRegistrationResponse> {
      const body = zCreateCurrentUserTotpBody.parse(request);
      return requestJson(
        context,
        ${JSON.stringify(routes.createCurrentUserTotp.route)},
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.createCurrentUserTotp.method)},
        },
        zCreateCurrentUserTotpResponse,
      );
    },`;
}

function renderInventoryMethods(routes) {
  return `async listCurrentUserAuthenticationMethods(
      request = {},
    ): Promise<ListAuthenticationMethodsResponse> {
      const query = zListCurrentUserAuthenticationMethodsQuery.parse(request);
      return requestJson(
        context,
        appendQuery(
          ${JSON.stringify(routes.listCurrentUserAuthenticationMethods.route)},
          query,
        ),
        { method: ${JSON.stringify(routes.listCurrentUserAuthenticationMethods.method)} },
        zListCurrentUserAuthenticationMethodsResponse,
      );
    },
    async listNextCurrentUserAuthenticationMethods(
      nextPageUrl,
    ): Promise<ListAuthenticationMethodsResponse> {
      return requestJson(
        context,
        validateAuthenticationMethodPageUrl(context.apiRoot, nextPageUrl),
        { method: "GET" },
        zListCurrentUserAuthenticationMethodsResponse,
      );
    },`;
}

function renderLifecycleMethods(routes) {
  return `async revokeCurrentUserAuthenticationMethod(
      methodId,
      request,
      csrfToken,
    ): Promise<RevokeAuthenticationMethodResponse> {
      const path = zRevokeCurrentUserAuthenticationMethodPath.parse({
        method_id: methodId,
      });
      const body = zRevokeCurrentUserAuthenticationMethodBody.parse(request);
      return requestJson(
        context,
        substitutePathParameter(
          ${JSON.stringify(routes.revokeCurrentUserAuthenticationMethod.route)},
          "method_id",
          path.method_id,
        ),
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.revokeCurrentUserAuthenticationMethod.method)},
        },
        zRevokeCurrentUserAuthenticationMethodResponse,
      );
    },
    async stepUpCurrentSession(
      request,
      csrfToken,
    ): Promise<CreateSessionResult> {
      const body = zStepUpCurrentSessionBody.parse(request);
      const response = await requestJsonResponse(
        context,
        ${JSON.stringify(routes.stepUpCurrentSession.route)},
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.stepUpCurrentSession.method)},
        },
        zStepUpCurrentSessionResponse,
      );
      return {
        csrfToken: readCsrfToken(response.headers),
        session: response.body,
      };
    },`;
}

/** Renders validation for ready-to-follow current-user authentication pages. */
export function renderAuthenticationClientRuntime(routes) {
  return `function validateAuthenticationMethodPageUrl(
  apiRoot: URL,
  value: string,
): string {
  if (value.length === 0 || value.length > 16_384 || !value.startsWith("/")) {
    throw new TypeError("authentication-method page URL is invalid");
  }
  const route = new URL(value, apiRoot.origin);
  if (
    route.origin !== apiRoot.origin ||
    route.username !== "" ||
    route.password !== "" ||
    route.hash !== "" ||
    route.pathname !== ${JSON.stringify(`/api/latest${routes.listCurrentUserAuthenticationMethods.route}`)}
  ) {
    throw new TypeError("authentication-method page URL is outside the current-user API");
  }
  validateAuthenticationMethodPageQuery(route);
  return route.pathname + route.search;
}

function validateAuthenticationMethodPageQuery(route: URL): void {
  const names = [...route.searchParams.keys()];
  if (
    names.some((name) => name !== "cursor" && name !== "limit") ||
    new Set(names).size !== names.length
  ) {
    throw new TypeError("authentication-method page URL has invalid query fields");
  }
  const rawLimit = route.searchParams.get("limit");
  zListCurrentUserAuthenticationMethodsQuery.parse({
    cursor: route.searchParams.get("cursor") ?? undefined,
    limit: rawLimit === null ? undefined : parseSafeDecimalHeader(rawLimit),
  });
}`;
}
