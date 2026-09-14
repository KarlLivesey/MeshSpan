// SPDX-License-Identifier: GPL-2.0-only

/** Renders the native federation invitation client, without a second API model. */
export function renderFederationClientInterface() {
  return `getFederationStorageGrant(query: FederationStorageGrantQuery): Promise<FederationStorageGrantResponse>;
  configureFederationStorageGrant(request: ConfigureFederationStorageGrantRequest, csrfToken?: string): Promise<ConfigureFederationStorageGrantResponse>;
  connectFederation(
    request: ConnectFederationRequest,
    csrfToken?: string,
  ): Promise<ConnectFederationResponse>;
  acceptFederationPairing(
    request: AcceptFederationPairingRequest,
    connectionCode: string,
  ): Promise<AcceptFederationPairingResponse>;
  createFederationPairingInvitation(
    request: CreateFederationPairingInvitationRequest,
    csrfToken?: string,
  ): Promise<CreateFederationPairingInvitationResponse>;
  cancelFederationPairingInvitation(
    request: CancelFederationPairingInvitationRequest,
    csrfToken?: string,
  ): Promise<CancelFederationPairingInvitationResponse>;`;
}

/** Uses the Rust-authored operation route and generated request/response validators. */
export function renderFederationClientMethods(routes) {
  return `async getFederationStorageGrant(query): Promise<FederationStorageGrantResponse> {
      const input = zGetFederationStorageGrantQuery.parse(query);
      const parameters = new URLSearchParams({ grant_id: input.grant_id });
      return requestJson(context,
        ${JSON.stringify(routes.getFederationStorageGrant.route)} + "?" + parameters.toString(),
        { method: ${JSON.stringify(routes.getFederationStorageGrant.method)} }, zGetFederationStorageGrantResponse);
    },
    async configureFederationStorageGrant(request, csrfToken): Promise<ConfigureFederationStorageGrantResponse> {
      const body = zConfigureFederationStorageGrantBody.parse(request);
      return requestJson(context,
        ${JSON.stringify(routes.configureFederationStorageGrant.route)},
        { body: JSON.stringify(body), headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.configureFederationStorageGrant.method)} }, zConfigureFederationStorageGrantResponse2);
    },
    async connectFederation(request, csrfToken): Promise<ConnectFederationResponse> {
      const body = zConnectFederationBody.parse(request);
      return requestJson(context,
        ${JSON.stringify(routes.connectFederation.route)},
        { body: JSON.stringify(body), headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.connectFederation.method)} },
        zConnectFederationResponse2);
    },
    async acceptFederationPairing(request, connectionCode): Promise<AcceptFederationPairingResponse> {
      const body = zAcceptFederationPairingBody.parse(request);
      const headers = zAcceptFederationPairingHeaders.parse({ Authorization: "MeshSpan-Pairing " + connectionCode });
      return requestJson({ ...context, authorization: headers.Authorization },
        ${JSON.stringify(routes.acceptFederationPairing.route)},
        { body: JSON.stringify(body), headers: { "Content-Type": "application/json" },
          method: ${JSON.stringify(routes.acceptFederationPairing.method)} },
        zAcceptFederationPairingResponse2, 26 * 1024);
    },
    async createFederationPairingInvitation(request, csrfToken): Promise<CreateFederationPairingInvitationResponse> {
      const body = zCreateFederationPairingInvitationBody.parse(request);
      return requestJson(context,
        ${JSON.stringify(routes.createFederationPairingInvitation.route)},
        { body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.createFederationPairingInvitation.method)} },
        zCreateFederationPairingInvitationResponse2);
    },
    async cancelFederationPairingInvitation(request, csrfToken): Promise<CancelFederationPairingInvitationResponse> {
      const body = zCancelFederationPairingInvitationBody.parse(request);
      return requestJson(context,
        ${JSON.stringify(routes.cancelFederationPairingInvitation.route)},
        { body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.cancelFederationPairingInvitation.method)} },
        zCancelFederationPairingInvitationResponse2);
    },`;
}
