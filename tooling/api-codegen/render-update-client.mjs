// SPDX-License-Identifier: GPL-2.0-only

/** Native update administration is shared by web and independent HTTPS clients. */
export function renderUpdateClientInterface() {
  return `getUpdates(rolloutId?: string): Promise<UpdatesResponse>;
  manageUpdate(request: ManageUpdateRequest, csrfToken?: string): Promise<ManageUpdateResponse>;`;
}

/** Uses Rust-generated routes and both incoming and outgoing validators. */
export function renderUpdateClientMethods(routes) {
  return `async getUpdates(rolloutId): Promise<UpdatesResponse> {
      const query = zGetUpdatesQuery.parse(rolloutId === undefined ? {} : { rollout_id: rolloutId });
      return requestJson(context, appendQuery(${JSON.stringify(routes.getUpdates.route)}, query ?? {}),
        { method: ${JSON.stringify(routes.getUpdates.method)} }, zGetUpdatesResponse);
    },
    async manageUpdate(request, csrfToken): Promise<ManageUpdateResponse> {
      const body = zManageUpdateBody.parse(request);
      return requestJson(context, ${JSON.stringify(routes.manageUpdate.route)},
        { body: JSON.stringify(body), headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.manageUpdate.method)} }, zManageUpdateResponse2);
    },`;
}
