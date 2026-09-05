// SPDX-License-Identifier: GPL-2.0-only

/** Renders registered backup destination controls. */
export function renderBackupDestinationClientInterface() {
  return `listBackupDestinations(query?: ListBackupDestinationsQuery): Promise<ListBackupDestinationsResponse>;
  configureBackupDestination(request: ConfigureBackupDestinationRequest, csrfToken?: string): Promise<ConfigureBackupDestinationResponse>;`;
}

/** Uses Rust-generated routes and request/response validators. */
export function renderBackupDestinationClientMethods(routes) {
  return `async listBackupDestinations(query = {}): Promise<ListBackupDestinationsResponse> {
      const input = zListBackupDestinationsQuery.parse(query);
      const parameters = new URLSearchParams();
      if (input.limit !== undefined) parameters.set("limit", String(input.limit));
      if (input.cursor !== undefined) parameters.set("cursor", input.cursor);
      const suffix = parameters.toString();
      return requestJson(context,
        ${JSON.stringify(routes.listBackupDestinations.route)} + (suffix ? "?" + suffix : ""),
        { method: ${JSON.stringify(routes.listBackupDestinations.method)} }, zListBackupDestinationsResponse2);
    },
    async configureBackupDestination(request, csrfToken): Promise<ConfigureBackupDestinationResponse> {
      const body = zConfigureBackupDestinationBody.parse(request);
      return requestJson(context, ${JSON.stringify(routes.configureBackupDestination.route)},
        { body: JSON.stringify(body), headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.configureBackupDestination.method)} }, zConfigureBackupDestinationResponse2);
    },`;
}
