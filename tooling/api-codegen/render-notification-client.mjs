// SPDX-License-Identifier: GPL-2.0-only

/** Typed administration over the Rust-owned notification contract. */
export function renderNotificationClientInterface() {
  return `getNotifications(): Promise<NotificationsResponse>;
  configureNotification(request: ConfigureNotificationRequest, csrfToken?: string): Promise<ConfigureNotificationResponse>;`;
}

/** Uses declared routes and validators, never duplicated models. */
export function renderNotificationClientMethods(routes) {
  return `async getNotifications(): Promise<NotificationsResponse> {
      return requestJson(context, ${JSON.stringify(routes.getNotifications.route)},
        { method: ${JSON.stringify(routes.getNotifications.method)} }, zGetNotificationsResponse);
    },
    async configureNotification(request, csrfToken): Promise<ConfigureNotificationResponse> {
      const body = zConfigureNotificationBody.parse(request);
      return requestJson(context, ${JSON.stringify(routes.configureNotification.route)},
        { body: JSON.stringify(body), headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.configureNotification.method)} }, zConfigureNotificationResponse2);
    },`;
}
