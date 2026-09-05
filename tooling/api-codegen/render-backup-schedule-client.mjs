// SPDX-License-Identifier: GPL-2.0-only

/** Renders the automatic metadata-backup policy client interface. */
export function renderBackupScheduleClientInterface() {
  return `getBackupSchedule(): Promise<BackupScheduleResponse>;
  configureBackupSchedule(
    request: ConfigureBackupScheduleRequest,
    csrfToken?: string,
  ): Promise<ConfigureBackupScheduleResponse>;`;
}

/** Renders policy operations using routes and validators from the Rust contract. */
export function renderBackupScheduleClientMethods(routes) {
  return `async getBackupSchedule(): Promise<BackupScheduleResponse> {
      return requestJson(context,
        ${JSON.stringify(routes.getBackupSchedule.route)},
        { method: ${JSON.stringify(routes.getBackupSchedule.method)} },
        zGetBackupScheduleResponse);
    },
    async configureBackupSchedule(request, csrfToken): Promise<ConfigureBackupScheduleResponse> {
      const body = zConfigureBackupScheduleBody.parse(request);
      return requestJson(context,
        ${JSON.stringify(routes.configureBackupSchedule.route)},
        { body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.configureBackupSchedule.method)} },
        zConfigureBackupScheduleResponse2);
    },`;
}
