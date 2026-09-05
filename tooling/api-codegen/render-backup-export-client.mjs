// SPDX-License-Identifier: GPL-2.0-only

/** Exposes an explicitly incomplete, cancellable transfer rather than buffering a backup. */
export function renderBackupExportClientInterface() {
  return `/** Builds a credential-free browser download URL without making a request.
   * Requires a browser session; API-key clients use exportMetadataBackup instead.
   * The server reauthorises the download. A URL is not evidence of availability. */
  metadataBackupDownloadUrl: (backupId: string) => string;
  /** Performs an isolated gateway-key restore check; never tests offline recovery custody. */
  checkMetadataBackupReadiness(backupId: string, signal?: AbortSignal): Promise<BackupReadinessResponse>;
  /** Opens encrypted bytes. Consume through successful EOF for verified length and SHA-256.
   * Partial consumption is not a complete download; this is not restore proof. */
  exportMetadataBackup(backupId: string, signal?: AbortSignal): Promise<Readonly<{
    headers: BackupExportHeaders;
    body: ReadableStream<Uint8Array>;
  }>>;`;
}

/** Derives the route from Rust and validates both path and returned header evidence. */
export function renderBackupExportClientMethods(routes) {
  return `metadataBackupDownloadUrl(backupId): string {
      if (context.authorization !== undefined) {
        throw new TypeError("API-key clients must use the authenticated backup stream");
      }
      const input = zBackupExportPath.parse({ backup_id: backupId });
      const route = substitutePathParameter(${JSON.stringify(routes.exportMetadataBackup.route)}, "backup_id", input.backup_id);
      const url = resolveRoute(context.apiRoot, route);
      if (url.protocol !== "https:" && url.protocol !== "http:") {
        throw new TypeError("backup downloads require an HTTP or HTTPS endpoint");
      }
      return url.href;
    },
    async checkMetadataBackupReadiness(backupId, signal): Promise<BackupReadinessResponse> {
      const input = zBackupExportPath.parse({ backup_id: backupId });
      const route = substitutePathParameter(${JSON.stringify(routes.checkMetadataBackupReadiness.route)}, "backup_id", input.backup_id);
      const response = await requestJson(context, route, {
        method: ${JSON.stringify(routes.checkMetadataBackupReadiness.method)},
        ...(signal === undefined ? {} : { signal }),
      }, zBackupReadinessResponse);
      if (response.backup_id !== input.backup_id) throw new TypeError("restore check names another backup generation");
      return response;
    },
    async exportMetadataBackup(backupId, signal): Promise<Readonly<{
      headers: BackupExportHeaders;
      body: ReadableStream<Uint8Array>;
    }>> {
      const input = zBackupExportPath.parse({ backup_id: backupId });
      const route = substitutePathParameter(${JSON.stringify(routes.exportMetadataBackup.route)}, "backup_id", input.backup_id);
      const response = await context.fetch(resolveRoute(context.apiRoot, route), {
        method: ${JSON.stringify(routes.exportMetadataBackup.method)},
        credentials: context.authorization === undefined ? "same-origin" : "omit",
        headers: authenticatedHeaders(context.authorization, { Accept: "application/octet-stream" }),
        ...(signal === undefined ? {} : { signal }),
      });
      try {
        validateContractHeaders(response);
        if (!response.ok) {
          const error = zApiError.safeParse(await readBoundedJson(response));
          throw new MeshSpanApiError(response.status, error.success ? error.data : undefined);
        }
        if (response.status !== 200 || response.headers.get("content-type") !== "application/octet-stream" || response.body === null) {
          throw new TypeError("backup export response is not a complete-container stream");
        }
        const headers = zBackupExportHeaders.parse({
          "Content-Length": response.headers.get("content-length"),
          "MeshSpan-Backup-ID": response.headers.get("meshspan-backup-id"),
          "MeshSpan-Backup-Digest": response.headers.get("meshspan-backup-digest"),
        });
        if (headers["MeshSpan-Backup-ID"] !== input.backup_id) {
          throw new TypeError("backup export response names another generation");
        }
        return { headers, body: verifyBackupStream(response.body, headers["Content-Length"], headers["MeshSpan-Backup-Digest"]) };
      } catch (error) {
        if (!response.bodyUsed) await response.body?.cancel();
        throw error;
      }
    },`;
}
