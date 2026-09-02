// SPDX-License-Identifier: GPL-2.0-only

/** Renders explicit SMB-export client operations. */
export function renderSmbExportClientInterface() {
  return `publishSmbExport(
    volumeId: string,
    request: PublishSmbExportRequest,
    csrfToken?: string,
  ): Promise<PublishSmbExportResponse>;
  withdrawSmbExport(
    exportId: string,
    request: WithdrawSmbExportRequest,
    csrfToken?: string,
  ): Promise<WithdrawSmbExportResponse>;`;
}

/** Renders strict SMB-export client implementations. */
export function renderSmbExportClientMethods(routes) {
  return `async publishSmbExport(
      volumeId,
      request,
      csrfToken,
    ): Promise<PublishSmbExportResponse> {
      const path = zPublishSmbExportPath.parse({ volume_id: volumeId });
      const body = zPublishSmbExportBody.parse(request);
      return requestJson(
        context,
        substitutePathParameter(
          ${JSON.stringify(routes.publishSmbExport.route)},
          "volume_id",
          path.volume_id,
        ),
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.publishSmbExport.method)},
        },
        zPublishSmbExportResponse2,
      );
    },
    async withdrawSmbExport(
      exportId,
      request,
      csrfToken,
    ): Promise<WithdrawSmbExportResponse> {
      const path = zWithdrawSmbExportPath.parse({ export_id: exportId });
      const body = zWithdrawSmbExportBody.parse(request);
      return requestJson(
        context,
        substitutePathParameter(
          ${JSON.stringify(routes.withdrawSmbExport.route)},
          "export_id",
          path.export_id,
        ),
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.withdrawSmbExport.method)},
        },
        zWithdrawSmbExportResponse2,
      );
    },`;
}
