// SPDX-License-Identifier: GPL-2.0-only

/** Native update administration is shared by web and independent HTTPS clients. */
export function renderUpdateClientInterface() {
  return `getUpdates(rolloutId?: string): Promise<UpdatesResponse>;
  manageUpdate(request: ManageUpdateRequest, csrfToken?: string): Promise<ManageUpdateResponse>;
  stageUpdateArtifact(rolloutId: string, target: string, operationId: string, bytes: Blob, csrfToken?: string): Promise<StageUpdateArtifactResponse>;`;
}

/** Uses Rust-generated routes and both incoming and outgoing validators. */
export function renderUpdateClientMethods(routes) {
  const maximum =
    routes.stageUpdateArtifact.operation["x-meshspan-max-request-bytes"];
  if (!Number.isSafeInteger(maximum) || maximum <= 0)
    throw new TypeError("artifact byte bound is missing");
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
    },
    async stageUpdateArtifact(rolloutId, target, operationId, bytes, csrfToken): Promise<StageUpdateArtifactResponse> {
      const path = zStageUpdateArtifactPath.parse({ rollout_id: rolloutId, target });
      const headers = zStageUpdateArtifactHeaders.parse({ "MeshSpan-Operation-Id": operationId, "Content-Length": String(bytes.size) });
      if (bytes.size <= 0 || bytes.size > ${JSON.stringify(maximum)}) throw new RangeError("executable exceeds the signed candidate format bounds");
      return requestJson(context, substitutePathParameter(substitutePathParameter(${JSON.stringify(routes.stageUpdateArtifact.route)},
        "rollout_id", path.rollout_id), "target", path.target),
        { body: bytes, method: ${JSON.stringify(routes.stageUpdateArtifact.method)},
          headers: { ...mutationHeaders("application/octet-stream", csrfToken), "MeshSpan-Operation-Id": headers["MeshSpan-Operation-Id"] } },
        zStageUpdateArtifactResponse2);
    },`;
}
