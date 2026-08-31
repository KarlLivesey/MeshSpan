// SPDX-License-Identifier: GPL-2.0-only

/** Renders public request helpers for the native resumable-upload lifecycle. */
export function renderUploadRequestTypes() {
  return `export type ListUploadRangesRequest = Readonly<{
  uploadId: string;
  cursor?: string;
  limit?: number;
}>;

export type WriteUploadRangeRequest = Readonly<{
  uploadId: string;
  offset: number;
  operationId: string;
  stageFence: number;
  contentBlake3: string;
  bytes: Uint8Array;
}>;`;
}

/** Renders upload methods in the generated client interface. */
export function renderUploadClientInterface() {
  return `abortUpload(
    uploadId: string,
    request: AbortUploadRequest,
  ): Promise<AbortUploadResponse>;
  beginUpload(
    volumeId: string,
    request: BeginUploadRequest,
  ): Promise<BeginUploadResponse>;
  commitUpload(
    uploadId: string,
    request: CommitUploadRequest,
  ): Promise<CommitUploadResponse>;
  getUpload(uploadId: string): Promise<UploadStatusResponse>;
  listUploadRanges(
    request: ListUploadRangesRequest,
  ): Promise<ListUploadRangesResponse>;
  writeUploadRange(
    request: WriteUploadRangeRequest,
  ): Promise<WriteUploadRangeResponse>;`;
}

/** Renders upload implementations from the authoritative OpenAPI routes. */
export function renderUploadClientMethods(routes) {
  return [
    renderUploadLifecycleMethods(routes),
    renderUploadReadMethods(routes),
    renderUploadRangeMethod(routes),
  ].join("\n    ");
}

function renderUploadLifecycleMethods(routes) {
  return `async abortUpload(uploadId, request): Promise<AbortUploadResponse> {
      const path = zAbortUploadPath.parse({ upload_id: uploadId });
      const body = zAbortUploadBody.parse(request);
      return requestJson(
        context,
        substitutePathParameter(
          ${JSON.stringify(routes.abortUpload.route)},
          "upload_id",
          path.upload_id,
        ),
        {
          body: JSON.stringify(body),
          headers: { "Content-Type": "application/json" },
          method: ${JSON.stringify(routes.abortUpload.method)},
        },
        zAbortUploadResponse2,
      );
    },
    async beginUpload(volumeId, request): Promise<BeginUploadResponse> {
      const path = zBeginUploadPath.parse({ volume_id: volumeId });
      const body = zBeginUploadBody.parse(request);
      validateNamespacePath(body.path);
      return requestJson(
        context,
        substitutePathParameter(
          ${JSON.stringify(routes.beginUpload.route)},
          "volume_id",
          path.volume_id,
        ),
        {
          body: JSON.stringify(body),
          headers: { "Content-Type": "application/json" },
          method: ${JSON.stringify(routes.beginUpload.method)},
        },
        zBeginUploadResponse2,
      );
    },
    async commitUpload(uploadId, request): Promise<CommitUploadResponse> {
      const path = zCommitUploadPath.parse({ upload_id: uploadId });
      const body = zCommitUploadBody.parse(request);
      return requestJson(
        context,
        substitutePathParameter(
          ${JSON.stringify(routes.commitUpload.route)},
          "upload_id",
          path.upload_id,
        ),
        {
          body: JSON.stringify(body),
          headers: { "Content-Type": "application/json" },
          method: ${JSON.stringify(routes.commitUpload.method)},
        },
        zCommitUploadResponse2,
      );
    },`;
}

function renderUploadReadMethods(routes) {
  return `async getUpload(uploadId): Promise<UploadStatusResponse> {
      const path = zGetUploadPath.parse({ upload_id: uploadId });
      return requestJson(
        context,
        substitutePathParameter(
          ${JSON.stringify(routes.getUpload.route)},
          "upload_id",
          path.upload_id,
        ),
        { method: ${JSON.stringify(routes.getUpload.method)} },
        zGetUploadResponse,
      );
    },
    async listUploadRanges(request): Promise<ListUploadRangesResponse> {
      const path = zListUploadRangesPath.parse({ upload_id: request.uploadId });
      const query = zListUploadRangesQuery.parse({
        cursor: request.cursor,
        limit: request.limit,
      });
      return requestJson(
        context,
        appendQuery(
          substitutePathParameter(
            ${JSON.stringify(routes.listUploadRanges.route)},
            "upload_id",
            path.upload_id,
          ),
          query,
        ),
        { method: ${JSON.stringify(routes.listUploadRanges.method)} },
        zListUploadRangesResponse2,
      );
    },`;
}

function renderUploadRangeMethod(routes) {
  return `async writeUploadRange(request): Promise<WriteUploadRangeResponse> {
      const path = zWriteUploadRangePath.parse({
        offset: request.offset,
        upload_id: request.uploadId,
      });
      const headers = zWriteUploadRangeHeaders.parse({
        "MeshSpan-Content-BLAKE3": request.contentBlake3,
        "MeshSpan-Operation-Id": request.operationId,
        "MeshSpan-Stage-Fence": request.stageFence,
      });
      if (request.bytes.byteLength === 0) {
        throw new RangeError("upload range must not be empty");
      }
      if (request.bytes.byteLength > MAX_UPLOAD_RANGE_BYTES) {
        throw new RangeError("upload range exceeds the native byte limit");
      }
      const body = new Uint8Array(request.bytes).buffer;
      return requestJson(
        context,
        substitutePathParameter(
          substitutePathParameter(
            ${JSON.stringify(routes.writeUploadRange.route)},
            "upload_id",
            path.upload_id,
          ),
          "offset",
          String(path.offset),
        ),
        {
          body,
          headers: {
            ...headers,
            "Content-Type": "application/octet-stream",
            "MeshSpan-Stage-Fence": String(headers["MeshSpan-Stage-Fence"]),
          },
          method: ${JSON.stringify(routes.writeUploadRange.method)},
        },
        zWriteUploadRangeResponse2,
      );
    },`;
}
