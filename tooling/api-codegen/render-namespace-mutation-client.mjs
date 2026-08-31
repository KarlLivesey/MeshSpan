// SPDX-License-Identifier: GPL-2.0-only

/** Renders native logical namespace mutations in the generated client interface. */
export function renderNamespaceMutationClientInterface() {
  return `createDirectory(
    volumeId: string,
    request: CreateDirectoryRequest,
    csrfToken?: string,
  ): Promise<CreateDirectoryResponse>;
  deleteObject(
    volumeId: string,
    request: DeleteObjectRequest,
    csrfToken?: string,
  ): Promise<DeleteObjectResponse>;
  renameObject(
    volumeId: string,
    request: RenameObjectRequest,
    csrfToken?: string,
  ): Promise<RenameObjectResponse>;`;
}

/** Renders native logical namespace mutation implementations from OpenAPI routes. */
export function renderNamespaceMutationClientMethods(routes) {
  return `async createDirectory(volumeId, request, csrfToken): Promise<CreateDirectoryResponse> {
      const path = zCreateDirectoryPath.parse({ volume_id: volumeId });
      const body = zCreateDirectoryBody.parse(request);
      validateNamespacePath(body.path);
      return requestJson(
        context,
        substitutePathParameter(
          ${JSON.stringify(routes.createDirectory.route)},
          "volume_id",
          path.volume_id,
        ),
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.createDirectory.method)},
        },
        zCreateDirectoryResponse2,
      );
    },
    async deleteObject(volumeId, request, csrfToken): Promise<DeleteObjectResponse> {
      const path = zDeleteObjectPath.parse({ volume_id: volumeId });
      const body = zDeleteObjectBody.parse(request);
      validateNamespacePath(body.path);
      return requestJson(
        context,
        substitutePathParameter(
          ${JSON.stringify(routes.deleteObject.route)},
          "volume_id",
          path.volume_id,
        ),
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.deleteObject.method)},
        },
        zDeleteObjectResponse2,
      );
    },
    async renameObject(volumeId, request, csrfToken): Promise<RenameObjectResponse> {
      const path = zRenameObjectPath.parse({ volume_id: volumeId });
      const body = zRenameObjectBody.parse(request);
      validateNamespacePath(body.source_path);
      validateNamespacePath(body.target_path);
      if (body.source_path === body.target_path) {
        throw new TypeError("rename source and target must differ");
      }
      return requestJson(
        context,
        substitutePathParameter(
          ${JSON.stringify(routes.renameObject.route)},
          "volume_id",
          path.volume_id,
        ),
        {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.renameObject.method)},
        },
        zRenameObjectResponse2,
      );
    },`;
}
