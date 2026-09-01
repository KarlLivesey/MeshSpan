// SPDX-License-Identifier: GPL-2.0-only

export function renderSetupClientInterface() {
  return `
  createMeshSetup(request: CreateMeshSetupRequestWritable): Promise<CreateMeshSetupResponse>;
  joinMeshSetup(request: JoinMeshSetupRequestWritable): Promise<JoinMeshSetupResponse>;`;
}

export function renderSetupClientMethods(routes) {
  return `
    async createMeshSetup(request): Promise<CreateMeshSetupResponse> {
      const body = zCreateMeshSetupBody.parse(request);
      return requestJson(
        context,
        ${JSON.stringify(routes.createMeshSetup.route)},
        {
          body: JSON.stringify(body),
          headers: { "Content-Type": "application/json" },
          method: ${JSON.stringify(routes.createMeshSetup.method)},
        },
        zCreateMeshSetupResponse2,
      );
    },
    async joinMeshSetup(request): Promise<JoinMeshSetupResponse> {
      const body = zJoinMeshSetupBody.parse(request);
      return requestJson(
        context,
        ${JSON.stringify(routes.joinMeshSetup.route)},
        {
          body: JSON.stringify(body),
          headers: { "Content-Type": "application/json" },
          method: ${JSON.stringify(routes.joinMeshSetup.method)},
        },
        zJoinMeshSetupResponse2,
      );
    },`;
}
