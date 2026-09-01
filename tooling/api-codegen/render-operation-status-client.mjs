// SPDX-License-Identifier: GPL-2.0-only

/** Renders the durable-operation client operation. */
export function renderOperationStatusClientInterface() {
  return `getOperationStatus(operationId: string): Promise<OperationStatusResponse>;`;
}

/** Renders the durable-operation client implementation. */
export function renderOperationStatusClientMethods(routes) {
  return `async getOperationStatus(operationId): Promise<OperationStatusResponse> {
      const path = zGetOperationStatusPath.parse({ operation_id: operationId });
      return requestJson(
        context,
        substitutePathParameter(
          ${JSON.stringify(routes.getOperationStatus.route)},
          "operation_id",
          path.operation_id,
        ),
        { method: ${JSON.stringify(routes.getOperationStatus.method)} },
        zGetOperationStatusResponse,
      );
    },`;
}
