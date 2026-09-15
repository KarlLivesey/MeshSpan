// SPDX-License-Identifier: GPL-2.0-only

/** Renders manager consent and anonymous first-credential enrollment operations. */
export function renderUserEnrollmentClientInterface() {
  return `issueUserEnrollment(
    principalId: string,
    request: IssueUserEnrollmentRequest,
    csrfToken: string,
  ): Promise<IssueUserEnrollmentResponse>;
  revokeUserEnrollment(
    enrollmentOperationId: string,
    request: RevokeUserEnrollmentRequest,
    csrfToken: string,
  ): Promise<RevokeUserEnrollmentResponse>;
  redeemUserEnrollmentApiKey(
    request: RedeemUserEnrollmentApiKeyRequestWritable,
  ): Promise<CreateApiKeyResponse>;`;
}

/** Derives routes and HTTP methods from the Rust-authored OpenAPI operations. */
export function renderUserEnrollmentClientMethods(routes) {
  return `async issueUserEnrollment(principalId, request, csrfToken): Promise<IssueUserEnrollmentResponse> {
      const path = zIssueUserEnrollmentPath.parse({ principal_id: principalId });
      const body = zIssueUserEnrollmentBody.parse(request);
      return requestJson(context, substitutePathParameter(
        ${JSON.stringify(routes.issueUserEnrollment.route)}, "principal_id", path.principal_id), {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.issueUserEnrollment.method)},
        }, zIssueUserEnrollmentResponse2);
    },
    async revokeUserEnrollment(enrollmentOperationId, request, csrfToken): Promise<RevokeUserEnrollmentResponse> {
      const path = zRevokeUserEnrollmentPath.parse({ enrollment_operation_id: enrollmentOperationId });
      const body = zRevokeUserEnrollmentBody.parse(request);
      return requestJson(context, substitutePathParameter(
        ${JSON.stringify(routes.revokeUserEnrollment.route)}, "enrollment_operation_id", path.enrollment_operation_id), {
          body: JSON.stringify(body),
          headers: mutationHeaders("application/json", csrfToken),
          method: ${JSON.stringify(routes.revokeUserEnrollment.method)},
        }, zRevokeUserEnrollmentResponse2);
    },
    async redeemUserEnrollmentApiKey(request): Promise<CreateApiKeyResponse> {
      const body = zRedeemUserEnrollmentApiKeyBody.parse(request);
      return requestJson(context, ${JSON.stringify(routes.redeemUserEnrollmentApiKey.route)}, {
        body: JSON.stringify(body),
        headers: { "Content-Type": "application/json" },
        method: ${JSON.stringify(routes.redeemUserEnrollmentApiKey.method)},
      }, zRedeemUserEnrollmentApiKeyResponse);
    },`;
}
