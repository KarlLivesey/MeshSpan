// SPDX-License-Identifier: GPL-2.0-only

import { open, rename, writeFile } from "node:fs/promises";

export function parseContract(sourceText) {
  const document = JSON.parse(sourceText);
  if (!isRecord(document)) {
    throw new Error("expected the OpenAPI document to be an object");
  }
  if (document.openapi !== "3.1.0") {
    throw new Error("expected an OpenAPI 3.1.0 document");
  }
  const info = requireRecord(document.info, "info");
  const license = requireRecord(info.license, "info.license");
  if (license.identifier !== "GPL-2.0-only") {
    throw new Error("expected the exact GPL-2.0-only identifier");
  }
  requireRecord(document.paths, "paths");
  return document;
}

export function readRequiredRoutes(document) {
  const operations = collectOperations(document);
  return {
    ...readAdministrationRoutes(operations),
    ...readAuthenticationRoutes(operations),
    ...readFileRoutes(operations),
    ...readLifecycleRoutes(operations),
    ...readSessionRoutes(operations),
  };
}

function readSessionRoutes(operations) {
  const createSession = readSessionOperation(
    requireOperation(operations, "createSession"),
  );
  const stepUpCurrentSession = readSessionOperation(
    requireOperation(operations, "stepUpCurrentSession"),
  );
  if (stepUpCurrentSession.csrfPattern !== createSession.csrfPattern) {
    throw new Error("session rotation must preserve the CSRF token contract");
  }
  return {
    createSession,
    getCurrentSession: requireOperation(operations, "getCurrentSession"),
    revokeCurrentSession: requireOperation(operations, "revokeCurrentSession"),
    stepUpCurrentSession,
  };
}

function readAuthenticationRoutes(operations) {
  return {
    createCurrentUserApiKey: requireOperation(
      operations,
      "createCurrentUserApiKey",
    ),
    createCurrentUserPasskey: requireOperation(
      operations,
      "createCurrentUserPasskey",
    ),
    createCurrentUserPasskeyRegistrationChallenge: requireOperation(
      operations,
      "createCurrentUserPasskeyRegistrationChallenge",
    ),
    createCurrentUserRecoveryCodes: requireOperation(
      operations,
      "createCurrentUserRecoveryCodes",
    ),
    createCurrentUserTotp: requireOperation(
      operations,
      "createCurrentUserTotp",
    ),
    createCurrentUserTotpRegistrationChallenge: requireOperation(
      operations,
      "createCurrentUserTotpRegistrationChallenge",
    ),
    createPasskeyChallenge: requireOperation(
      operations,
      "createPasskeyChallenge",
    ),
    listCurrentUserAuthenticationMethods: requireOperation(
      operations,
      "listCurrentUserAuthenticationMethods",
    ),
    revokeCurrentUserAuthenticationMethod: requireOperation(
      operations,
      "revokeCurrentUserAuthenticationMethod",
    ),
  };
}

function readAdministrationRoutes(operations) {
  return {
    addGroupMember: requireOperation(operations, "addGroupMember"),
    createGroup: requireOperation(operations, "createGroup"),
    createFaultGroup: requireOperation(operations, "createFaultGroup"),
    createUser: requireOperation(operations, "createUser"),
    createVolume: requireOperation(operations, "createVolume"),
    createVolumePermissionGrant: requireOperation(
      operations,
      "createVolumePermissionGrant",
    ),
    listGroups: requireOperation(operations, "listGroups"),
    listFaultGroups: requireOperation(operations, "listFaultGroups"),
    listFaultGroupMemberships: requireOperation(
      operations,
      "listFaultGroupMemberships",
    ),
    listGroupMembers: requireOperation(operations, "listGroupMembers"),
    listOperations: requireOperation(operations, "listOperations"),
    listStorageFolders: requireOperation(operations, "listStorageFolders"),
    listTopologyNodes: requireOperation(operations, "listTopologyNodes"),
    listTopologyTargets: requireOperation(operations, "listTopologyTargets"),
    listVolumePermissionGrants: requireOperation(
      operations,
      "listVolumePermissionGrants",
    ),
    listUsers: requireOperation(operations, "listUsers"),
    listVolumes: requireOperation(operations, "listVolumes"),
    removeGroupMember: requireOperation(operations, "removeGroupMember"),
    setFaultGroupMembership: requireOperation(
      operations,
      "setFaultGroupMembership",
    ),
    revokePermissionGrant: requireOperation(
      operations,
      "revokePermissionGrant",
    ),
    registerStorageFolder: requireOperation(
      operations,
      "registerStorageFolder",
    ),
  };
}

function readFileRoutes(operations) {
  return {
    abortUpload: requireOperation(operations, "abortUpload"),
    beginUpload: requireOperation(operations, "beginUpload"),
    commitUpload: requireOperation(operations, "commitUpload"),
    createDirectory: requireOperation(operations, "createDirectory"),
    deleteObject: requireOperation(operations, "deleteObject"),
    getObject: requireOperation(operations, "getObject"),
    getUpload: requireOperation(operations, "getUpload"),
    listDirectory: requireOperation(operations, "listDirectory"),
    listUploadRanges: requireOperation(operations, "listUploadRanges"),
    readFile: requireOperation(operations, "readFile"),
    renameObject: requireOperation(operations, "renameObject"),
    writeUploadRange: requireOperation(operations, "writeUploadRange"),
  };
}

function readLifecycleRoutes(operations) {
  return {
    createMeshSetup: requireOperation(operations, "createMeshSetup"),
    joinMeshSetup: requireOperation(operations, "joinMeshSetup"),
    getHealth: requireOperation(operations, "getHealth"),
    getOpenApi: requireOperation(operations, "getOpenApi"),
    getOperationStatus: requireOperation(operations, "getOperationStatus"),
    getSetupStatus: requireOperation(operations, "getSetupStatus"),
  };
}

function collectOperations(document) {
  const operations = new Map();
  const paths = requireRecord(document.paths, "paths");
  for (const [route, rawPathItem] of Object.entries(paths)) {
    if (!route.startsWith("/") || route.length > 256) {
      throw new Error(`invalid OpenAPI route: ${route}`);
    }
    const pathItem = requireRecord(rawPathItem, `paths.${route}`);
    collectPathOperations(operations, route, pathItem);
  }
  return operations;
}

function collectPathOperations(operations, route, pathItem) {
  for (const [method, rawOperation] of Object.entries(pathItem)) {
    if (!/^(?:get|post|put|patch|delete)$/.test(method)) {
      throw new Error(`unsupported OpenAPI path member: ${route} ${method}`);
    }
    const operation = requireRecord(rawOperation, `paths.${route}.${method}`);
    const operationId = operation.operationId;
    if (
      typeof operationId !== "string" ||
      !/^[A-Za-z][A-Za-z0-9]{0,63}$/.test(operationId)
    ) {
      throw new Error(
        `invalid operationId for ${method.toUpperCase()} ${route}`,
      );
    }
    if (operations.has(operationId)) {
      throw new Error(`duplicate operationId: ${operationId}`);
    }
    operations.set(operationId, {
      method: method.toUpperCase(),
      operation,
      route,
    });
  }
}

function readSessionOperation(operation) {
  const responses = requireRecord(
    operation.operation.responses,
    "createSession.responses",
  );
  const created = requireRecord(
    responses["201"],
    "createSession.responses.201",
  );
  const headers = requireRecord(
    created.headers,
    "createSession.responses.201.headers",
  );
  const csrf = requireRecord(
    headers["MeshSpan-CSRF-Token"],
    "createSession CSRF header",
  );
  const schema = requireRecord(csrf.schema, "createSession CSRF header schema");
  if (typeof schema.pattern !== "string" || schema.pattern.length > 256) {
    throw new Error("createSession CSRF header requires one bounded pattern");
  }
  return { ...operation, csrfPattern: schema.pattern };
}

export function regexLiteral(pattern) {
  if (/[\r\n]/u.test(pattern)) {
    throw new Error("regular expression pattern must occupy one line");
  }
  return `/${pattern.replaceAll("/", "\\/")}/u`;
}

function requireOperation(operations, operationId) {
  const operation = operations.get(operationId);
  if (operation === undefined) {
    throw new Error(`missing required operation: ${operationId}`);
  }
  return operation;
}

function requireRecord(value, location) {
  if (!isRecord(value)) {
    throw new Error(`expected ${location} to be an object`);
  }
  return value;
}

function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export async function readBoundedUtf8(sourcePath) {
  const handle = await open(sourcePath, "r");
  try {
    const metadata = await handle.stat();
    if (!metadata.isFile() || metadata.size > 1_048_576) {
      throw new Error(
        "OpenAPI input must be a regular file no larger than 1 MiB",
      );
    }
    return await handle.readFile("utf8");
  } finally {
    await handle.close();
  }
}

export async function writeAtomically(destination, contents) {
  const temporary = new URL(`${destination.href}.tmp`);
  await writeFile(temporary, contents, "utf8");
  await rename(temporary, destination);
}
