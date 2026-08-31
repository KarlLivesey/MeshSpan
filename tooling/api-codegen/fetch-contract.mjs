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
    abortUpload: requireOperation(operations, "abortUpload"),
    beginUpload: requireOperation(operations, "beginUpload"),
    commitUpload: requireOperation(operations, "commitUpload"),
    createGroup: requireOperation(operations, "createGroup"),
    createDirectory: requireOperation(operations, "createDirectory"),
    createCurrentUserApiKey: requireOperation(
      operations,
      "createCurrentUserApiKey",
    ),
    createMeshSetup: requireOperation(operations, "createMeshSetup"),
    createSession: readSessionOperation(
      requireOperation(operations, "createSession"),
    ),
    createUser: requireOperation(operations, "createUser"),
    deleteObject: requireOperation(operations, "deleteObject"),
    getHealth: requireOperation(operations, "getHealth"),
    getCurrentSession: requireOperation(operations, "getCurrentSession"),
    getObject: requireOperation(operations, "getObject"),
    getOpenApi: requireOperation(operations, "getOpenApi"),
    getSetupStatus: requireOperation(operations, "getSetupStatus"),
    getUpload: requireOperation(operations, "getUpload"),
    listDirectory: requireOperation(operations, "listDirectory"),
    listGroups: requireOperation(operations, "listGroups"),
    listUploadRanges: requireOperation(operations, "listUploadRanges"),
    listUsers: requireOperation(operations, "listUsers"),
    readFile: requireOperation(operations, "readFile"),
    renameObject: requireOperation(operations, "renameObject"),
    revokeCurrentSession: requireOperation(operations, "revokeCurrentSession"),
    revokeCurrentUserAuthenticationMethod: requireOperation(
      operations,
      "revokeCurrentUserAuthenticationMethod",
    ),
    writeUploadRange: requireOperation(operations, "writeUploadRange"),
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
