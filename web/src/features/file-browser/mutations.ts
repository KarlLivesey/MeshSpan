// SPDX-License-Identifier: GPL-2.0-only

import type { MeshSpanFetchClient } from "../../generated/fetch.gen";
import type {
  CreateDirectoryResponse,
  DeleteObjectResponse,
  RenameObjectResponse,
} from "../../generated/types.gen";

export type FileMutation = { operation_id: string; volume_id: string } & (
  | { kind: "create"; path: string }
  | { kind: "delete"; path: string; object_id: string }
  | {
      kind: "rename";
      source_path: string;
      target_path: string;
      object_id: string;
    }
);
export type FileReceipt =
  CreateDirectoryResponse | DeleteObjectResponse | RenameObjectResponse;
type Client = Pick<
  MeshSpanFetchClient,
  "createDirectory" | "deleteObject" | "renameObject"
>;

export async function sendFileMutation(
  client: Client,
  request: FileMutation,
  csrfToken: string,
): Promise<FileReceipt> {
  const operation_id = request.operation_id;
  switch (request.kind) {
    case "create":
      return client.createDirectory(
        request.volume_id,
        { operation_id, path: request.path },
        csrfToken,
      );
    case "delete":
      return client.deleteObject(
        request.volume_id,
        { operation_id, path: request.path },
        csrfToken,
      );
    case "rename":
      return client.renameObject(
        request.volume_id,
        {
          operation_id,
          source_path: request.source_path,
          target_path: request.target_path,
        },
        csrfToken,
      );
  }
}

export function verifyFileReceipt(
  receipt: FileReceipt,
  request: FileMutation,
): void {
  if (
    receipt.operation_id !== request.operation_id ||
    receipt.volume_id !== request.volume_id ||
    receipt.head_sequence <= 0
  ) {
    throw new TypeError("File receipt does not match the requested operation.");
  }
  if (request.kind !== "create" && receipt.object_id !== request.object_id) {
    throw new TypeError("File receipt does not match the requested object.");
  }
  verifyFilePath(receipt, request);
}

function verifyFilePath(receipt: FileReceipt, request: FileMutation): void {
  switch (request.kind) {
    case "create":
      if (
        !("path" in receipt) ||
        receipt.path !== request.path ||
        "scope" in receipt
      )
        throw new TypeError("Folder receipt does not match the created path.");
      break;
    case "delete":
      if (!("scope" in receipt) || receipt.path !== request.path)
        throw new TypeError(
          "Deletion receipt does not confirm the requested branch deletion.",
        );
      break;
    case "rename":
      if (
        !("source_path" in receipt) ||
        receipt.source_path !== request.source_path ||
        receipt.target_path !== request.target_path
      )
        throw new TypeError(
          "Rename receipt does not match the requested paths.",
        );
      break;
  }
}
