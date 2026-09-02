# Stage 7 implementation evidence

Status: complete on 2026-09-03.

Stage 7 delivers the embedded SMB 3.1.1 appliance slice. This is implementation
evidence, not a release declaration; release creation remains disabled pending
the dependency review.

## Delivered surfaces

| Surface                 | Executable evidence                                                                                                                                                                                                                    |
| ----------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Embedded service        | The Rust daemon negotiates SMB 3.1.1, authenticates sessions, serves published trees and handles file IO without Samba, FUSE or another service.                                                                                       |
| Shared identity         | One ordinary MeshSpan API key authenticates the same user through HTTPS and every SMB gateway; no SMB-only credential database exists.                                                                                                 |
| Common filesystem       | Create, write, flush, close, read, rename and delete use the same copy-on-write filesystem authority and immutable namespace history as the native HTTPS API.                                                                          |
| Gateway convergence     | Namespace history, content layouts, wrapped content keys and remote shard routes converge between three independently persisted daemon processes.                                                                                      |
| Exact failure behaviour | A live encrypted SMB client retains exact acknowledged bytes after metadata-leader loss, reads locally after a second storage process is killed and receives `NT_STATUS_IO_TIMEOUT` for content available only from that lost process. |
| Resource bounds         | Private control requests, concurrent history-object retrieval, SMB frames, buffers and operations are explicitly bounded; private QUIC control connections are reused.                                                                 |
| Storage isolation       | SMB exposes only authorised logical objects in published volumes. Provider-folder paths and sibling host files are never mapped into the SMB namespace.                                                                                |

## Real-client proof

The ignored process test starts three real MeshSpan daemon processes with three
metadata voters, separate SQLite state and separate storage folders. A pinned
Debian Linux container supplies the real `smbclient`; all traffic is SMB 3.1.1
with SMB encryption required.

The client uploads through gateway one, downloads and renames through gateway
two, downloads and deletes through gateway three, and observes the deletion from
gateway two. The proof then creates another file through gateway three, kills the
confirmed metadata leader while the client remains active, verifies exact bytes,
kills the process holding a different file's only shard, verifies locally held
bytes again and checks the exact unavailable-content status.

Two clean consecutive runs passed in 47.97 and 48.36 seconds.

## Local verification

The final focused gate ran with warnings denied and no GitHub Actions:

```text
PASS meshspan-filesystem unit tests (194 passed)
PASS meshspan-cluster unit tests (59 passed)
PASS meshspan-smb unit and conformance tests (61 passed)
PASS meshspan-daemon unit tests (165 passed)
PASS real three-process SMB 3.1.1 failure proof (2 consecutive runs)
PASS cargo clippy for all affected packages and targets (-D warnings)
PASS Rust dependency licence policy
PASS JavaScript dependency licence policy
```
