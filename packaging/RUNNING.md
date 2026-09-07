# MeshSpan local development package

Licence: `GPL-2.0-only`. This is an unsigned local artefact, **not a release**.
Packaging does not establish stage acceptance, safe upgrades or compatibility.
No publication is permitted while the owner's review hold remains.

## Native daemon

The binary contains the HTTPS service, SMB service and web panels. It needs no
Node.js runtime, Samba, FUSE or separate web service. macOS uses only system
libraries; Linux packages require a statically linked musl executable.

Create separate writable state and storage directories, then run:

```sh
./bin/meshspan-daemon \
  --daemon-state-dir /your/meshspan-state \
  --storage-path /your/storage-one \
  --storage-path /your/storage-two \
  --https-listen 0.0.0.0:8443 \
  --http01-listen 0.0.0.0:8080 \
  --smb-listen 0.0.0.0:8445 \
  --private-listen 0.0.0.0:7443 \
  --private-endpoint node.example.internal:7443
```

Choose an endpoint other nodes can reach. Each `--storage-path` is a folder;
several folders on the same physical drive do not create drive redundancy.
Protect the state directory: it contains node identity, settings and metadata.
The first-boot claim appears only locally; do not paste it in logs or support
bundles. Use the HTTPS setup page to create a mesh or use `--join-code` for
headless enrolment. Treat join codes as secrets, including in shell history and
process arguments. Never share one state directory between daemon processes.

These high ports allow an unprivileged process. Normal SMB clients typically
require port 445: arrange a host/container port mapping, or grant only the
platform-specific low-port binding permission. Public HTTP-01 requires external
port 80 to reach the selected HTTP challenge listener. DNS-01 does not require
inbound HTTP. HTTPS initially uses locally managed trust, not a public CA.

## Container preparation — local only

Use only a static **Linux** package of the matching container architecture.
Place a reviewed public CA PEM bundle named `ca-certificates.crt` beside the
included Dockerfile. The bundle is an explicit prerequisite, not silently
downloaded trust. The image contains no shell or package manager.

```sh
docker build --network=none --pull=false --tag meshspan-local:development .
docker run --rm --read-only --cap-drop=ALL \
  --mount type=bind,src=/your/meshspan-state,dst=/state \
  --mount type=bind,src=/your/storage-one,dst=/storage \
  -p 8443:8443 -p 80:8080 -p 445:8445 -p 7443:7443/udp \
  meshspan-local:development \
  --daemon-state-dir /state --storage-path /storage \
  --https-listen 0.0.0.0:8443 --http01-listen 0.0.0.0:8080 \
  --smb-listen 0.0.0.0:8445 --private-listen 0.0.0.0:7443 \
  --private-endpoint node.example.internal:7443
```

Create the two bind directories first and make them writable by UID/GID 10001,
or use `--user` with their existing owner. Do not run recursive permission changes
on a folder containing unrelated files. Persist both mounts across replacement;
the ephemeral container layer must never hold acknowledged data or identity.

## Verification and upgrades

`SHA256SUMS` covers the unpacked files; the adjacent `.tar.gz.sha256` covers the
archive. Hashes detect corruption, **not publisher authenticity**. Provenance
records the source commit, dirty-worktree flag, toolchain, profile and linkage;
it does not claim a reproducible build or a completed acceptance run.
`dependencies.json` is a conservative package inventory including Rust build
dependencies, not a link-level SBOM or the complete third-party licence notices.

Pre-1.0 migrations can be one-way. Do not downgrade, replace binaries on live
state or infer upgrade safety from successful packaging. Keep verified encrypted
backups; supported rolling updates and disaster recovery require their separate
acceptance. Release signatures, complete notices/SBOM, platform proofs and
publication approval remain separate Stage 10 requirements.
