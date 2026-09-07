# SPDX-License-Identifier: GPL-2.0-only

# Build only from an inspected static Linux local package. No base-image pull,
# package manager, external daemon, runtime Node, FUSE or Samba is involved.
FROM scratch
LABEL org.opencontainers.image.title="MeshSpan"
LABEL org.opencontainers.image.licenses="GPL-2.0-only"
COPY bin/meshspan-daemon /usr/local/bin/meshspan-daemon
COPY LICENSE /usr/share/licenses/meshspan/LICENSE
COPY dependencies.json provenance.json /usr/share/meshspan/
# Supply a reviewed PEM trust bundle in the build context. Public CA trust is
# explicit; mesh-private roots are managed separately by the daemon.
COPY ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt
USER 10001:10001
EXPOSE 8443/tcp 8080/tcp 8445/tcp 7443/udp
STOPSIGNAL SIGINT
ENTRYPOINT ["/usr/local/bin/meshspan-daemon"]
CMD ["--daemon-state-dir", "/state", "--storage-path", "/storage", "--https-listen", "0.0.0.0:8443", "--http01-listen", "0.0.0.0:8080", "--smb-listen", "0.0.0.0:8445", "--private-listen", "0.0.0.0:7443"]
