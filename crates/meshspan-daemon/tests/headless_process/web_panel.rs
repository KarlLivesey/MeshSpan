// SPDX-License-Identifier: GPL-2.0-only

//! Real TLS delivery of the compiled application before claim and after joining.

use super::{
    ClientConfig, Error, SocketAddr, request_with_headers, require_status, response_body,
    response_header,
};

pub(super) async fn verify(
    address: SocketAddr,
    client: &ClientConfig,
) -> Result<(), Box<dyn Error>> {
    let index = include_str!("../../../../web/dist/index.html");
    for route in ["/", "/sign-in", "/admin/backups"] {
        let response = get(address, client, route).await?;
        require_status(&response, "200 OK", "load embedded panel")?;
        assert_eq!(
            response_header(&response, "content-type")?,
            "text/html; charset=utf-8"
        );
        assert_eq!(response_header(&response, "cache-control")?, "no-cache");
        assert_eq!(response_body(&response)?, index);
    }
    // Read the build output only in the test oracle; the daemon serves embedded bytes.
    let bundle = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../web/dist/assets");
    let mut checked = 0;
    for file in std::fs::read_dir(bundle)? {
        let file = file?.path();
        if !matches!(
            file.extension().and_then(|value| value.to_str()),
            Some("js" | "css")
        ) {
            continue;
        }
        let name = file
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or("non-UTF8 bundle name")?;
        let response = get(address, client, &format!("/assets/{name}")).await?;
        require_status(&response, "200 OK", "load embedded asset")?;
        assert_eq!(
            response_header(&response, "cache-control")?,
            "public, max-age=31536000, immutable"
        );
        assert_eq!(response_body(&response)?.as_bytes(), std::fs::read(&file)?);
        checked += 1;
    }
    assert!(checked >= 2);
    for route in [
        "/api/latest/not-a-route",
        "/assets/missing.js",
        "/src/main.tsx",
        "/.vite/manifest.json",
    ] {
        let response = get(address, client, route).await?;
        require_status(&response, "404 Not Found", "reject non-public resource")?;
        assert!(!response_body(&response)?.contains("<html"));
    }
    Ok(())
}

async fn get(
    address: SocketAddr,
    client: &ClientConfig,
    route: &str,
) -> Result<String, Box<dyn Error>> {
    request_with_headers(
        address,
        client,
        "GET",
        route,
        None,
        &[("Accept", "text/html")],
    )
    .await
    .map_err(|error| format!("embedded panel request {route}: {error}").into())
}
