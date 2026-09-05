// SPDX-License-Identifier: GPL-2.0-only

//! Embeds the explicitly built panel; never downloads tools or starts a web server.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::Path;

const MAX_ASSETS: usize = 512;
const MAX_ASSET_BYTES: u64 = 16 * 1024 * 1024;

#[allow(clippy::print_stdout, reason = "Cargo build directives use stdout")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let crate_root = env::var("CARGO_MANIFEST_DIR")?;
    let output = env::var("OUT_DIR")?;
    let bundle = Path::new(&crate_root).join("../../web/dist");
    // Cargo must notice both replacements and additions to the compiled bundle.
    println!("cargo::rerun-if-changed=../../web/dist");
    if !bundle.join("index.html").is_file() {
        return Err("panel bundle missing: activate NVM and run `pnpm build:daemon` or `pnpm check`; direct Cargo builds consume the most recently built web/dist".into());
    }
    let mut source = String::from("const EMBEDDED_ASSETS: &[WebAsset] = &[\n");
    embed(
        &mut source,
        &bundle.join("index.html"),
        "/index.html",
        "text/html; charset=utf-8",
    )?;
    let mut assets = Vec::new();
    for entry in fs::read_dir(bundle.join("assets"))?.take(MAX_ASSETS + 1) {
        assets.push(entry?.path());
    }
    if assets.len() > MAX_ASSETS {
        return Err("panel bundle exceeds the asset-count limit".into());
    }
    assets.sort();
    for file in assets {
        let name = file
            .file_name()
            .and_then(|value| value.to_str())
            .ok_or("panel asset name is not UTF-8")?;
        if !name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"-_.".contains(&byte))
        {
            return Err("panel asset name is not a simple generated filename".into());
        }
        let media_type = match file.extension().and_then(|value| value.to_str()) {
            Some("js") => "text/javascript; charset=utf-8",
            Some("css") => "text/css; charset=utf-8",
            // Debug sources and the Vite manifest are not public appliance resources.
            Some("map") => continue,
            _ => {
                return Err(
                    "unsupported panel asset type; declare its serving policy before embedding"
                        .into(),
                );
            }
        };
        embed(&mut source, &file, &format!("/assets/{name}"), media_type)?;
    }
    source.push_str("];\n");
    fs::write(Path::new(&output).join("web_assets.rs"), source)?;
    Ok(())
}

fn embed(
    source: &mut String,
    file: &Path,
    route: &str,
    media_type: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let metadata = fs::symlink_metadata(file)?;
    if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_ASSET_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "panel asset must be a bounded non-empty regular file",
        )
        .into());
    }
    let absolute = fs::canonicalize(file)?;
    let absolute = absolute.to_str().ok_or("panel asset path is not UTF-8")?;
    writeln!(
        source,
        "WebAsset {{ route: {route:?}, media_type: {media_type:?}, bytes: include_bytes!({absolute:?}) }},"
    )?;
    Ok(())
}
