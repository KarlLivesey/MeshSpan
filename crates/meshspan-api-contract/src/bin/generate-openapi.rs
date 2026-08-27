// SPDX-License-Identifier: GPL-2.0-only

//! Writes the deterministic rolling `OpenAPI` contract to its committed path.

use std::{env, fs, path::Path, process::ExitCode};

use meshspan_api_contract::{OPENAPI_PATH, generate_openapi};

#[allow(
    clippy::print_stderr,
    reason = "the command-line generator must report a fatal error to its caller"
)]
fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("OpenAPI generation failed: {message}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let output = env::args()
        .nth(1)
        .unwrap_or_else(|| OPENAPI_PATH.to_owned());
    let output_path = Path::new(&output);
    let parent = output_path
        .parent()
        .ok_or_else(|| format!("output path has no parent: {output}"))?;
    fs::create_dir_all(parent)
        .map_err(|error| format!("could not create {}: {error}", parent.display()))?;

    let document = generate_openapi().map_err(|error| error.to_string())?;
    let bytes = document
        .to_pretty_bytes()
        .map_err(|error| error.to_string())?;
    let temporary = output_path.with_extension("json.tmp");
    fs::write(&temporary, bytes)
        .map_err(|error| format!("could not write {}: {error}", temporary.display()))?;
    fs::rename(&temporary, output_path)
        .map_err(|error| format!("could not replace {}: {error}", output_path.display()))?;
    Ok(())
}
