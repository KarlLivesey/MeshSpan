// SPDX-License-Identifier: GPL-2.0-only

//! `MeshSpan` headless appliance executable.

#[tokio::main]
async fn main() -> Result<(), meshspan_daemon::DaemonProcessError> {
    meshspan_daemon::run_headless_daemon(std::env::args_os().skip(1), async {
        let _signal = tokio::signal::ctrl_c().await;
    })
    .await
}
