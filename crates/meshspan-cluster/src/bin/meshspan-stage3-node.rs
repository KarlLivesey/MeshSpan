// SPDX-License-Identifier: GPL-2.0-only

//! Stage 3 headless node executable used by the real multi-process acceptance proof.

#[tokio::main]
async fn main() -> Result<(), meshspan_cluster::NodeRuntimeError> {
    meshspan_cluster::run_stage_three_node(std::env::args().skip(1)).await
}
