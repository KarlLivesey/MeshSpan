// SPDX-License-Identifier: GPL-2.0-only

use std::fs;
use std::os::unix::fs::PermissionsExt;

use meshspan_api_contract::{JoinMeshSetupRequest, decode_join_mesh_setup_request};
use meshspan_domain::{ClaimBundle, EntropyError, JoinGrantBundle, MeshId, RandomSource};
use serde_json::json;
use tempfile::tempdir;

use crate::join_mesh_setup::load_pending_join;
use crate::{
    ClaimFile, JoinMeshSetupError, JoinMeshSetupService, SetupStateSnapshot, SetupStatusSource,
};

#[test]
fn accepted_join_is_owner_only_restart_safe_and_exactly_replayable()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let claim_path = directory.path().join("claim");
    let intent_path = directory.path().join("intent");
    let claim = ClaimBundle::generate(&mut SequentialRandom(1))?;
    ClaimFile::create(&claim_path, &claim)?;
    let request = request(&claim, "Shop gateway")?;
    let state = std::sync::Arc::new(SetupStateSnapshot::new(
        meshspan_api_contract::SetupState::ClaimRequired,
    ));
    let (restart, mut restarts) = tokio::sync::mpsc::unbounded_channel();
    let mut service = JoinMeshSetupService::new(
        claim_path.clone(),
        intent_path.clone(),
        std::sync::Arc::clone(&state),
        restart,
    );

    let accepted = service.accept(&request)?;
    assert_eq!(accepted.operation_id, request.operation_id);
    assert_eq!(restarts.try_recv(), Ok(()));
    assert_eq!(
        state.setup_state(),
        meshspan_api_contract::SetupState::Configuring
    );
    assert_eq!(
        fs::metadata(&intent_path)?.permissions().mode() & 0o777,
        0o600
    );
    assert!(load_pending_join(&intent_path, &claim_path)? == Some(request.clone()));

    service.accept(&request)?;
    assert_eq!(restarts.try_recv(), Ok(()));
    Ok(())
}

#[test]
fn changed_retry_cannot_replace_the_protected_join_intent() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let claim_path = directory.path().join("claim");
    let intent_path = directory.path().join("intent");
    let claim = ClaimBundle::generate(&mut SequentialRandom(1))?;
    ClaimFile::create(&claim_path, &claim)?;
    let state = std::sync::Arc::new(SetupStateSnapshot::new(
        meshspan_api_contract::SetupState::ClaimRequired,
    ));
    let (restart, _restarts) = tokio::sync::mpsc::unbounded_channel();
    let mut service = JoinMeshSetupService::new(claim_path, intent_path, state, restart);
    service.accept(&request(&claim, "Shop gateway")?)?;

    assert!(matches!(
        service.accept(&request(&claim, "Changed gateway")?),
        Err(JoinMeshSetupError::Conflict)
    ));
    Ok(())
}

fn request(
    claim: &ClaimBundle,
    node_name: &str,
) -> Result<JoinMeshSetupRequest, Box<dyn std::error::Error>> {
    let mesh_id = MeshId::from_bytes([7; 16])?;
    let invitation = JoinGrantBundle::generate(
        mesh_id,
        "https://127.0.0.1:9443",
        [9; 32],
        &mut SequentialRandom(60),
    )?;
    Ok(decode_join_mesh_setup_request(&serde_json::to_vec(
        &json!({
            "operation_id": "00000000-0000-4000-8000-000000000001",
            "claim": claim.expose_encoded().as_str(),
            "join_code": invitation.expose_encoded().as_str(),
            "host_name": "Shop server",
            "node_name": node_name,
        }),
    )?)?)
}

struct SequentialRandom(u8);

impl RandomSource for SequentialRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        for byte in destination {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1);
        }
        Ok(())
    }
}
