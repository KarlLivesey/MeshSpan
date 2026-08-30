// SPDX-License-Identifier: GPL-2.0-only

use std::path::PathBuf;
use std::sync::Arc;

use meshspan_api_contract::{CreateMeshSetupRequest, decode_create_mesh_setup_request};
use meshspan_domain::{
    ClaimBundle, EntropyError, InitialBootstrapMaterial, OperationId, RandomSource, UnixMicros,
};
use meshspan_metadata::{
    AuthoritativeCommand, AuthoritativeRepository, CommandContext, LocalClaimState, LocalDatabase,
    LogPosition, NewLocalClaim, PartitionDatabase, RepositoryError,
};
use tempfile::tempdir;

use crate::{
    BootstrapAuthority, BootstrapAuthorityError, BootstrapCommit, ClaimFile, CreateMeshSetupError,
    CreateMeshSetupService, SetupStateSnapshot,
};

const OPERATION_TEXT: &str = "00000000-0000-4000-8000-000000000001";

#[test]
fn committed_response_loss_resolves_exactly_and_consumes_claim_once()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture(true)?;
    let mut service = fixture.service;
    assert!(matches!(
        service.create(&fixture.request, UnixMicros::new(20)),
        Err(CreateMeshSetupError::Authority(
            BootstrapAuthorityError::Unavailable
        ))
    ));
    assert!(service.claim_output_path().is_file());
    let response = service.create(&fixture.request, UnixMicros::new(30))?;
    assert_eq!(response.operation_id.as_str(), OPERATION_TEXT);
    assert!(response.api_key.starts_with("meshspan-key-v1."));
    assert!(!service.claim_output_path().exists());

    let local = LocalDatabase::open(
        &fixture.local_path,
        fixture.material.node_id,
        UnixMicros::new(40),
    )?;
    assert_eq!(
        local
            .local_claim_record(fixture.claim_id)?
            .ok_or("claim missing")?
            .state,
        LocalClaimState::Consumed
    );
    assert_eq!(
        local.local_setup()?.ok_or("setup missing")?.revision.get(),
        3
    );
    Ok(())
}

#[test]
fn changed_retry_conflicts_before_a_second_authority_mutation()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = fixture(false)?;
    let mut service = fixture.service;
    service.create(&fixture.request, UnixMicros::new(20))?;
    let changed = request(&fixture.claim, "Changed mesh")?;
    assert!(matches!(
        service.create(&changed, UnixMicros::new(30)),
        Err(CreateMeshSetupError::Local(_))
    ));
    Ok(())
}

struct Fixture {
    service: CreateMeshSetupService<RepositoryBootstrapAuthority>,
    request: CreateMeshSetupRequest,
    claim: ClaimBundle,
    claim_id: meshspan_domain::ClaimId,
    material: InitialBootstrapMaterial,
    local_path: PathBuf,
}

fn fixture(lose_first_response: bool) -> Result<Fixture, Box<dyn std::error::Error>> {
    let directory = tempdir()?.keep();
    let claim = ClaimBundle::generate(&mut SequentialRandom(1))?;
    let claim_id = claim.claim_id();
    let mut operation_bytes = [0_u8; 16];
    operation_bytes[6] = 0x40;
    operation_bytes[8] = 0x80;
    operation_bytes[15] = 1;
    let operation_id = OperationId::from_bytes(operation_bytes)?;
    let material = InitialBootstrapMaterial::derive(&claim, operation_id)?;
    let local_path = directory.join("local.sqlite3");
    let claim_path = directory.join("first-boot.claim");
    ClaimFile::create(&claim_path, &claim)?;
    let mut local_database =
        LocalDatabase::open(&local_path, material.node_id, UnixMicros::new(1))?;
    local_database.create_local_claim(NewLocalClaim {
        claim_id,
        node_public_key_fingerprint: [99; 32],
        secret_digest: claim.secret_digest(),
        created_at: UnixMicros::new(10),
    })?;
    let partition = PartitionDatabase::open(
        &directory.join("root.sqlite3"),
        material.partition_id,
        UnixMicros::new(1),
    )?;
    let setup_state = Arc::new(SetupStateSnapshot::new(
        meshspan_api_contract::SetupState::ClaimRequired,
    ));
    let service = CreateMeshSetupService::new(
        local_database,
        RepositoryBootstrapAuthority {
            repository: AuthoritativeRepository::new(partition),
            lose_first_response,
        },
        claim_path,
        setup_state,
    );
    let request = request(&claim, "First mesh")?;
    Ok(Fixture {
        service,
        request,
        claim,
        claim_id,
        material,
        local_path,
    })
}

fn request(
    claim: &ClaimBundle,
    mesh_name: &str,
) -> Result<CreateMeshSetupRequest, Box<dyn std::error::Error>> {
    let value = serde_json::json!({
        "operation_id": OPERATION_TEXT,
        "claim": claim.expose_encoded().as_str(),
        "mesh_name": mesh_name,
        "administrator_name": "Administrator",
        "host_name": "First host",
        "node_name": "First node"
    });
    Ok(decode_create_mesh_setup_request(&serde_json::to_vec(
        &value,
    )?)?)
}

struct RepositoryBootstrapAuthority {
    repository: AuthoritativeRepository,
    lose_first_response: bool,
}

impl BootstrapAuthority for RepositoryBootstrapAuthority {
    fn commit_or_resolve(
        &mut self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<BootstrapCommit, BootstrapAuthorityError> {
        if let Some(receipt) = self
            .repository
            .resolve_operation(context.operation_id)
            .map_err(|error| map_repository_error(&error))?
        {
            return Ok(BootstrapCommit {
                result_digest: receipt.result_digest,
            });
        }
        let receipt = self
            .repository
            .apply_committed(LogPosition { index: 1, term: 1 }, context, command)
            .map_err(|error| map_repository_error(&error))?;
        if self.lose_first_response {
            self.lose_first_response = false;
            return Err(BootstrapAuthorityError::Unavailable);
        }
        Ok(BootstrapCommit {
            result_digest: receipt.result_digest,
        })
    }
}

fn map_repository_error(error: &RepositoryError) -> BootstrapAuthorityError {
    match error {
        RepositoryError::OperationConflict => BootstrapAuthorityError::Conflict,
        RepositoryError::Store(_) | RepositoryError::Sqlite(_) | RepositoryError::Io(_) => {
            BootstrapAuthorityError::Unavailable
        }
        _ => BootstrapAuthorityError::Failed,
    }
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
