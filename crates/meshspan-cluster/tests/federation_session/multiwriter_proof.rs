// SPDX-License-Identifier: GPL-2.0-only

//! Composed two-swarm proof for disconnected edits, restart, admission and quarantine.

use std::error::Error;

use ed25519_dalek::SigningKey;
use meshspan_domain::{BranchId, UnixMicros};
use meshspan_filesystem::RootFilePublication;
use tempfile::{TempDir, tempdir};

use self::filesystem::{
    EditIdentity, FirstMerge, HomeMutationAcceptance, base_publication, next_publication,
    prove_quarantined_edit_stays_invisible, publish_before_home_suspension,
    reconcile_visible_edits, seed_disconnected_edits,
};
use self::metadata::FederationFixture;
use self::transport::sync_history;
use super::{ConnectionPair, MetadataAuthorities, SessionExpectation, SessionRuntimes};

#[path = "multiwriter_proof/filesystem.rs"]
mod filesystem;
#[path = "multiwriter_proof/metadata.rs"]
mod metadata;
#[path = "multiwriter_proof/transport.rs"]
mod transport;

const SYNC_NOW: UnixMicros = UnixMicros::new(1_500_000);

pub(super) async fn prove(
    authorities: &mut MetadataAuthorities,
    runtimes: SessionRuntimes<'_>,
    connections: &ConnectionPair,
    home_key: &SigningKey,
) -> Result<(), Box<dyn Error>> {
    let state = Box::pin(prove_disconnected_edits(
        authorities,
        runtimes,
        connections,
        home_key,
    ))
    .await?;
    Box::pin(prove_suspended_writer_quarantine(
        authorities,
        runtimes,
        connections,
        home_key,
        state,
    ))
    .await
}

struct DisconnectedEditState {
    federation: FederationFixture,
    source_directory: TempDir,
    owner_directory: TempDir,
    source_branch: BranchId,
    source: RootFilePublication,
    first_merge: FirstMerge,
}

async fn prove_disconnected_edits(
    authorities: &mut MetadataAuthorities,
    runtimes: SessionRuntimes<'_>,
    connections: &ConnectionPair,
    home_key: &SigningKey,
) -> Result<DisconnectedEditState, Box<dyn Error>> {
    let federation = FederationFixture::prepare(authorities, home_key)?;
    let proof = authorities.proof(
        runtimes,
        connections,
        SessionExpectation::new(
            90,
            authorities.server.repository().current_revision()?.get(),
            1,
        ),
    );
    super::prove_admitted_session(&proof)
        .await
        .map_err(|error| format!("initial federation session: {error}"))?;

    let source_directory = tempdir()?;
    let owner_directory = tempdir()?;
    let base = base_publication(authorities.client.administrator_id)?;
    let owner = next_publication(
        &base,
        base.file.branch_id,
        authorities.client.administrator_id,
        EditIdentity::new(100),
        b"home-edit",
    )?;
    let source_branch = BranchId::from_bytes([101; 16])?;
    let source = next_publication(
        &base,
        source_branch,
        federation.user,
        EditIdentity::new(110),
        b"shop-edit",
    )?;

    seed_disconnected_edits(
        source_directory.path(),
        owner_directory.path(),
        &base,
        &owner,
        &source,
        &HomeMutationAcceptance::new(
            &federation,
            home_key,
            proof.server_authority,
            federation.home_gateway,
        ),
    )?;
    sync_history(
        &proof,
        &federation,
        source_directory.path(),
        owner_directory.path(),
        source.namespace_commit_id,
        vec![base.namespace_commit_id],
        120,
    )
    .await
    .map_err(|error| format!("first history sync: {error}"))?;
    let first_merge = reconcile_visible_edits(
        owner_directory.path(),
        &base,
        &owner,
        &source,
        authorities.client.administrator_id,
    )
    .map_err(|error| format!("first reconciliation: {error}"))?;
    Ok(DisconnectedEditState {
        federation,
        source_directory,
        owner_directory,
        source_branch,
        source,
        first_merge,
    })
}

async fn prove_suspended_writer_quarantine(
    authorities: &mut MetadataAuthorities,
    runtimes: SessionRuntimes<'_>,
    connections: &ConnectionPair,
    home_key: &SigningKey,
    state: DisconnectedEditState,
) -> Result<(), Box<dyn Error>> {
    let DisconnectedEditState {
        mut federation,
        source_directory,
        owner_directory,
        source_branch,
        source,
        first_merge,
    } = state;
    let rejected = next_publication(
        &source,
        source_branch,
        federation.user,
        EditIdentity::new(130),
        b"late-edit",
    )
    .map_err(|error| format!("publish before suspension: {error}"))?;
    publish_before_home_suspension(
        source_directory.path(),
        &rejected,
        &HomeMutationAcceptance::new(
            &federation,
            home_key,
            &authorities.server.repository,
            federation.home_gateway,
        ),
    )?;
    federation
        .suspend_home_user(authorities, home_key)
        .map_err(|error| format!("home suspension: {error}"))?;
    let proof = authorities.proof(
        runtimes,
        connections,
        SessionExpectation::new(
            139,
            authorities.server.repository().current_revision()?.get(),
            1,
        ),
    );
    sync_history(
        &proof,
        &federation,
        source_directory.path(),
        owner_directory.path(),
        rejected.namespace_commit_id,
        vec![source.namespace_commit_id],
        140,
    )
    .await
    .map_err(|error| format!("quarantine history sync: {error}"))?;
    prove_quarantined_edit_stays_invisible(
        owner_directory.path(),
        &first_merge,
        &rejected,
        authorities.client.administrator_id,
    )
    .map_err(|error| format!("quarantine reconciliation: {error}"))?;
    Ok(())
}
