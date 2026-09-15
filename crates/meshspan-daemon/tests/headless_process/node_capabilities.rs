// SPDX-License-Identifier: GPL-2.0-only

//! Automatic transport reports must follow joining, voter promotion and restart.

use super::*;
use std::io;

#[tokio::test]
async fn native_nodes_refresh_exact_capabilities_after_promotion_and_restart()
-> Result<(), Box<dyn Error>> {
    let root = ProcessFixture::new()?;
    let second = ProcessFixture::new()?;
    let third = ProcessFixture::new()?;
    let mut processes = ProcessCleanup(vec![root.start()?]);
    let proof = tokio::time::timeout(Duration::from_secs(180), async {
        let claim = wait_for_claim(&root.claim_path).await?;
        let root_client = wait_for_client(&root.identity_path).await?;
        wait_for_status(root.address, &root_client, "claim_required").await?;
        let created = create_process_mesh(&root, &root_client, &claim).await?;
        let api_key = created["api_key"]
            .as_str()
            .ok_or("missing initial API key")?;
        save_and_verify_recovery_bundle(&root, &root_client, api_key, &created).await?;
        let join_code = issue_join_code(&root, &root_client, api_key).await?;
        processes.0.push(second.start_join(&join_code)?);
        let second_client = wait_for_client(&second.identity_path).await?;
        wait_for_status(second.address, &second_client, "configured").await?;
        processes.0.push(third.start_join(&join_code)?);
        let third_client = wait_for_client(&third.identity_path).await?;
        wait_for_status(third.address, &third_client, "configured").await?;
        let fixtures = [&root, &second, &third];
        wait_for_three_voters(fixtures, &root.identity_path).await?;
        wait_for_presentations(fixtures).await?;
        stop_processes(&mut processes.0);
        for fixture in fixtures {
            processes.0.push(fixture.start()?);
        }
        wait_for_status(root.address, &root_client, "configured").await?;
        wait_for_status(second.address, &second_client, "configured").await?;
        wait_for_status(third.address, &third_client, "configured").await?;
        wait_for_three_voters(fixtures, &root.identity_path).await?;
        wait_for_presentations(fixtures).await?;
        Ok::<_, Box<dyn Error>>(())
    })
    .await
    .map_err(|_| -> Box<dyn Error> { "automatic capability proof exceeded 180s".into() })
    .and_then(std::convert::identity);
    drop(processes);
    retain_failure_state(proof, [root.temporary, second.temporary, third.temporary])
}

async fn wait_for_presentations(fixtures: [&ProcessFixture; 3]) -> Result<(), Box<dyn Error>> {
    let root_node = fixture_node_id(fixtures[0])?;
    let partition = InitialBootstrapMaterial::root_partition_id(root_node)?;
    let nodes = fixtures
        .map(fixture_node_id)
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let paths = fixtures.map(|fixture| fixture.state_path.clone());
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        let paths = paths.clone();
        let nodes = nodes.clone();
        let complete = tokio::task::spawn_blocking(move || -> Result<bool, String> {
            let observed = observed_presentations(&paths, &nodes)?;
            for path in paths {
                let database = PartitionDatabase::open(
                    &path.join("root-authority.sqlite3"),
                    partition,
                    UnixMicros::new(1),
                )
                .map_err(|error| error.to_string())?;
                let repository = AuthoritativeRepository::new(database);
                for node in &nodes {
                    let Some(presentation) = repository
                        .node_capability_presentation(*node)
                        .map_err(|error| error.to_string())?
                    else {
                        return Ok(false);
                    };
                    let certificate = repository
                        .active_node_certificate(*node)
                        .map_err(|error| error.to_string())?
                        .ok_or("missing current node certificate")?;
                    if presentation.incarnation != certificate.incarnation
                        || presentation.certificate_generation != certificate.generation
                        || presentation.certificate_fingerprint
                            != certificate.certificate_fingerprint
                        || !observed.iter().any(|cached| {
                            cached.node_id == *node
                                && cached.incarnation == presentation.incarnation
                                && cached.certificate_fingerprint
                                    == presentation.certificate_fingerprint
                                && cached.capability_digest == presentation.capability_digest
                        })
                    {
                        return Ok(false);
                    }
                }
            }
            Ok(true)
        })
        .await?
        .map_err(io::Error::other)?;
        if complete {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err(
                "three replicas did not observe all current node capability reports".into(),
            );
        }
        sleep(RETRY_INTERVAL).await;
    }
}

fn observed_presentations(
    paths: &[std::path::PathBuf; 3],
    nodes: &[meshspan_domain::NodeId],
) -> Result<Vec<meshspan_metadata::CachedNodeCapabilityPresentation>, String> {
    use meshspan_protocol::v1::control_envelope::Message;
    let limits = meshspan_protocol::WireLimits::new(64 * 1024, 1024 * 1024, 1024, 4096)
        .map_err(|error| error.to_string())?;
    let mut observed = Vec::new();
    for (path, node) in paths.iter().zip(nodes) {
        let local = meshspan_metadata::LocalDatabase::open(
            &path.join("local.sqlite3"),
            *node,
            UnixMicros::new(1),
        )
        .map_err(|error| error.to_string())?;
        for cached in local
            .node_capability_presentations()
            .map_err(|error| error.to_string())?
        {
            let envelope = meshspan_protocol::decode_control_frame(&cached.canonical_hello, limits)
                .map_err(|error| error.to_string())?;
            let Some(Message::NodeHello(hello)) = &envelope.as_inner().message else {
                return Err("cached preimage was not NodeHello".into());
            };
            if hello.node_id.as_slice() != cached.node_id.as_bytes()
                || hello.incarnation != cached.incarnation
                || meshspan_protocol::node_capability_digest(hello) != cached.capability_digest
            {
                return Err("cached capability preimage changed identity or digest".into());
            }
            if hello
                .roles
                .contains(&i32::from(meshspan_protocol::v1::NodeRole::MetadataVoter))
                && hello.consensus_transfer.as_ref()
                    == Some(&meshspan_protocol::consensus_transfer_support())
            {
                observed.push(cached);
            }
        }
    }
    Ok(observed)
}
