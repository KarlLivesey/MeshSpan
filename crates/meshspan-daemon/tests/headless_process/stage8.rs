// SPDX-License-Identifier: GPL-2.0-only

//! Real-process Stage 8 proof through the public HTTPS and embedded SMB boundaries.

use std::collections::BTreeMap;

use super::*;

const MACHINE_CLASS_ID: &str = "6d657368-7370-816e-ad6d-616368696e65";
const STORAGE_DEVICE_CLASS_ID: &str = "6d657368-7370-826e-ae64-657669636521";

#[tokio::test]
#[ignore = "requires the local pinned smbclient container image"]
async fn six_nodes_apply_one_protection_contract_through_https_and_smb()
-> Result<(), Box<dyn Error>> {
    let fixtures = (0..6)
        .map(|_| ProcessFixture::new())
        .collect::<Result<Vec<_>, _>>()?;
    let mut processes = vec![fixtures[0].start()?];
    let proof = async {
        let claim = wait_for_claim(&fixtures[0].claim_path).await?;
        let root_client = wait_for_client(&fixtures[0].identity_path).await?;
        let administrator_id = bootstrap_administrator_id(&claim, &fixtures[0].identity_path)?;
        wait_for_status(fixtures[0].address, &root_client, "claim_required").await?;
        let created = create_process_mesh(&fixtures[0], &root_client, &claim).await?;
        let api_key = created["api_key"]
            .as_str()
            .ok_or("setup response omitted the API key")?;
        save_and_verify_recovery_bundle(&fixtures[0], &root_client, api_key, &created).await?;

        let join_code = issue_join_code_for_five(&fixtures[0], &root_client, api_key).await?;
        let mut clients = vec![root_client];
        for (index, fixture) in fixtures[1..].iter().enumerate() {
            processes.push(fixture.start_join(&join_code)?);
            let client = wait_for_client(&fixture.identity_path).await?;
            wait_for_status(fixture.address, &client, "configured").await?;
            if let Err(error) = wait_for_live_provider(fixture).await {
                return Err(format!(
                    "joined node {} provider: {error}; {}",
                    index + 2,
                    local_target_diagnostic(&fixtures, fixture, &fixtures[0].identity_path)
                )
                .into());
            }
            clients.push(client);
        }
        wait_for_stage8_voter_plan(&fixtures, &fixtures[0].identity_path).await?;
        wait_for_all_authentication_roots(&fixtures, &fixtures[0].identity_path).await?;
        register_second_targets(&fixtures, &clients, api_key).await?;

        let topology = topology_snapshot(fixtures[0].address, &clients[0], api_key).await?;
        let cells = create_cells_and_memberships(
            fixtures[0].address,
            &clients[0],
            api_key,
            &topology,
            &fixtures,
        )
        .await?;
        let policies =
            create_stage8_policies(fixtures[0].address, &clients[0], api_key, &cells).await?;
        let volume =
            create_volume_details(fixtures[0].address, &clients[0], api_key, &administrator_id)
                .await?;
        assign_stage8_policies(
            fixtures[0].address,
            &clients[0],
            api_key,
            &volume.volume_id,
            &policies,
        )
        .await?;
        publish_smb_export(fixtures[0].address, &clients[0], api_key, &volume).await?;
        wait_for_smb_export_visibility(
            [&fixtures[0], &fixtures[1], &fixtures[2]],
            &fixtures[0].identity_path,
        )
        .await?;
        for fixture in &fixtures {
            wait_for_smb_listener(fixture.smb_address).await?;
        }

        prove_https_and_smb_share_one_protected_namespace(
            &fixtures,
            &clients,
            api_key,
            &volume.volume_id,
        )
        .await?;
        prove_two_machine_cell_loss_remains_readable(
            &fixtures,
            &clients,
            &mut processes,
            api_key,
            &volume.volume_id,
        )
        .await
    }
    .await;
    stop_processes(&mut processes);
    proof
}

async fn wait_for_stage8_voter_plan(
    fixtures: &[ProcessFixture],
    root_identity_path: &Path,
) -> Result<(), Box<dyn Error>> {
    let root_identity = LocalNodeIdentity::open(root_identity_path, CERTIFICATE_NAME)?;
    let root_node = InitialBootstrapMaterial::node_id(root_identity.public_key_fingerprint())?;
    let partition_id = InitialBootstrapMaterial::root_partition_id(root_node)?;
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        if fixtures.iter().all(|fixture| {
            has_stage8_voter_plan(&fixture.state_path, partition_id).unwrap_or(false)
        }) {
            return Ok(());
        }
        if Instant::now() >= deadline {
            let states = fixtures
                .iter()
                .enumerate()
                .map(|(index, fixture)| {
                    format!(
                        "node{}=({})",
                        index + 1,
                        authority_diagnostic(fixture, root_identity_path, None)
                    )
                })
                .collect::<Vec<_>>()
                .join(", ");
            return Err(format!("five-voter convergence failed: [{states}]").into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

fn has_stage8_voter_plan(
    state_path: &Path,
    partition_id: PartitionId,
) -> Result<bool, Box<dyn Error>> {
    let database = PartitionDatabase::open(
        &state_path.join("root-authority.sqlite3"),
        partition_id,
        UnixMicros::new(1),
    )?;
    let active = AuthoritativeRepository::new(database).load_active_consensus_quorum_plan()?;
    Ok(matches!(
        active,
        Some(ActiveQuorumPlan::Stable(plan))
            if plan.spec().voters.len() == 5 && plan.spec().learners.len() == 1
    ))
}

fn local_target_diagnostic(
    fixtures: &[ProcessFixture],
    fixture: &ProcessFixture,
    root_identity_path: &Path,
) -> String {
    let marker = fixture
        .storage_path
        .join(".meshspan/target.marker")
        .is_file();
    let pack = fixture
        .storage_path
        .join(".meshspan/packs/0000000000000001.sqlite3")
        .is_file();
    let (states, registration_operation) = match meshspan_metadata::LocalDatabase::open_existing(
        &fixture.state_path.join("local.sqlite3"),
        UnixMicros::new(1),
    ) {
        Ok(database) => database.local_targets().map_or_else(
            |error| (format!("unreadable:{error}"), None),
            |targets| {
                (
                    targets
                        .iter()
                        .map(|target| format!("{:?}", target.state))
                        .collect::<Vec<_>>()
                        .join(","),
                    targets
                        .first()
                        .map(|target| target.intent.registration_operation_id),
                )
            },
        ),
        Err(error) => (format!("unreadable:{error}"), None),
    };
    let authorities = fixtures
        .iter()
        .enumerate()
        .map(|(index, candidate)| {
            format!(
                "node{}=({})",
                index + 1,
                authority_diagnostic(candidate, root_identity_path, registration_operation)
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "marker={marker}, pack={pack}, local_states=[{states}], operation={registration_operation:?}, authorities=[{authorities}]"
    )
}

fn authority_diagnostic(
    fixture: &ProcessFixture,
    root_identity_path: &Path,
    operation_id: Option<OperationId>,
) -> String {
    let result = (|| -> Result<String, Box<dyn Error>> {
        let identity = LocalNodeIdentity::open(root_identity_path, CERTIFICATE_NAME)?;
        let root_node = InitialBootstrapMaterial::node_id(identity.public_key_fingerprint())?;
        let partition_id = InitialBootstrapMaterial::root_partition_id(root_node)?;
        let repository = AuthoritativeRepository::new(PartitionDatabase::open(
            &fixture.state_path.join("root-authority.sqlite3"),
            partition_id,
            UnixMicros::new(1),
        )?);
        let plan = repository
            .load_active_consensus_quorum_plan()?
            .ok_or("active plan missing")?;
        let state = repository.load_consensus_state(plan.membership_epoch())?;
        let membership = repository
            .partition_membership()?
            .ok_or("membership missing")?;
        let operation_revision = operation_id
            .map(|operation_id| repository.resolve_operation(operation_id))
            .transpose()?
            .flatten()
            .map(|receipt| receipt.committed_revision.get());
        Ok(format!(
            "revision={}, epoch={}, voters={}, learners={}, projected_voters={}, projected_learners={}, term={}, vote={:?}, applied={}, log={}, operation_revision={operation_revision:?}",
            repository.current_revision()?.get(),
            plan.membership_epoch(),
            plan.voters().len(),
            plan.members().len().saturating_sub(plan.voters().len()),
            membership.active_voters().len(),
            membership.admitted_learners().len(),
            state.current_term,
            state.voted_for,
            state.applied_index,
            state.log.len(),
        ))
    })();
    result.unwrap_or_else(|error| format!("authority=unreadable:{error}"))
}

struct TopologySnapshot {
    hosts_by_node: BTreeMap<String, String>,
}

struct Stage8Policies {
    protection: String,
    locality: String,
    acknowledgement: String,
}

async fn issue_join_code_for_five(
    fixture: &ProcessFixture,
    client: &ClientConfig,
    api_key: &str,
) -> Result<String, Box<dyn Error>> {
    let body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "81000000-0000-4000-8000-000000000001",
        "enrolment_endpoint": format!("https://{}", fixture.address),
        "allowed_roles": ["storage", "gateway", "metadata_eligible"],
        "maximum_uses": 5,
        "valid_for_seconds": 3600
    }))?;
    let authorization = format!("Bearer {api_key}");
    let response = request_with_headers(
        fixture.address,
        client,
        "POST",
        "/api/latest/admin/node-join-grants",
        Some(&body),
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    require_status(&response, "201 Created", "issue five-use node join code")?;
    let response: serde_json::Value = serde_json::from_str(response_body(&response)?)?;
    response["join_code"]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| "join-grant response omitted the join code".into())
}

async fn wait_for_all_authentication_roots(
    fixtures: &[ProcessFixture],
    root_identity_path: &Path,
) -> Result<(), Box<dyn Error>> {
    let root_identity = LocalNodeIdentity::open(root_identity_path, CERTIFICATE_NAME)?;
    let root_node = InitialBootstrapMaterial::node_id(root_identity.public_key_fingerprint())?;
    let partition_id = InitialBootstrapMaterial::root_partition_id(root_node)?;
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        if fixtures
            .iter()
            .all(|fixture| has_authentication_root_access(fixture, partition_id).unwrap_or(false))
        {
            return Ok(());
        }
        if Instant::now() >= deadline {
            return Err("authentication root did not become accessible to all six nodes".into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

async fn register_second_targets(
    fixtures: &[ProcessFixture],
    clients: &[ClientConfig],
    api_key: &str,
) -> Result<(), Box<dyn Error>> {
    for (index, (fixture, client)) in fixtures.iter().zip(clients).enumerate() {
        let operation_id = format!("82000000-0000-4000-8000-{index:012x}");
        register_storage_folder_with_operation(
            fixture.address,
            client,
            api_key,
            &fixture.additional_storage_path,
            &operation_id,
        )
        .await?;
    }
    Ok(())
}

async fn register_storage_folder_with_operation(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    folder_path: &Path,
    operation_id: &str,
) -> Result<(), Box<dyn Error>> {
    let path = folder_path
        .to_str()
        .ok_or("additional storage path was not UTF-8")?;
    let body = serde_json::to_vec(&serde_json::json!({
        "operation_id": operation_id,
        "path": path,
        "usage_limit": { "kind": "percent", "percent": 90 }
    }))?;
    let authorization = format!("Bearer {api_key}");
    let response = request_with_headers(
        address,
        client,
        "POST",
        "/api/latest/admin/storage-folders",
        Some(&body),
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    require_status(&response, "201 Created", "register second storage target")
}

async fn topology_snapshot(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
) -> Result<TopologySnapshot, Box<dyn Error>> {
    let payload = get_json(
        address,
        client,
        api_key,
        "/api/latest/admin/topology/nodes?limit=100",
        "list six-node topology",
    )
    .await?;
    let nodes = payload["nodes"]
        .as_array()
        .ok_or("topology response omitted nodes")?;
    if nodes.len() != 6 {
        return Err(format!("topology contained {} nodes instead of six", nodes.len()).into());
    }
    let hosts_by_node = nodes
        .iter()
        .map(|node| {
            Ok((
                node["node_id"]
                    .as_str()
                    .ok_or("topology node omitted node_id")?
                    .to_owned(),
                node["host_id"]
                    .as_str()
                    .ok_or("topology node omitted host_id")?
                    .to_owned(),
            ))
        })
        .collect::<Result<BTreeMap<_, _>, Box<dyn Error>>>()?;
    Ok(TopologySnapshot { hosts_by_node })
}

async fn create_cells_and_memberships(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    topology: &TopologySnapshot,
    fixtures: &[ProcessFixture],
) -> Result<[String; 3], Box<dyn Error>> {
    let mut cells = Vec::new();
    for index in 0..3 {
        let body = serde_json::to_vec(&serde_json::json!({
            "operation_id": format!("83000000-0000-4000-8000-{index:012x}"),
            "name": format!("Stage 8 cell {}", index + 1),
            "parent_cell_id": null
        }))?;
        let created = mutate_json(
            address,
            client,
            api_key,
            "POST",
            "/api/latest/admin/topology/availability-cells",
            &body,
            "201 Created",
            "create availability cell",
        )
        .await?;
        cells.push(
            created["cell"]["cell_id"]
                .as_str()
                .ok_or("cell creation omitted cell_id")?
                .to_owned(),
        );
    }

    let hosts = fixtures
        .iter()
        .map(|fixture| fixture_host(topology, fixture))
        .collect::<Result<Vec<_>, _>>()?;
    for (index, host_id) in hosts.iter().enumerate() {
        let body = serde_json::to_vec(&serde_json::json!({
            "operation_id": format!("84000000-0000-4000-8000-{index:012x}"),
            "present": true
        }))?;
        mutate_json(
            address,
            client,
            api_key,
            "PUT",
            &format!(
                "/api/latest/admin/topology/availability-cells/{}/hosts/{host_id}",
                cells[index / 2]
            ),
            &body,
            "200 OK",
            "assign host to availability cell",
        )
        .await?;
    }
    cells
        .try_into()
        .map_err(|_| "availability-cell construction was incomplete".into())
}

fn fixture_host(
    topology: &TopologySnapshot,
    fixture: &ProcessFixture,
) -> Result<String, Box<dyn Error>> {
    let identity = LocalNodeIdentity::open(&fixture.identity_path, CERTIFICATE_NAME)?;
    let node_id = InitialBootstrapMaterial::node_id(identity.public_key_fingerprint())?.to_string();
    topology
        .hosts_by_node
        .iter()
        .find(|(encoded, _)| encoded.replace('-', "") == node_id)
        .map(|(_, host)| host.clone())
        .ok_or_else(|| "fixture node was absent from the topology snapshot".into())
}

async fn create_stage8_policies(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    cells: &[String; 3],
) -> Result<Stage8Policies, Box<dyn Error>> {
    let protection = create_protection_policy(
        address,
        client,
        api_key,
        "85000000-0000-4000-8000-000000000001",
        "Two machines and three devices",
        vec![serde_json::json!({
            "name": "Combined two-machine and three-device loss",
            "terms": [
                { "class_id": MACHINE_CLASS_ID, "failure_count": 2 },
                { "class_id": STORAGE_DEVICE_CLASS_ID, "failure_count": 3 }
            ]
        })],
    )
    .await?;
    let scenario_id = text_field(&protection["policy"]["scenarios"][0], "scenario_id")?;
    let protection = text_field(&protection["policy"], "policy_id")?;

    let local = create_protection_policy(
        address,
        client,
        api_key,
        "85000000-0000-4000-8000-000000000002",
        "One local device",
        vec![serde_json::json!({
            "name": "One local storage-device loss",
            "terms": [{ "class_id": STORAGE_DEVICE_CLASS_ID, "failure_count": 1 }]
        })],
    )
    .await?;
    let local_id = text_field(&local["policy"], "policy_id")?;

    let locality = create_locality_policy(address, client, api_key, cells, &local_id).await?;
    let acknowledgement =
        create_acknowledgement_policy(address, client, api_key, cells, &local_id, &scenario_id)
            .await?;
    Ok(Stage8Policies {
        protection,
        locality,
        acknowledgement,
    })
}

async fn create_locality_policy(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    cells: &[String; 3],
    local_policy: &str,
) -> Result<String, Box<dyn Error>> {
    let body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "86000000-0000-4000-8000-000000000001",
        "name": "Complete in two cells",
        "maximum_lag_micros": 5_000_000,
        "requirements": [
            { "cell_id": cells[0], "local_protection_policy_id": local_policy },
            { "cell_id": cells[1], "local_protection_policy_id": local_policy }
        ]
    }))?;
    let response = mutate_json(
        address,
        client,
        api_key,
        "POST",
        "/api/latest/admin/locality-policies",
        &body,
        "201 Created",
        "create two-cell locality policy",
    )
    .await?;
    text_field(&response["policy"], "policy_id")
}

async fn create_acknowledgement_policy(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    cells: &[String; 3],
    local_policy: &str,
    scenario: &str,
) -> Result<String, Box<dyn Error>> {
    let body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "87000000-0000-4000-8000-000000000001",
        "name": "Two cells before strong acknowledgement",
        "consistency": "strong",
        "minimum_durable_targets": 6,
        "minimum_distinct_nodes": 4,
        "strong_wait_micros": 10_000_000,
        "fallback": "remain_pending",
        "required_scenario_ids": [scenario],
        "cells": [
            {
                "cell_id": cells[0],
                "mode": "required_before_commit",
                "minimum_durable_targets": 3,
                "minimum_distinct_nodes": 2,
                "local_protection_policy_id": local_policy
            },
            {
                "cell_id": cells[1],
                "mode": "required_before_commit",
                "minimum_durable_targets": 3,
                "minimum_distinct_nodes": 2,
                "local_protection_policy_id": local_policy
            },
            {
                "cell_id": cells[2],
                "mode": "eventual",
                "minimum_durable_targets": null,
                "minimum_distinct_nodes": null,
                "local_protection_policy_id": null
            }
        ]
    }))?;
    let response = mutate_json(
        address,
        client,
        api_key,
        "POST",
        "/api/latest/admin/acknowledgement-policies",
        &body,
        "201 Created",
        "create strong multi-cell acknowledgement policy",
    )
    .await?;
    text_field(&response["policy"], "policy_id")
}

async fn create_protection_policy(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    operation_id: &str,
    name: &str,
    scenarios: Vec<serde_json::Value>,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let body = serde_json::to_vec(&serde_json::json!({
        "operation_id": operation_id,
        "name": name,
        "scenarios": scenarios
    }))?;
    mutate_json(
        address,
        client,
        api_key,
        "POST",
        "/api/latest/admin/protection-policies",
        &body,
        "201 Created",
        "create protection policy",
    )
    .await
}

async fn assign_stage8_policies(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    volume_id: &str,
    policies: &Stage8Policies,
) -> Result<(), Box<dyn Error>> {
    for (index, (kind, policy_id)) in [
        ("protection", policies.protection.as_str()),
        ("locality", policies.locality.as_str()),
        ("acknowledgement", policies.acknowledgement.as_str()),
    ]
    .into_iter()
    .enumerate()
    {
        let body = serde_json::to_vec(&serde_json::json!({
            "operation_id": format!("88000000-0000-4000-8000-{index:012x}")
        }))?;
        mutate_json(
            address,
            client,
            api_key,
            "PUT",
            &format!("/api/latest/admin/volumes/{volume_id}/{kind}-policies/{policy_id}"),
            &body,
            "200 OK",
            "assign Stage 8 volume policy",
        )
        .await?;
    }
    Ok(())
}

async fn prove_https_and_smb_share_one_protected_namespace(
    fixtures: &[ProcessFixture],
    clients: &[ClientConfig],
    api_key: &str,
    volume_id: &str,
) -> Result<(), Box<dyn Error>> {
    let https_bytes = b"Stage 8 exact HTTPS protected bytes";
    let committed = upload_file(
        fixtures[2].address,
        &clients[2],
        api_key,
        volume_id,
        https_bytes,
    )
    .await?;
    require_strong_acknowledgement(&committed)?;
    wait_for_file_surfaces(
        fixtures[2].address,
        &clients[2],
        api_key,
        volume_id,
        https_bytes,
    )
    .await?;

    let exchange = TempDir::new()?;
    fs::write(
        exchange.path().join("smb-source.bin"),
        b"Stage 8 exact SMB protected bytes",
    )?;
    run_real_smb_command(
        fixtures[2].smb_address.port(),
        api_key.to_owned(),
        exchange.path(),
        "put /proof/smb-source.bin smb-protected.bin; get process-proof.bin /proof/from-https.bin",
    )
    .await?;
    if fs::read(exchange.path().join("from-https.bin"))? != https_bytes {
        return Err("embedded SMB returned bytes different from the HTTPS publication".into());
    }
    wait_for_named_file_length(
        fixtures[1].address,
        &clients[1],
        api_key,
        volume_id,
        "smb-protected.bin",
        b"Stage 8 exact SMB protected bytes".len(),
    )
    .await
}

async fn prove_two_machine_cell_loss_remains_readable(
    fixtures: &[ProcessFixture],
    clients: &[ClientConfig],
    processes: &mut [Child],
    api_key: &str,
    volume_id: &str,
) -> Result<(), Box<dyn Error>> {
    processes[4].kill()?;
    processes[4].wait()?;
    processes[5].kill()?;
    processes[5].wait()?;

    let exchange = TempDir::new()?;
    run_real_smb_command(
        fixtures[2].smb_address.port(),
        api_key.to_owned(),
        exchange.path(),
        "get smb-protected.bin /proof/after-two-machines.bin",
    )
    .await?;
    if fs::read(exchange.path().join("after-two-machines.bin"))?
        != b"Stage 8 exact SMB protected bytes"
    {
        return Err("SMB degraded read changed acknowledged bytes".into());
    }
    wait_for_named_file_length(
        fixtures[1].address,
        &clients[1],
        api_key,
        volume_id,
        "smb-protected.bin",
        b"Stage 8 exact SMB protected bytes".len(),
    )
    .await
}

fn require_strong_acknowledgement(response: &serde_json::Value) -> Result<(), Box<dyn Error>> {
    let acknowledgement = &response["acknowledgement"];
    if acknowledgement["configured_consistency"] == "strong"
        && acknowledgement["acknowledged_consistency"] == "strong"
        && acknowledgement["durability_scope"] == "globally_converged"
        && acknowledgement["policy_committed"] == true
        && acknowledgement["fallback_applied"] == false
        && acknowledgement["required_shard_receipts"]
            .as_u64()
            .is_some_and(|count| count >= 6)
    {
        Ok(())
    } else {
        Err(format!("HTTPS upload returned invalid strong evidence: {acknowledgement}").into())
    }
}

async fn get_json(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    route: &str,
    action: &str,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let authorization = format!("Bearer {api_key}");
    let response = request_with_headers(
        address,
        client,
        "GET",
        route,
        None,
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    require_status(&response, "200 OK", action)?;
    Ok(serde_json::from_str(response_body(&response)?)?)
}

#[allow(clippy::too_many_arguments)]
async fn mutate_json(
    address: SocketAddr,
    client: &ClientConfig,
    api_key: &str,
    method: &str,
    route: &str,
    body: &[u8],
    expected_status: &str,
    action: &str,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let authorization = format!("Bearer {api_key}");
    let response = request_with_headers(
        address,
        client,
        method,
        route,
        Some(body),
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    require_status(&response, expected_status, action)?;
    Ok(serde_json::from_str(response_body(&response)?)?)
}

fn text_field(value: &serde_json::Value, field: &str) -> Result<String, Box<dyn Error>> {
    value[field]
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| format!("response omitted {field}").into())
}
