// SPDX-License-Identifier: GPL-2.0-only

//! Three actual daemons: consumer swarm, provider gateway with drained storage, storage owner.

use super::{
    ClientConfig, Error, ProcessFixture, WAIT_LIMIT, request_with_headers, require_status,
    response_body,
};
use meshspan_domain::{BackupDestinationId, BackupId, InitialBootstrapMaterial, UnixMicros};
use meshspan_metadata::{AuthoritativeRepository, PageLimit, PartitionDatabase};
use serde_json::{Value, json};

const GRANTS: &str = "/api/latest/admin/federation/storage-grants";
const DESTINATIONS: &str = "/api/latest/admin/backups/destinations";
const GRANT: &str = "01900000-0000-7000-8000-000000000102";
const DESTINATION: &str = "01900000-0000-7000-8000-000000000103";

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn remote_backup_forwards_through_gateway_to_distinct_storage_process()
-> Result<(), Box<dyn Error>> {
    let gateway = ProcessFixture::new()?;
    let storage = ProcessFixture::new()?;
    let consumer = ProcessFixture::new()?;
    let mut processes = vec![gateway.start()?, consumer.start()?];
    let proof = async {
        let provider = Appliance::bootstrap(&gateway).await?;
        let consumer_api = Appliance::bootstrap(&consumer).await?;
        let join = super::issue_join_code(&gateway, &provider.client, &provider.api_key).await?;
        processes.push(storage.start_join(&join)?);
        let storage_client = super::wait_for_client(&storage.identity_path).await?;
        super::wait_for_status(storage.address, &storage_client, "configured").await?;
        super::wait_for_storage_folder_visibility(&storage, &storage_client, &provider.api_key)
            .await?;
        drain_gateway_storage(&provider).await?;
        let relationship = pair(&provider, &consumer_api).await?;
        offer(&provider, &relationship).await?;
        remote_only_destination(&consumer_api, &provider.mesh_id).await?;
        let sequence = super::stage10::request_post_enrolment_backup(
            consumer.address,
            &consumer_api.client,
            &consumer_api.authorization(),
        )
        .await?;
        let backup = super::backup_history::automatic_backup_history_for_schedule(
            consumer.address,
            &consumer_api.client,
            &consumer_api.authorization(),
            sequence,
        )
        .await;
        let backup = match backup {
            Ok(backup) => backup,
            Err(error) => {
                return Err(format!(
                    "{error}; provider lifecycle: {}; consumer lifecycle: {}",
                    provider.lifecycle_evidence().await,
                    consumer_api.lifecycle_evidence().await
                )
                .into());
            }
        };
        verify_exact_remote_copy(&consumer, &gateway, &storage, &backup)?;
        let original = super::backup_history::encrypted_export(
            consumer.address,
            &consumer_api.client,
            &consumer_api.authorization(),
            &backup,
        )
        .await?;
        processes[2].kill()?;
        processes[2].wait()?;
        processes[2] = storage.start()?;
        super::wait_for_status(storage.address, &storage_client, "configured").await?;
        let restored = super::backup_history::encrypted_export(
            consumer.address,
            &consumer_api.client,
            &consumer_api.authorization(),
            &backup,
        )
        .await?;
        assert_eq!(
            restored, original,
            "storage-owner restart must retain the exact encrypted backup"
        );
        if let Err(error) =
            verify_permission_succession(&provider, &consumer_api, &backup, &original).await
        {
            let evidence = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                super::diagnostics::failure_evidence(
                    storage.address,
                    &storage_client,
                    &provider.authorization(),
                ),
            )
            .await
            .unwrap_or_else(|_| "storage diagnostics timed out".to_owned());
            return Err(format!("{error}; storage: {evidence}").into());
        }
        Ok::<_, Box<dyn Error>>(())
    }
    .await;
    super::stop_processes(&mut processes);
    super::retain_failure_state(
        proof,
        [gateway.temporary, storage.temporary, consumer.temporary],
    )
}

struct Appliance<'a> {
    fixture: &'a ProcessFixture,
    client: ClientConfig,
    api_key: String,
    mesh_id: String,
    administrator_id: String,
}

impl<'a> Appliance<'a> {
    async fn bootstrap(fixture: &'a ProcessFixture) -> Result<Self, Box<dyn Error>> {
        let claim = super::wait_for_claim(&fixture.claim_path).await?;
        let client = super::wait_for_client(&fixture.identity_path).await?;
        let administrator_id = super::bootstrap_administrator_id(&claim, &fixture.identity_path)?;
        super::wait_for_status(fixture.address, &client, "claim_required").await?;
        let created = super::create_process_mesh(fixture, &client, &claim).await?;
        let api_key = created["api_key"]
            .as_str()
            .ok_or("bootstrap key missing")?
            .to_owned();
        super::save_and_verify_recovery_bundle(fixture, &client, &api_key, &created).await?;
        Ok(Self {
            fixture,
            client,
            api_key,
            administrator_id,
            mesh_id: created["mesh_id"]
                .as_str()
                .ok_or("mesh identity missing")?
                .to_owned(),
        })
    }

    fn authorization(&self) -> String {
        format!("Bearer {}", self.api_key)
    }

    async fn lifecycle_evidence(&self) -> String {
        let evidence =
            async {
                self.call("PUT", "/api/latest/admin/metrics/exporter", Some(&json!({
                "operation_id":"01900000-0000-7000-8000-000000000115", "expected_sequence":0,
                "policy":{"enabled":true,"allowed_principals":[self.administrator_id]}
            })), "200 OK").await?;
                let response = request_with_headers(
                    self.fixture.address,
                    &self.client,
                    "GET",
                    "/api/latest/metrics",
                    None,
                    &[("Authorization", &self.authorization())],
                )
                .await?;
                require_status(&response, "200 OK", "failure lifecycle observations")?;
                Ok::<_, Box<dyn Error>>(
                    response_body(&response)?
                        .lines()
                        .filter(|line| {
                            (line.contains("federation_sessions") || line.contains("backup_"))
                                && line.contains("passes")
                                && !line.starts_with('#')
                        })
                        .collect::<Vec<_>>()
                        .join("; "),
                )
            }
            .await;
        match evidence {
            Ok(value) => value,
            Err(error) => format!("unavailable: {error}"),
        }
    }

    async fn call(
        &self,
        method: &str,
        route: &str,
        body: Option<&Value>,
        expected: &str,
    ) -> Result<Value, Box<dyn Error>> {
        let response = self.request(method, route, body).await?;
        require_status(&response, expected, route)?;
        Ok(serde_json::from_str(response_body(&response)?)?)
    }

    async fn request(
        &self,
        method: &str,
        route: &str,
        body: Option<&Value>,
    ) -> Result<String, Box<dyn Error>> {
        let body = body.map(serde_json::to_vec).transpose()?;
        let transfer = tokio::time::timeout(
            WAIT_LIMIT,
            request_with_headers(
                self.fixture.address,
                &self.client,
                method,
                route,
                body.as_deref(),
                &[("Authorization", &self.authorization())],
            ),
        )
        .await;
        let response = if let Ok(response) = transfer {
            response?
        } else {
            let evidence = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                super::diagnostics::failure_evidence(
                    self.fixture.address,
                    &self.client,
                    &self.authorization(),
                ),
            )
            .await
            .unwrap_or_else(|_| "diagnostic request timed out".to_owned());
            return Err(format!("{method} {route}: request deadline elapsed; {evidence}").into());
        };
        Ok(response)
    }

    async fn change_grant(&self, operation: &str, change: Value) -> Result<(), Box<dyn Error>> {
        let grant = change["grant_id"].as_str().ok_or("grant identity")?;
        let deadline = super::Instant::now() + WAIT_LIMIT;
        loop {
            let observed = self
                .request("GET", &format!("{GRANTS}?grant_id={grant}"), None)
                .await?;
            if !observed.starts_with("HTTP/1.1 409 ") {
                require_status(&observed, "200 OK", "observe grant revision")?;
                let observed: Value = serde_json::from_str(response_body(&observed)?)?;
                let body = json!({"operation_id":operation,
                    "expected_metadata_revision":observed["metadata_revision"],"change":change});
                let response = self.request("POST", GRANTS, Some(&body)).await?;
                if !response.starts_with("HTTP/1.1 409 ") {
                    require_status(&response, "200 OK", "change grant")?;
                    let receipt: Value = serde_json::from_str(response_body(&response)?)?;
                    assert_eq!(receipt["operation_id"], operation);
                    return Ok(());
                }
            }
            // Background metadata work can win the CAS. Retry a rejected attempt
            // against a fresh revision; never turn an unknown IO result into a retry.
            if super::Instant::now() >= deadline {
                return Err("grant revision never stabilised".into());
            }
            super::sleep(super::RETRY_INTERVAL).await;
        }
    }
}

async fn drain_gateway_storage(provider: &Appliance<'_>) -> Result<(), Box<dyn Error>> {
    super::wait_for_storage_folder_visibility(
        provider.fixture,
        &provider.client,
        &provider.api_key,
    )
    .await?;
    let page = provider
        .call(
            "GET",
            "/api/latest/admin/storage-folders?limit=1",
            None,
            "200 OK",
        )
        .await?;
    let folder = page["folders"]
        .as_array()
        .and_then(|folders| folders.first())
        .ok_or("gateway folder missing")?;
    let drained = provider.call("POST", "/api/latest/admin/storage-drains", Some(&json!({
        "operation_id":"01900000-0000-7000-8000-000000000114",
        "scope":{"kind":"target","target_id":folder["target_id"],"generation":folder["generation"]},
        "allow_temporary_degraded":true,"cleanup_requested":false
    })), "202 Accepted").await?;
    assert_eq!(drained["drain"]["scope"]["target_id"], folder["target_id"]);
    // Admission itself fences new allocations; this test never physically detaches a folder.
    Ok(())
}

async fn pair(
    provider: &Appliance<'_>,
    consumer: &Appliance<'_>,
) -> Result<String, Box<dyn Error>> {
    let invitation = provider.call("POST", "/api/latest/admin/federation/invitations", Some(&json!({
        "operation_id":"01900000-0000-7000-8000-000000000110", "pairing_endpoint":format!("https://{}", provider.fixture.address), "valid_for_seconds":900
    })), "201 Created").await?;
    let approval = consumer.call("POST", "/api/latest/admin/federation/connections", Some(&json!({
        "operation_id":"01900000-0000-7000-8000-000000000111", "connection_code":invitation["connection_code"], "local_endpoint":format!("https://{}", consumer.fixture.address)
    })), "201 Created").await?;
    Ok(approval["relationship_id"]
        .as_str()
        .ok_or("relationship missing")?
        .to_owned())
}

async fn offer(provider: &Appliance<'_>, relationship: &str) -> Result<(), Box<dyn Error>> {
    provider.change_grant("01900000-0000-7000-8000-000000000112", json!({
        "kind":"issue","grant_id":GRANT,"relationship_id":relationship,
        "policy":{"maximum_bytes":"268435456","counts_towards_protection":true,"serves_reads":false,"allow_downstream_delegation":false}
    })).await?;
    Ok(())
}

async fn remote_only_destination(
    consumer: &Appliance<'_>,
    remote: &str,
) -> Result<(), Box<dyn Error>> {
    super::wait_for_storage_folder_visibility(
        consumer.fixture,
        &consumer.client,
        &consumer.api_key,
    )
    .await?;
    let page = consumer
        .call("GET", &format!("{DESTINATIONS}?limit=100"), None, "200 OK")
        .await?;
    assert_eq!(page["next_page_url"], Value::Null);
    let destinations = page["destinations"]
        .as_array()
        .ok_or("destinations missing")?;
    assert!(
        !destinations.is_empty(),
        "automatic local destination must exist before disabling it"
    );
    for (index, destination) in destinations.iter().enumerate() {
        consumer.call("PUT", DESTINATIONS, Some(&json!({"operation_id":format!("01900000-0000-7000-8000-0000000002{index:02x}"),
            "destination_id":destination["destination_id"],"expected_revision":destination["revision"],"name":destination["name"],
            "provider":destination["provider"],"provider_generation":destination["provider_generation"],"enabled":false
        })), "200 OK").await?;
    }
    consumer.call("PUT", DESTINATIONS, Some(&json!({"operation_id":"01900000-0000-7000-8000-000000000113",
        "destination_id":DESTINATION,"expected_revision":0,"name":"Remote provider swarm",
        "provider":{"kind":"federated_mesh","remote_mesh_id":remote},"provider_generation":"1","enabled":true
    })), "200 OK").await?;
    Ok(())
}

async fn verify_permission_succession(
    provider: &Appliance<'_>,
    consumer: &Appliance<'_>,
    backup: &str,
    original: &(Vec<u8>, String),
) -> Result<(), Box<dyn Error>> {
    let successor = "01900000-0000-7000-8000-000000000116";
    provider
        .change_grant(
            "01900000-0000-7000-8000-000000000117",
            json!({"kind":"replace","predecessor_grant_id":GRANT,"grant_id":successor,
                    "policy":{"maximum_bytes":"134217728","counts_towards_protection":true,
                        "serves_reads":false,"allow_downstream_delegation":false},
                    "restricts_authority":true,"reason":"Reduce the offered quota"}),
        )
        .await?;
    let retained = super::backup_history::encrypted_export(
        consumer.fixture.address,
        &consumer.client,
        &consumer.authorization(),
        backup,
    )
    .await?;
    assert_eq!(
        &retained, original,
        "renewed permission must find the original allocation without moving its bytes"
    );
    provider
        .change_grant(
            "01900000-0000-7000-8000-000000000118",
            json!({
                "kind":"revoke","grant_id":successor,"reason":"Withdraw remote storage access"
            }),
        )
        .await?;
    // The caller still has local manager rights. The provider has withdrawn its
    // independent permission: a retained route/old receipt cannot authorise reads.
    let denied = consumer
        .call(
            "GET",
            &format!("/api/latest/admin/backups/{backup}/restore-readiness"),
            None,
            "503 Service Unavailable",
        )
        .await?;
    assert_eq!(denied["code"], "busy");
    Ok(())
}

fn verify_exact_remote_copy(
    consumer: &ProcessFixture,
    gateway: &ProcessFixture,
    storage: &ProcessFixture,
    backup: &str,
) -> Result<(), Box<dyn Error>> {
    let repository = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &consumer.state_path.join("root-authority.sqlite3"),
        UnixMicros::new(1),
    )?);
    let backup = BackupId::parse(&backup.replace('-', ""))?;
    let destination = BackupDestinationId::parse(&DESTINATION.replace('-', ""))?;
    let route = repository
        .federated_backup_route(backup, destination)?
        .ok_or("remote route missing")?;
    let intent = repository
        .backup_publication_intent(backup, destination)?
        .ok_or("upload intent missing")?;
    assert_eq!(intent.binding.object, route.binding.object);
    let storage_identity =
        super::LocalNodeIdentity::open(&storage.identity_path, super::CERTIFICATE_NAME)?;
    let gateway_identity =
        super::LocalNodeIdentity::open(&gateway.identity_path, super::CERTIFICATE_NAME)?;
    assert_eq!(
        route.binding.scope.provider_node_id,
        InitialBootstrapMaterial::node_id(storage_identity.public_key_fingerprint())?
    );
    assert_ne!(
        route.binding.scope.provider_node_id,
        InitialBootstrapMaterial::node_id(gateway_identity.public_key_fingerprint())?
    );
    let copies = repository.backup_copies(backup, None, PageLimit::new(10)?)?;
    assert_eq!(
        copies.items.len(),
        1,
        "proof must not pass using a local duplicate"
    );
    let copy = copies.items.first().ok_or("copy missing")?;
    assert!(
        intent.revision < copy.revision,
        "intent must precede provider-copy admission/verification"
    );
    assert_eq!(copy.destination_id, destination);
    assert!(copy.verified_at.is_some());
    assert!(copy.byte_length > 0);
    Ok(())
}
