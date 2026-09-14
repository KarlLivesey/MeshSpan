// SPDX-License-Identifier: GPL-2.0-only

//! A second user redeems a one-use invitation through native HTTPS and survives restart.

use super::*;

const REDEEM_PATH: &str = "/api/latest/user-enrollments/api-keys";
const BOB_LABEL: &str = "Bob's first key";

#[tokio::test]
async fn native_user_enrollment_replays_and_signs_in_independently_after_restart()
-> Result<(), Box<dyn Error>> {
    let fixture = ProcessFixture::new()?;
    let mut processes = ProcessCleanup(vec![fixture.start()?]);
    let proof = tokio::time::timeout(Duration::from_secs(120), async {
        let claim = wait_for_claim(&fixture.claim_path).await?;
        let client = wait_for_client(&fixture.identity_path).await?;
        wait_for_status(fixture.address, &client, "claim_required").await?;
        let administrator = bootstrap_administrator_id(&claim, &fixture.identity_path)?;
        let created = create_process_mesh(&fixture, &client, &claim).await?;
        let key = created["api_key"]
            .as_str()
            .ok_or("missing initial API key")?;
        save_and_verify_recovery_bundle(&fixture, &client, key, &created).await?;
        let bob = create_bob(fixture.address, &client, key).await?;
        assert_ne!(bob.principal_id, administrator);
        let administrator = recent_administrator(fixture.address, &client, key).await?;
        let invitation = issue_invitation(fixture.address, &client, &administrator, &bob).await?;
        let redemption = serde_json::json!({
            "operation_id": "00000000-0000-4000-8000-000000000604",
            "token": invitation["token"],
            "label": BOB_LABEL,
            "scopes": ["https_session", "headless_api"],
            "expires_at_epoch_micros": null
        });
        let receipt = redeem_exactly(fixture.address, &client, &redemption).await?;
        assert_redemption_retries(fixture.address, &client, &redemption, &receipt).await?;
        assert_independent_sign_in(fixture.address, &client, &bob, &receipt, 606).await?;

        stop_processes(&mut processes.0);
        processes.0.push(fixture.start()?);
        wait_for_status(fixture.address, &client, "configured").await?;
        assert_independent_sign_in(fixture.address, &client, &bob, &receipt, 607).await?;
        let recovered = redeem_exactly(fixture.address, &client, &redemption).await?;
        // Secret-bearing values must never appear in assertion diagnostics.
        assert!(
            recovered == receipt,
            "restart changed the exact enrollment receipt"
        );
        Ok::<_, Box<dyn Error>>(())
    })
    .await
    .map_err(|_| -> Box<dyn Error> { "native user enrollment exceeded its 120s deadline".into() })
    .and_then(std::convert::identity);
    drop(processes);
    retain_failure_state(proof, [fixture.temporary])
}

struct Recipient {
    principal_id: String,
    revision: u64,
}

async fn create_bob(
    address: SocketAddr,
    client: &ClientConfig,
    administrator_key: &str,
) -> Result<Recipient, Box<dyn Error>> {
    let body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000600",
        "display_name": "Bob"
    }))?;
    let authorization = format!("Bearer {administrator_key}");
    let response = request_with_headers(
        address,
        client,
        "POST",
        "/api/latest/admin/users",
        Some(&body),
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    require_redacted_status(&response, "201 Created", "create Bob")?;
    let value: serde_json::Value = serde_json::from_str(response_body(&response)?)?;
    assert_eq!(value["principal"]["display_name"], "Bob");
    Ok(Recipient {
        principal_id: principal_id(&response)?,
        revision: value["principal"]["revision"]
            .as_u64()
            .ok_or("missing Bob revision")?,
    })
}

async fn recent_administrator(
    address: SocketAddr,
    client: &ClientConfig,
    key: &str,
) -> Result<BrowserSessionHeaders, Box<dyn Error>> {
    let session = sign_in(address, client, key, 601).await?;
    let secret = enrol_totp(address, client, key, &session).await?;
    // Registration consumes the current code. Observe a new window rather than reuse it.
    let consumed = current_totp_code(&secret)?;
    let code = tokio::time::timeout(Duration::from_secs(35), async {
        loop {
            let code = current_totp_code(&secret)?;
            if code != consumed {
                return Ok::<_, Box<dyn Error>>(code);
            }
            sleep(Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| "TOTP did not advance to an unused step")??;
    let body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000602",
        "additional_factor": {"method": "totp", "code": code}
    }))?;
    let response = request_with_headers(
        address,
        client,
        "POST",
        "/api/latest/sessions/current/step-ups",
        Some(&body),
        &session.mutation_headers(),
    )
    .await?;
    require_redacted_status(&response, "201 Created", "step up administrator")?;
    let value: serde_json::Value = serde_json::from_str(response_body(&response)?)?;
    assert_eq!(value["assurance"], "recent_step_up");
    browser_session_headers(&response)
}

async fn issue_invitation(
    address: SocketAddr,
    client: &ClientConfig,
    administrator: &BrowserSessionHeaders,
    bob: &Recipient,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let now = i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_micros())?;
    let expires = now
        .checked_add(300_000_000)
        .ok_or("invitation expiry overflow")?;
    let body = serde_json::to_vec(&serde_json::json!({
        "operation_id": "00000000-0000-4000-8000-000000000603",
        "expected_principal_revision": bob.revision,
        "expires_at_epoch_micros": expires
    }))?;
    let target = format!(
        "/api/latest/admin/identities/users/{}/enrollments",
        bob.principal_id
    );
    let denied = request(address, client, "POST", &target, Some(&body)).await?;
    require_redacted_status(
        &denied,
        "403 Forbidden",
        "deny anonymous invitation issuance",
    )?;
    let response = request_with_headers(
        address,
        client,
        "POST",
        &target,
        Some(&body),
        &administrator.mutation_headers(),
    )
    .await?;
    require_redacted_status(&response, "200 OK", "issue Bob invitation")?;
    let invitation: serde_json::Value = serde_json::from_str(response_body(&response)?)?;
    assert_eq!(invitation["principal_id"], bob.principal_id);
    assert_eq!(invitation["expires_at_epoch_micros"], expires);
    assert_eq!(
        invitation["operation_id"],
        "00000000-0000-4000-8000-000000000603"
    );
    assert!(
        invitation["committed_revision"]
            .as_u64()
            .is_some_and(|revision| revision > 0)
    );
    Ok(invitation)
}

async fn redeem_exactly(
    address: SocketAddr,
    client: &ClientConfig,
    redemption: &serde_json::Value,
) -> Result<serde_json::Value, Box<dyn Error>> {
    let body = serde_json::to_vec(redemption)?;
    // Deliberately omit both manager credentials and a browser session.
    let response = request(address, client, "POST", REDEEM_PATH, Some(&body)).await?;
    require_redacted_status(&response, "200 OK", "redeem Bob invitation")?;
    let receipt: serde_json::Value = serde_json::from_str(response_body(&response)?)?;
    assert_eq!(receipt["operation_id"], redemption["operation_id"]);
    assert_eq!(
        receipt["scopes"],
        serde_json::json!(["https_session", "headless_api"])
    );
    assert!(
        receipt["secret"]
            .as_str()
            .is_some_and(|secret| secret.starts_with("meshspan-key-v1."))
    );
    assert!(receipt["expires_at_epoch_micros"].is_null());
    Ok(receipt)
}

async fn assert_redemption_retries(
    address: SocketAddr,
    client: &ClientConfig,
    redemption: &serde_json::Value,
    original: &serde_json::Value,
) -> Result<(), Box<dyn Error>> {
    let recovered = redeem_exactly(address, client, redemption).await?;
    assert!(
        recovered == *original,
        "exact retry changed the enrollment receipt"
    );
    let mut changed = redemption.clone();
    changed["label"] = serde_json::json!("Changed request");
    let body = serde_json::to_vec(&changed)?;
    let response = request(address, client, "POST", REDEEM_PATH, Some(&body)).await?;
    require_redacted_status(
        &response,
        "409 Conflict",
        "reject changed redemption digest",
    )?;
    let mut second = redemption.clone();
    second["operation_id"] = serde_json::json!("00000000-0000-4000-8000-000000000605");
    let body = serde_json::to_vec(&second)?;
    let response = request(address, client, "POST", REDEEM_PATH, Some(&body)).await?;
    require_redacted_status(
        &response,
        "403 Forbidden",
        "reject second redemption operation",
    )
}

async fn assert_independent_sign_in(
    address: SocketAddr,
    client: &ClientConfig,
    bob: &Recipient,
    receipt: &serde_json::Value,
    operation: u64,
) -> Result<(), Box<dyn Error>> {
    let key = receipt["secret"]
        .as_str()
        .ok_or("enrollment omitted Bob key")?;
    let session = sign_in(address, client, key, operation).await?;
    let response = request_with_headers(
        address,
        client,
        "GET",
        "/api/latest/sessions/current",
        None,
        &[("Cookie", session.cookie.as_str())],
    )
    .await?;
    require_redacted_status(&response, "200 OK", "read Bob session")?;
    let current: serde_json::Value = serde_json::from_str(response_body(&response)?)?;
    assert_eq!(current["principal_id"], bob.principal_id);
    assert_eq!(current["administration_available"], false);
    let denied = request_with_headers(
        address,
        client,
        "GET",
        "/api/latest/admin/users?limit=100",
        None,
        &[("Cookie", session.cookie.as_str())],
    )
    .await?;
    require_redacted_status(&denied, "403 Forbidden", "deny Bob administration")?;
    assert_own_method_inventory(address, client, key, receipt).await
}

async fn sign_in(
    address: SocketAddr,
    client: &ClientConfig,
    key: &str,
    operation: u64,
) -> Result<BrowserSessionHeaders, Box<dyn Error>> {
    let body = serde_json::to_vec(&serde_json::json!({
        "operation_id": format!("00000000-0000-4000-8000-{operation:012}"),
        "authentication": {"method": "api_key", "secret": key},
        "client_label": "Native enrollment acceptance",
        "remember": false
    }))?;
    let response = request(address, client, "POST", "/api/latest/sessions", Some(&body)).await?;
    require_redacted_status(&response, "201 Created", "sign in with ordinary API key")?;
    browser_session_headers(&response)
}

async fn assert_own_method_inventory(
    address: SocketAddr,
    client: &ClientConfig,
    key: &str,
    receipt: &serde_json::Value,
) -> Result<(), Box<dyn Error>> {
    let authorization = format!("Bearer {key}");
    let response = request_with_headers(
        address,
        client,
        "GET",
        "/api/latest/users/current/authentication-methods?limit=100",
        None,
        &[("Authorization", authorization.as_str())],
    )
    .await?;
    require_redacted_status(&response, "200 OK", "list Bob credentials")?;
    let value: serde_json::Value = serde_json::from_str(response_body(&response)?)?;
    let methods = value["methods"]
        .as_array()
        .ok_or("missing credential inventory")?;
    assert_eq!(
        methods.len(),
        1,
        "redemption retries must not create extra credentials"
    );
    let method = methods
        .first()
        .ok_or("Bob credential inventory was empty")?;
    assert_eq!(method["method_id"], receipt["method_id"]);
    assert_eq!(method["label"], BOB_LABEL);
    assert_eq!(method["state"], "active");
    assert!(value["next_page_url"].is_null());
    Ok(())
}

fn require_redacted_status(
    response: &str,
    expected: &str,
    operation: &str,
) -> Result<(), Box<dyn Error>> {
    if response.starts_with(&format!("HTTP/1.1 {expected}\r\n")) {
        Ok(())
    } else {
        // Even an unexpected success response may carry a credential: never dump the body.
        Err(format!("{operation}: expected HTTP {expected}").into())
    }
}
