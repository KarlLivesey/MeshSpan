// SPDX-License-Identifier: GPL-2.0-only

//! Real-router provider offers use durable consensus, not seeded grants or a mock controller.

use super::{RunningAuthority, TestResult, authority, command_context, post_route, router};
use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use meshspan_domain::FederationRelationshipId;
use serde_json::{Value, json};
use tower::ServiceExt;

const ROUTE: &str = "/api/latest/admin/federation/storage-grants";
const FIRST: &str = "01900000-0000-7000-8000-000000000002";
const SECOND: &str = "01900000-0000-7000-8000-000000000003";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn federation_storage_grant_http_lifecycle_retains_exact_receipts() -> TestResult<()> {
    let fixture = RunningAuthority::start().await?;
    let result = lifecycle(&fixture).await;
    fixture.shutdown().await?;
    result
}

async fn lifecycle(fixture: &RunningAuthority) -> TestResult<()> {
    let relationship = paired_relationship(fixture)?;
    let routes = router(fixture)?;
    let (status, absent) = lookup(&routes, fixture, FIRST).await?;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(absent, json!({"metadata_revision":3,"grant":null}));
    let issue = json!({"operation_id":"01900000-0000-7000-8000-000000000004", "expected_metadata_revision":3,
        "change":{"kind":"issue", "grant_id":FIRST, "relationship_id":relationship,
            "policy":{"maximum_bytes":"1024", "counts_towards_protection":true,"serves_reads":false,"allow_downstream_delegation":false}}});
    let (status, receipt) = mutate(&routes, fixture, &issue).await?;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_eq!(
        receipt,
        json!({"operation_id":issue["operation_id"],"grant_id":FIRST,"committed_revision":4})
    );
    assert_eq!(
        mutate(&router(fixture)?, fixture, &issue).await?,
        (StatusCode::OK, receipt.clone())
    );
    let (_, current) = lookup(&routes, fixture, FIRST).await?;
    assert_eq!(current["grant"]["state"], "active");
    assert_eq!(current["grant"]["policy"]["maximum_bytes"], "1024");
    let start = current["grant"]["valid_from_epoch_micros"]
        .as_i64()
        .ok_or("start")?;
    let end = current["grant"]["valid_until_epoch_micros"]
        .as_i64()
        .ok_or("end")?;
    assert_eq!(end - start, 30 * 24 * 60 * 60 * 1_000_000_i64);
    let mut changed = issue.clone();
    changed["change"]["policy"]["maximum_bytes"] = json!("512");
    assert_eq!(
        mutate(&routes, fixture, &changed).await?.0,
        StatusCode::CONFLICT
    );
    changed["operation_id"] = json!("01900000-0000-7000-8000-000000000005");
    assert_eq!(
        mutate(&routes, fixture, &changed).await?.0,
        StatusCode::CONFLICT
    );
    replace_and_revoke(&routes, fixture).await?;
    assert_eq!(
        mutate(&router(fixture)?, fixture, &issue).await?,
        (StatusCode::OK, receipt)
    );
    Ok(())
}

async fn replace_and_revoke(routes: &Router, fixture: &RunningAuthority) -> TestResult<()> {
    let replacement = json!({"operation_id":"01900000-0000-7000-8000-000000000006", "expected_metadata_revision":4,
        "change":{"kind":"replace", "predecessor_grant_id":FIRST, "grant_id":SECOND,
            "policy":{"maximum_bytes":"512", "counts_towards_protection":true,"serves_reads":false,"allow_downstream_delegation":false},
            "valid_for_seconds":null,"restricts_authority":true,"reason":"Reduce offered capacity"}});
    let (status, receipt) = mutate(routes, fixture, &replacement).await?;
    assert_eq!(status, StatusCode::OK, "{receipt}");
    assert_eq!(receipt["committed_revision"], 5);
    let (_, old) = lookup(routes, fixture, FIRST).await?;
    assert_eq!(old["grant"]["state"], "superseded");
    assert_eq!(old["grant"]["successor_grant_id"], SECOND);
    let (_, current) = lookup(routes, fixture, SECOND).await?;
    assert_eq!(current["grant"]["policy"]["maximum_bytes"], "512");
    assert_eq!(current["grant"]["valid_until_epoch_micros"], Value::Null);
    let revoke = json!({"operation_id":"01900000-0000-7000-8000-000000000007", "expected_metadata_revision":5,
        "change":{"kind":"revoke", "grant_id":SECOND,"reason":"Withdraw offer"}});
    let (status, revoked) = mutate(routes, fixture, &revoke).await?;
    assert_eq!(status, StatusCode::OK, "{revoked}");
    assert_eq!(revoked["committed_revision"], 6);
    let reopened = router(fixture)?;
    assert_eq!(
        mutate(&reopened, fixture, &revoke).await?,
        (StatusCode::OK, revoked)
    );
    assert_eq!(
        mutate(&reopened, fixture, &replacement).await?,
        (StatusCode::OK, receipt)
    );
    assert_eq!(
        lookup(&reopened, fixture, SECOND).await?.1["grant"]["state"],
        "revoked"
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn federation_storage_grant_http_rejects_before_body_and_invalid_queries() -> TestResult<()> {
    let fixture = RunningAuthority::start().await?;
    let result = rejection(&fixture).await;
    fixture.shutdown().await?;
    result
}

async fn rejection(fixture: &RunningAuthority) -> TestResult<()> {
    let routes = router(fixture)?;
    let denied = routes
        .clone()
        .oneshot(Request::post(ROUTE).body(Body::from(vec![0; 8192]))?)
        .await?;
    assert_eq!(denied.status(), StatusCode::UNAUTHORIZED);
    for suffix in [
        "bad",
        "",
        "01900000-0000-7000-8000-000000000002&extra=1",
        "01900000-0000-7000-8000-000000000002&grant_id=01900000-0000-7000-8000-000000000003",
    ] {
        assert_eq!(
            lookup(&routes, fixture, suffix).await?.0,
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(authority(fixture)?.reader().current_revision()?.get(), 1);
    Ok(())
}

fn paired_relationship(fixture: &RunningAuthority) -> TestResult<String> {
    let relationship = FederationRelationshipId::from_bytes(meshspan_domain::uuid_v8([30; 16]))?;
    let authority = authority(fixture)?;
    tokio::task::block_in_place(|| -> TestResult<()> {
        for (index, (command, _, _)) in
            super::super::federation_relationship::lifecycle(relationship)?
                .into_iter()
                .take(2)
                .enumerate()
        {
            authority.commit_authoritative(
                command_context(
                    fixture.administrator_id,
                    100 + u8::try_from(index)?,
                    110 + u8::try_from(index)?,
                    100,
                    None,
                )?,
                &command,
            )?;
        }
        Ok(())
    })?;
    Ok(crate::create_mesh_setup::format_uuid(
        relationship.as_bytes(),
    ))
}

async fn lookup(
    routes: &Router,
    fixture: &RunningAuthority,
    id: &str,
) -> TestResult<(StatusCode, Value)> {
    let response = routes
        .clone()
        .oneshot(
            Request::get(format!("{ROUTE}?grant_id={id}"))
                .header(
                    "authorization",
                    format!("Bearer {}", fixture.api_key.expose_encoded().as_str()),
                )
                .body(Body::empty())?,
        )
        .await?;
    let status = response.status();
    Ok((
        status,
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?,
    ))
}

async fn mutate(
    routes: &Router,
    fixture: &RunningAuthority,
    body: &Value,
) -> TestResult<(StatusCode, Value)> {
    let response = post_route(routes, fixture, body, ROUTE).await?;
    let status = response.status();
    Ok((
        status,
        serde_json::from_slice(&to_bytes(response.into_body(), 4096).await?)?,
    ))
}
