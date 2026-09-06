// SPDX-License-Identifier: GPL-2.0-only

//! Process restart after atomic retirement must preserve the exact retry deadline and leaf key.

use meshspan_metadata::{
    CertificateOrderRecord, CertificateOrderState, PUBLIC_CERTIFICATE_REQUEST_KEY_SECRET_KIND,
    PageLimit,
};

use super::*;

#[derive(Debug, Eq, PartialEq)]
struct QueuedRetry {
    order: CertificateOrderRecord,
    encrypted_key_digest: [u8; 32],
}

pub(super) async fn await_reissuance(
    root: &ProcessFixture,
    ca: &authority::TestAuthority,
    key: &str,
    process: &mut Child,
) -> Result<(), Box<dyn Error>> {
    let repository = open_repository(root)?;
    let queued = wait_for_queued_retirement(&repository).await?;
    drop(repository);
    ca.assert_rejected_challenge_removed().await?;
    assert!(
        process.try_wait()?.is_none(),
        "rejection terminated the daemon"
    );
    process.kill()?;
    process.wait()?;
    *process = root
        .command()
        .env("SSL_CERT_FILE", root.temporary.path().join("test-ca.pem"))
        .spawn()?;
    let bootstrap = wait_for_client(&root.identity_path).await?;
    wait_for_status(root.address, &bootstrap, "configured").await?;
    let repository = open_repository(root)?;
    assert_eq!(read_queued_retirement(&repository)?.as_ref(), Some(&queued));
    let issued = client_config(&ca.anchor_der)?;
    wait_for_active_until(
        root.address,
        &issued,
        key,
        1,
        Instant::now() + Duration::from_mins(7),
    )
    .await?;
    assert!(
        process.try_wait()?.is_none(),
        "reissuance terminated the daemon"
    );
    assert_eq!(
        leaf_key_digest(&repository, queued.order.order_id)?,
        queued.encrypted_key_digest
    );
    Ok(())
}

async fn wait_for_queued_retirement(
    repository: &AuthoritativeRepository,
) -> Result<QueuedRetry, Box<dyn Error>> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        if let Some(queued) = read_queued_retirement(repository)? {
            return Ok(queued);
        }
        if Instant::now() >= deadline {
            return Err("rejected order did not atomically retire into its retry queue".into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

fn read_queued_retirement(
    repository: &AuthoritativeRepository,
) -> Result<Option<QueuedRetry>, Box<dyn Error>> {
    // A future read instant includes the delayed retry without admitting or mutating it.
    let page =
        repository.due_certificate_orders(UnixMicros::new(i64::MAX), None, PageLimit::new(2)?)?;
    assert!(
        page.items.len() <= 1 && page.next.is_none(),
        "fixture has unexpected additional orders"
    );
    let Some(order) = page.items.first().copied() else {
        return Ok(None);
    };
    if order.state != CertificateOrderState::Queued || order.attempt_count != 1 {
        return Ok(None);
    }
    assert!(order.claim.is_none());
    assert!(
        repository
            .certificate_order_checkpoint(order.order_id)?
            .is_none(),
        "retry kept the rejected checkpoint"
    );
    Ok(Some(QueuedRetry {
        encrypted_key_digest: leaf_key_digest(repository, order.order_id)?,
        order,
    }))
}

fn leaf_key_digest(
    repository: &AuthoritativeRepository,
    order_id: meshspan_domain::CertificateOrderId,
) -> Result<[u8; 32], Box<dyn Error>> {
    Ok(repository
        .secret_generation(SecretContext::new(
            PUBLIC_CERTIFICATE_REQUEST_KEY_SECRET_KIND,
            order_id.as_bytes(),
            1,
        )?)?
        .ok_or("protected leaf key missing")?
        .secret
        .parts()
        .digest)
}

fn open_repository(root: &ProcessFixture) -> Result<AuthoritativeRepository, Box<dyn Error>> {
    Ok(AuthoritativeRepository::new(
        PartitionDatabase::open_existing(
            &root.state_path.join("root-authority.sqlite3"),
            UnixMicros::new(1),
        )?,
    ))
}
