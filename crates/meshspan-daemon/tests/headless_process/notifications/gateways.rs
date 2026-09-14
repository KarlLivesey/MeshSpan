// SPDX-License-Identifier: GPL-2.0-only

//! New gateways use existing encrypted channel settings after the configuring node is killed.

use super::{Error, NotificationDeliveryState, ProcessFixture, Receiver, WorkId};

#[tokio::test]
async fn notification_credentials_reach_joined_gateways_and_deliver_after_source_loss()
-> Result<(), Box<dyn Error>> {
    let root = ProcessFixture::new()?;
    let second = ProcessFixture::new()?;
    let third = ProcessFixture::new()?;
    let mut receiver = Receiver::start().await?;
    let trust = root.temporary.path().join("notification-trust.pem");
    std::fs::write(&trust, &receiver.anchor)?;
    let mut processes = vec![root.command().env("SSL_CERT_FILE", &trust).spawn()?];
    let proof = async {
        let claim = super::super::wait_for_claim(&root.claim_path).await?;
        let client = super::super::wait_for_client(&root.identity_path).await?;
        super::super::wait_for_status(root.address, &client, "claim_required").await?;
        let created = super::super::create_process_mesh(&root, &client, &claim).await?;
        let key = created["api_key"].as_str().ok_or("missing bootstrap key")?;
        super::super::save_and_verify_recovery_bundle(&root, &client, key, &created).await?;
        // Configuration is encrypted before either future delivery gateway exists.
        super::configure(
            &root,
            &client,
            key,
            &super::configuration(&receiver.endpoint),
        )
        .await?;
        let join = super::super::issue_join_code(&root, &client, key).await?;
        for peer in [&second, &third] {
            processes.push(
                peer.command()
                    .env("SSL_CERT_FILE", &trust)
                    .arg("--join-code")
                    .arg(&join)
                    .spawn()?,
            );
            let peer_client = super::super::wait_for_client(&peer.identity_path).await?;
            super::super::wait_for_status(peer.address, &peer_client, "configured").await?;
        }
        super::super::wait_for_three_voters([&root, &second, &third], &root.identity_path).await?;
        super::super::stop_processes(&mut processes[..1]);
        let client = super::super::wait_for_client(&second.identity_path).await?;
        super::super::wait_for_user_creation(
            second.address,
            &client,
            key,
            [&second, &third],
            &root.identity_path,
        )
        .await?;
        super::queue_certificate(&second, &client, key, &receiver.endpoint).await?;
        let first = receiver.receive().await?;
        let second_event = receiver.receive().await?;
        assert_eq!(
            first, second_event,
            "replacement delivery retry changed its event"
        );
        assert_eq!(first["kind"], "certificate_order_queued");
        let delivery = WorkId::from_bytes(super::parse(
            first["delivery_id"].as_str().ok_or("missing delivery ID")?,
        )?)?;
        super::await_delivery(&second, delivery, NotificationDeliveryState::Accepted, 2).await?;
        assert!(
            processes[0].try_wait()?.is_some(),
            "original gateway restarted"
        );
        Ok::<_, Box<dyn Error>>(())
    }
    .await;
    super::super::stop_processes(&mut processes);
    let stopped = receiver.stop().await;
    super::super::retain_failure_state(proof, [root.temporary, second.temporary, third.temporary])?;
    stopped
}
