// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use meshspan_metadata::{AuthoritativeCommand, CommandContext, CreateUser, RecordName};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn shutdown_drains_private_admission_and_preserves_lost_response_receipt()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let occupied = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let config = lifecycle_config(directory.path(), &occupied.local_addr()?.to_string())?;
    let now = current_time()?;
    let mut node = initialise_daemon_node(&config, now).await?;
    let private = start_private_authority(&mut node, &config, now).await?;
    let generation = Arc::clone(&private.network_starter.generation);
    let (restart, requests) = tokio::sync::mpsc::unbounded_channel();
    let services = compose_appliance_services(&mut node, &private, &config, restart, now)?;
    let administrator = configure_lifecycle_mesh(&node, services.router.clone()).await?;
    let command = AuthoritativeCommand::CreateUser(CreateUser {
        principal_id: PrincipalId::from_bytes([117; 16])?,
        name: RecordName::new("Private durable user")?,
    });
    let context = CommandContext {
        operation_id: OperationId::from_bytes([115; 16])?,
        actor_principal_id: administrator,
        audit_event_id: AuditEventId::from_bytes([116; 16])?,
        occurred_at: current_time()?,
        expected_revision: None,
    };
    let (started, release) = admit_blocked_command(&node, &private, context, &command).await?;
    tokio::time::timeout(Duration::from_secs(5), started).await??;
    let shutdown = std::future::pending();
    tokio::pin!(shutdown);
    let cycle = Box::pin(serve_daemon_cycle(
        &config, services, private, requests, shutdown,
    ));
    tokio::pin!(cycle);
    tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            result = &mut cycle => { drop(result); Err("cycle returned with admitted IO blocked") },
            () = generation.stopped() => Ok(()),
        }
    })
    .await??;
    let returned =
        std::future::poll_fn(|cx| std::task::Poll::Ready(cycle.as_mut().poll(cx).is_ready())).await;
    // Releasing or dropping this sender always lets the owned blocking worker finish.
    release.send(())?;
    assert!(!returned, "shutdown abandoned admitted private IO");
    let result = tokio::time::timeout(Duration::from_secs(10), cycle).await?;
    assert!(matches!(result, Err(DaemonProcessError::Http01(_))));
    drop(generation);
    drop(node);
    verify_private_receipt_replay(&config, context, command).await
}

type AdmissionSignals = (
    tokio::sync::oneshot::Receiver<()>,
    std::sync::mpsc::Sender<()>,
);

async fn admit_blocked_command(
    node: &DaemonNodeRuntime,
    private: &PrivateAuthorityRuntime,
    context: CommandContext,
    command: &AuthoritativeCommand,
) -> Result<AdmissionSignals, Box<dyn std::error::Error>> {
    let (started, observed) = tokio::sync::oneshot::channel();
    let (release, released) = std::sync::mpsc::channel();
    *private
        .network_starter
        .admission_gate
        .lock()
        .map_err(|_| "test gate poisoned")? = Some(crate::metadata_forwarding::AdmissionGate {
        operation_id: context.operation_id,
        started,
        released,
    });
    let request = private_command_request(node, context, command)?;
    let sender = private
        .network_starter
        .generation
        .control_requests
        .lock()
        .map_err(|_| "test queue poisoned")?
        .clone()
        .ok_or("private dispatcher not started")?;
    sender
        .send(request)
        .await
        .map_err(|_| "private dispatcher closed before admission")?;
    Ok((observed, release))
}

fn private_command_request(
    node: &DaemonNodeRuntime,
    context: CommandContext,
    command: &AuthoritativeCommand,
) -> Result<PeerControlRequest, Box<dyn std::error::Error>> {
    use meshspan_protocol::v1::{MetadataCommand, VersionedPayload, metadata_command::Command};
    let network = node
        .private_network
        .network()
        .map_err(|()| "private network missing")?;
    let certificate = open_root_repository_at(node.local_state.state_directory(), current_time()?)?
        .active_node_certificate(node.local_state.node_id())?
        .ok_or("active certificate missing")?;
    let envelope = ControlEnvelope {
        header: Some(
            network.control_header(context.operation_id, current_time()?.get() + 30_000_000)?,
        ),
        message: Some(Message::MetadataCommand(MetadataCommand {
            expected_revision: context.expected_revision.map(Revision::get),
            request_digest: command.request_digest(context).to_vec(),
            command: Some(Command::ClusterControl(VersionedPayload {
                format_version: u32::from(meshspan_metadata::METADATA_COMMAND_VERSION),
                canonical_bytes: meshspan_metadata::encode_authoritative_command(context, command)?,
            })),
        })),
    };
    let limits = meshspan_protocol::WireLimits::new(64 * 1_024, 8, 256, 4_096)?;
    let frame = meshspan_protocol::encode_control_frame(&envelope, limits)?;
    let (respond, disconnected) = tokio::sync::oneshot::channel();
    drop(disconnected); // Lost response never supplies the test with an acknowledgement.
    Ok(PeerControlRequest {
        from: node.local_state.node_id(),
        sender_incarnation: certificate.incarnation,
        certificate_fingerprint: certificate.certificate_fingerprint,
        capability_digest: [1; 32],
        envelope: meshspan_protocol::decode_control_frame(&frame, limits)?,
        respond,
    })
}

async fn verify_private_receipt_replay(
    config: &HeadlessDaemonConfig,
    context: CommandContext,
    command: AuthoritativeCommand,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut node = initialise_daemon_node(config, current_time()?).await?;
    let repository = open_root_repository_at(node.local_state.state_directory(), current_time()?)?;
    let before = repository
        .resolve_operation(context.operation_id)?
        .ok_or("private operation receipt absent after reopen")?;
    assert_eq!(before.request_digest, command.request_digest(context));
    let user = repository
        .principal(PrincipalId::from_bytes([117; 16])?)?
        .ok_or("durable user absent after reopen")?;
    assert_eq!(user.display_name, "Private durable user");
    let private = start_private_authority(&mut node, config, current_time()?).await?;
    let replay = private.authority.commit_or_resolve(context, command).await;
    let mut cleanup = ShutdownOutcome::default();
    private.drain(&mut cleanup).await;
    cleanup.finish()?;
    assert_eq!(replay?, before);
    assert_eq!(
        repository.resolve_operation(context.operation_id)?,
        Some(before)
    );
    Ok(())
}
