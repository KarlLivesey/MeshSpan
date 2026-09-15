// SPDX-License-Identifier: GPL-2.0-only

//! Bind typed metadata forwarding to the authenticated node, not its claimed audit actor.

use meshspan_cluster::{
    MetadataAuthorityHandle, MetadataPeerAdmissionDetails, MetadataPeerAdmissionPurpose,
    MetadataPeerAdmissionState,
};
use meshspan_domain::{Clock as _, UnixMicros};
use meshspan_metadata::{
    ActiveNodeCertificate, AuthoritativeCommand, DecodedAuthoritativeCommand, JoinRoles,
    METADATA_COMMAND_VERSION, StorageTargetRegistrationContext, decode_authoritative_command,
};
use meshspan_protocol::v1::{
    ControlEnvelope, ErrorCode, MetadataCommand, RequestHeader, control_envelope::Message,
    metadata_command::Command,
};
use meshspan_transport::PeerBinding;
use sha2::{Digest as _, Sha256};

#[derive(Debug)]
pub(crate) enum AdmissionError {
    Protocol(ErrorCode),
    WorkerStopped,
}

impl From<ErrorCode> for AdmissionError {
    fn from(code: ErrorCode) -> Self {
        Self::Protocol(code)
    }
}

pub(crate) async fn prepare(
    authority: &MetadataAuthorityHandle,
    peer: PeerBinding,
    envelope: ControlEnvelope,
) -> Result<DecodedAuthoritativeCommand, AdmissionError> {
    // The existing private request owner bounds and joins both CPU jobs. Codec/digest and
    // installation-signature work must not execute on an asynchronous executor thread.
    let (header, decoded) = tokio::task::spawn_blocking(move || decode_request(peer, envelope))
        .await
        .map_err(|_| AdmissionError::WorkerStopped)??;
    let purpose = if matches!(
        decoded.command,
        AuthoritativeCommand::AcknowledgeNodeCertificateInstallation(_)
    ) {
        MetadataPeerAdmissionPurpose::CertificateInstallation
    } else {
        MetadataPeerAdmissionPurpose::Command
    };
    let state = authority
        .peer_admission(peer.node_id, purpose)
        .await
        .map_err(|_| ErrorCode::Unavailable)?;
    tokio::task::spawn_blocking(move || authorize(peer, &header, decoded, state))
        .await
        .map_err(|_| AdmissionError::WorkerStopped)?
        .map_err(Into::into)
}

fn decode_request(
    peer: PeerBinding,
    envelope: ControlEnvelope,
) -> Result<(RequestHeader, DecodedAuthoritativeCommand), ErrorCode> {
    let header = envelope.header.ok_or(ErrorCode::Invalid)?;
    validate_sender(peer, &header, crate::OperatingSystemClock.now())?;
    let Some(Message::MetadataCommand(command)) = envelope.message else {
        return Err(ErrorCode::Invalid);
    };
    let decoded = decode(&header, &command)?;
    Ok((header, decoded))
}

fn authorize(
    peer: PeerBinding,
    header: &RequestHeader,
    decoded: DecodedAuthoritativeCommand,
    state: MetadataPeerAdmissionState,
) -> Result<DecodedAuthoritativeCommand, ErrorCode> {
    let now = crate::OperatingSystemClock.now();
    let certificate = state.certificate.ok_or(ErrorCode::Unauthorised)?;
    validate_sender(peer, header, now)?;
    if certificate.node_id != peer.node_id || certificate.incarnation != peer.incarnation {
        return Err(ErrorCode::Unauthorised);
    }
    let mesh = state.mesh_id.ok_or(ErrorCode::Unauthorised)?;
    if header.mesh_id.as_slice() != mesh.as_bytes()
        || header.partition_id.as_slice() != state.partition_id.as_bytes()
    {
        return Err(ErrorCode::Unauthorised);
    }
    match (
        matches!(
            decoded.command,
            AuthoritativeCommand::AcknowledgeNodeCertificateInstallation(_)
        ),
        state.details,
    ) {
        (
            true,
            MetadataPeerAdmissionDetails::CertificateInstallation {
                registration,
                rotation,
            },
        ) => {
            let registration = registration.ok_or(ErrorCode::Unauthorised)?;
            let rotation = rotation.ok_or(ErrorCode::Unauthorised)?;
            // An already-open control stream may use the active leaf. The staged leaf is
            // accepted only for this exact same-key signed installation acknowledgement.
            if validate_binding(peer, header, &certificate, now).is_err()
                && Sha256::digest(&rotation.certificate_der).as_slice()
                    != peer.certificate_fingerprint
            {
                return Err(ErrorCode::Unauthorised);
            }
            if !acknowledgement_matches(&decoded, peer, registration, &rotation, now) {
                return Err(ErrorCode::Unauthorised);
            }
        }
        (
            false,
            MetadataPeerAdmissionDetails::Command {
                is_voter,
                registration,
            },
        ) => {
            validate_binding(peer, header, &certificate, now)?;
            if certificate.roles.bits() & JoinRoles::GATEWAY == 0
                && !is_voter
                && (certificate.roles.bits() & JoinRoles::STORAGE == 0
                    || !registration
                        .is_some_and(|registration| registration_matches(&decoded, registration)))
            {
                return Err(ErrorCode::Unauthorised);
            }
        }
        (_, MetadataPeerAdmissionDetails::ReadFence)
        | (true, MetadataPeerAdmissionDetails::Command { .. })
        | (false, MetadataPeerAdmissionDetails::CertificateInstallation { .. }) => {
            return Err(ErrorCode::InternalContract);
        }
    }
    Ok(decoded)
}

fn validate_binding(
    peer: PeerBinding,
    header: &RequestHeader,
    certificate: &ActiveNodeCertificate,
    now: UnixMicros,
) -> Result<(), ErrorCode> {
    validate_sender(peer, header, now)?;
    if certificate.node_id != peer.node_id
        || certificate.incarnation != peer.incarnation
        || certificate.certificate_fingerprint != peer.certificate_fingerprint
        || certificate.valid_until <= now
    {
        return Err(ErrorCode::Unauthorised);
    }
    Ok(())
}

fn validate_sender(
    peer: PeerBinding,
    header: &RequestHeader,
    now: UnixMicros,
) -> Result<(), ErrorCode> {
    let remaining = header
        .deadline_unix_micros
        .checked_sub(now.get())
        .ok_or(ErrorCode::Deadline)?;
    if !(1..=30_000_000).contains(&remaining) {
        return Err(ErrorCode::Deadline);
    }
    if header.sender_node_id.as_slice() != peer.node_id.as_bytes()
        || header.sender_incarnation != peer.incarnation
    {
        return Err(ErrorCode::Unauthorised);
    }
    Ok(())
}

fn acknowledgement_matches(
    decoded: &DecodedAuthoritativeCommand,
    peer: PeerBinding,
    registration: StorageTargetRegistrationContext,
    rotation: &meshspan_metadata::NodeCertificateRotation,
    now: UnixMicros,
) -> bool {
    let AuthoritativeCommand::AcknowledgeNodeCertificateInstallation(ack) = &decoded.command else {
        return false;
    };
    let bound = ack.node_id == peer.node_id
        && ack.incarnation == peer.incarnation
        && registration.node_id == peer.node_id
        && decoded.context.actor_principal_id == registration.actor_principal_id
        && rotation.node_id == peer.node_id
        && rotation.incarnation == peer.incarnation
        && rotation.generation == ack.generation
        && rotation.staged_revision == ack.staged_revision
        && rotation.valid_until > now
        && matches!(
            rotation.state,
            meshspan_metadata::NodeCertificateRotationState::Staged
                | meshspan_metadata::NodeCertificateRotationState::Installed
        )
        && Sha256::digest(&rotation.certificate_der).as_slice() == ack.certificate_fingerprint;
    bound
        && meshspan_certificates::NodePublicIdentity::from_certificate(&rotation.certificate_der)
            .and_then(|identity| {
                identity.verify_enrolment_transcript(&ack.signing_transcript(), &ack.signature)
            })
            .is_ok()
}

fn decode(
    header: &RequestHeader,
    request: &MetadataCommand,
) -> Result<DecodedAuthoritativeCommand, ErrorCode> {
    let Some(
        Command::Topology(payload)
        | Command::IdentityAccess(payload)
        | Command::Namespace(payload)
        | Command::Policy(payload)
        | Command::Lifecycle(payload)
        | Command::ClusterControl(payload),
    ) = request.command.as_ref()
    else {
        return Err(ErrorCode::Invalid);
    };
    if payload.format_version != u32::from(METADATA_COMMAND_VERSION) {
        return Err(ErrorCode::Unsupported);
    }
    let decoded =
        decode_authoritative_command(&payload.canonical_bytes).map_err(|_| ErrorCode::Invalid)?;
    if decoded.context.operation_id.as_bytes().as_slice() != header.operation_id
        || decoded
            .context
            .expected_revision
            .map(meshspan_domain::Revision::get)
            != request.expected_revision
        || decoded.context.occurred_at.get() > header.deadline_unix_micros
        || request.request_digest.as_slice() != decoded.command.request_digest(decoded.context)
    {
        return Err(ErrorCode::Invalid);
    }
    Ok(decoded)
}

fn registration_matches(
    decoded: &DecodedAuthoritativeCommand,
    registration: StorageTargetRegistrationContext,
) -> bool {
    // An allow-list is deliberate: new command families do not inherit storage-node authority.
    let AuthoritativeCommand::RegisterStorageTarget(target) = &decoded.command else {
        return false;
    };
    target.node_id == registration.node_id
        && target.host_id == registration.host_id
        && decoded.context.actor_principal_id == registration.actor_principal_id
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshspan_domain::{NodeId, Revision};

    #[test]
    fn installation_acknowledgement_is_bound_to_its_own_candidate()
    -> Result<(), Box<dyn std::error::Error>> {
        let (decoded, peer, registration, rotation) = acknowledgement_fixture()?;
        let now = UnixMicros::new(10);
        assert!(acknowledgement_matches(
            &decoded,
            peer,
            registration,
            &rotation,
            now
        ));
        let mut installed = rotation.clone();
        installed.state = meshspan_metadata::NodeCertificateRotationState::Installed;
        assert!(acknowledgement_matches(
            &decoded,
            peer,
            registration,
            &installed,
            now
        ));
        for changed in [
            PeerBinding {
                node_id: NodeId::from_bytes([9; 16])?,
                ..peer
            },
            PeerBinding {
                incarnation: 8,
                ..peer
            },
        ] {
            assert!(!acknowledgement_matches(
                &decoded,
                changed,
                registration,
                &rotation,
                now
            ));
        }
        for field in 0..7 {
            let mut changed = decoded.clone();
            let AuthoritativeCommand::AcknowledgeNodeCertificateInstallation(ack) =
                &mut changed.command
            else {
                return Err("fixture command is not an acknowledgement".into());
            };
            match field {
                0 => ack.generation += 1,
                1 => ack.staged_revision = Revision::new(8),
                2 => ack.signature.clear(),
                3 => ack.node_id = NodeId::from_bytes([9; 16])?,
                4 => ack.incarnation += 1,
                5 => ack.certificate_fingerprint = [9; 32],
                _ => {
                    changed.context.actor_principal_id =
                        meshspan_domain::PrincipalId::from_bytes([9; 16])?;
                }
            }
            assert!(!acknowledgement_matches(
                &changed,
                peer,
                registration,
                &rotation,
                now
            ));
        }
        for state in [
            meshspan_metadata::NodeCertificateRotationState::Retired,
            meshspan_metadata::NodeCertificateRotationState::Abandoned,
        ] {
            let mut changed = rotation.clone();
            changed.state = state;
            assert!(!acknowledgement_matches(
                &decoded,
                peer,
                registration,
                &changed,
                now
            ));
        }
        assert!(!acknowledgement_matches(
            &decoded,
            peer,
            registration,
            &rotation,
            rotation.valid_until
        ));
        Ok(())
    }

    #[test]
    fn admission_purpose_mismatch_never_grants_forwarding() -> Result<(), Box<dyn std::error::Error>>
    {
        let (mut decoded, peer, registration, rotation) = acknowledgement_fixture()?;
        let now = crate::OperatingSystemClock.now();
        let partition = meshspan_domain::PartitionId::from_bytes([8; 16])?;
        let header = RequestHeader {
            mesh_id: registration.mesh_id.as_bytes().to_vec(),
            partition_id: partition.as_bytes().to_vec(),
            sender_node_id: peer.node_id.as_bytes().to_vec(),
            sender_incarnation: peer.incarnation,
            deadline_unix_micros: now.get() + 9_000_000,
            ..RequestHeader::default()
        };
        let mut state = MetadataPeerAdmissionState {
            mesh_id: Some(registration.mesh_id),
            partition_id: partition,
            certificate: Some(ActiveNodeCertificate {
                node_id: peer.node_id,
                incarnation: peer.incarnation,
                roles: JoinRoles::new(JoinRoles::GATEWAY)?,
                generation: 1,
                certificate_der: rotation.certificate_der,
                certificate_fingerprint: peer.certificate_fingerprint,
                valid_until: UnixMicros::new(now.get() + 20_000_000),
                revision: Revision::new(1),
            }),
            details: MetadataPeerAdmissionDetails::Command {
                is_voter: true,
                registration: None,
            },
        };
        assert!(matches!(
            authorize(peer, &header, decoded.clone(), state.clone()),
            Err(ErrorCode::InternalContract)
        ));
        decoded.command = AuthoritativeCommand::CreateUser(meshspan_metadata::CreateUser {
            principal_id: registration.actor_principal_id,
            name: meshspan_metadata::RecordName::new("Not an installation")?,
        });
        state.details = MetadataPeerAdmissionDetails::CertificateInstallation {
            registration: None,
            rotation: None,
        };
        assert!(matches!(
            authorize(peer, &header, decoded, state),
            Err(ErrorCode::InternalContract)
        ));
        Ok(())
    }

    fn acknowledgement_fixture() -> Result<
        (
            DecodedAuthoritativeCommand,
            PeerBinding,
            StorageTargetRegistrationContext,
            meshspan_metadata::NodeCertificateRotation,
        ),
        Box<dyn std::error::Error>,
    > {
        let ca = meshspan_certificates::CertificateAuthority::new()?;
        let (der, key) = ca.issue_node("storage.meshspan.internal")?.into_parts();
        let identity = meshspan_certificates::NodeIdentityKey::from_pkcs8(&key)?;
        let node = NodeId::from_bytes([1; 16])?;
        let peer = PeerBinding {
            node_id: node,
            incarnation: 7,
            certificate_fingerprint: Sha256::digest(&der).into(),
        };
        let registration = StorageTargetRegistrationContext {
            mesh_id: meshspan_domain::MeshId::from_bytes([2; 16])?,
            node_id: node,
            host_id: meshspan_domain::HostId::from_bytes([3; 16])?,
            actor_principal_id: meshspan_domain::PrincipalId::from_bytes([4; 16])?,
        };
        let rotation = meshspan_metadata::NodeCertificateRotation {
            node_id: node,
            incarnation: 7,
            generation: 2,
            certificate_der: der,
            previous_certificate_der: Vec::new(),
            issuer_certificate_der: Vec::new(),
            staged_revision: Revision::new(6),
            state: meshspan_metadata::NodeCertificateRotationState::Staged,
            retire_after: None,
            valid_until: UnixMicros::new(100),
        };
        let mut ack = meshspan_metadata::AcknowledgeNodeCertificateInstallation {
            node_id: node,
            incarnation: 7,
            generation: 2,
            certificate_fingerprint: peer.certificate_fingerprint,
            staged_revision: rotation.staged_revision,
            signature: Vec::new(),
        };
        ack.signature = identity.sign_enrolment_transcript(&ack.signing_transcript())?;
        Ok((
            DecodedAuthoritativeCommand {
                context: crate::private_certificate_renewal::command_context(
                    registration.actor_principal_id,
                    UnixMicros::new(10),
                )?,
                command: AuthoritativeCommand::AcknowledgeNodeCertificateInstallation(ack),
            },
            peer,
            registration,
            rotation,
        ))
    }

    #[test]
    fn forwarding_rechecks_certificate_sender_and_deadline()
    -> Result<(), Box<dyn std::error::Error>> {
        let node = NodeId::from_bytes([1; 16])?;
        let peer = PeerBinding {
            node_id: node,
            incarnation: 7,
            certificate_fingerprint: [2; 32],
        };
        let certificate = ActiveNodeCertificate {
            node_id: node,
            incarnation: 7,
            roles: JoinRoles::new(JoinRoles::STORAGE)?,
            generation: 1,
            certificate_der: vec![1],
            certificate_fingerprint: [2; 32],
            valid_until: UnixMicros::new(100),
            revision: Revision::new(1),
        };
        let header = RequestHeader {
            sender_node_id: node.as_bytes().to_vec(),
            sender_incarnation: 7,
            deadline_unix_micros: 50,
            ..RequestHeader::default()
        };
        let now = UnixMicros::new(10);
        assert_eq!(validate_binding(peer, &header, &certificate, now), Ok(()));
        for changed in [
            PeerBinding {
                node_id: NodeId::from_bytes([3; 16])?,
                ..peer
            },
            PeerBinding {
                incarnation: 8,
                ..peer
            },
            PeerBinding {
                certificate_fingerprint: [4; 32],
                ..peer
            },
        ] {
            assert_eq!(
                validate_binding(changed, &header, &certificate, now),
                Err(ErrorCode::Unauthorised)
            );
        }
        for changed in [
            RequestHeader {
                sender_node_id: vec![5; 16],
                ..header.clone()
            },
            RequestHeader {
                sender_incarnation: 8,
                ..header.clone()
            },
        ] {
            assert_eq!(
                validate_binding(peer, &changed, &certificate, now),
                Err(ErrorCode::Unauthorised)
            );
        }
        let expired = ActiveNodeCertificate {
            valid_until: now,
            ..certificate.clone()
        };
        assert_eq!(
            validate_binding(peer, &header, &expired, now),
            Err(ErrorCode::Unauthorised)
        );
        for deadline in [i64::MIN, 9, 10, 30_000_011, i64::MAX] {
            let changed = RequestHeader {
                deadline_unix_micros: deadline,
                ..header.clone()
            };
            assert_eq!(
                validate_binding(peer, &changed, &certificate, now),
                Err(ErrorCode::Deadline)
            );
        }
        Ok(())
    }
}
