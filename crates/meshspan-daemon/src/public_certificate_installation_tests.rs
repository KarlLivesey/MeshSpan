// SPDX-License-Identifier: GPL-2.0-only

use std::sync::Mutex;

use meshspan_certificates::{CertificateAuthority, PublicCertificateBundle};
use meshspan_domain::{
    CertificateOrderId, EntropyError, MeshLocalCertificateIssuanceId, NodeId, OperationId,
    PrincipalId, RandomSource, Revision, UnixMicros,
};
use meshspan_metadata::{
    ApplyDisposition, AuthoritativeCommand, CommandContext, CommandReceipt, EntityKind,
    EntityReference, LogPosition, PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND, PublicCertificateSource,
    SecretGenerationRecord, SecretGenerationReference,
};
use meshspan_secret_envelope::{SecretContext, encrypt_secret};

use crate::{
    LoadedPublicCertificate, LocalWrappingKey, PublicCertificateInstallationAuthority,
    PublicCertificateInstallationAuthorityError, PublicCertificateInstallationReceipt,
    PublicCertificateInstallationRequest, PublicCertificateInstallationService,
    PublicCertificateLoadingService, RotatingHttpsIdentity, SecretGenerationAuthority,
    SecretGenerationAuthorityError,
};

#[test]
fn live_installation_is_acknowledged_once_and_ambiguous_retry_resolves_exactly()
-> Result<(), Box<dyn std::error::Error>> {
    let order_id = CertificateOrderId::from_bytes([1; 16])?;
    let reference = SecretGenerationReference {
        secret_id: order_id.as_bytes(),
        generation: 1,
    };
    let (loaded, bundle_digest) = loaded_certificate(reference)?;
    let identity = RotatingHttpsIdentity::new(Revision::new(9), &loaded)?;
    let acknowledgements = AcknowledgementAuthority::default();
    let service = PublicCertificateInstallationService::new(&acknowledgements);
    let request = PublicCertificateInstallationRequest {
        source: PublicCertificateSource::AcmeOrder(order_id),
        source_revision: Revision::new(10),
        gateway_node_id: NodeId::from_bytes([2; 16])?,
        gateway_incarnation: 3,
        actor_principal_id: PrincipalId::from_bytes([4; 16])?,
        now: UnixMicros::new(500),
    };

    let committed = service.install_and_acknowledge(&identity, &loaded, request)?;
    assert_eq!(committed.certificate, reference);
    assert_eq!(committed.bundle_digest, bundle_digest);
    assert_eq!(committed.acknowledgement_revision, Revision::new(11));
    assert_eq!(
        identity
            .current()?
            .ok_or("installed identity missing")?
            .revision,
        Revision::new(10)
    );
    assert_eq!(acknowledgements.commit_count(), 1);
    let command = acknowledgements.command()?;
    let AuthoritativeCommand::AcknowledgePublicCertificateInstallation(command) = command else {
        return Err("wrong acknowledgement command".into());
    };
    assert_eq!(command.gateway_node_id, request.gateway_node_id);
    assert_eq!(command.gateway_incarnation, request.gateway_incarnation);
    assert_eq!(command.certificate, reference);
    assert_eq!(command.bundle_digest, bundle_digest);

    let retry = PublicCertificateInstallationRequest {
        now: UnixMicros::new(501),
        ..request
    };
    assert_eq!(
        service.install_and_acknowledge(&identity, &loaded, retry)?,
        committed
    );
    assert_eq!(acknowledgements.commit_count(), 1);
    acknowledgements
        .state
        .lock()
        .map_err(|_| "acknowledgement lock failed")?
        .occurred_at = Some(UnixMicros::new(499));
    assert!(matches!(
        service.install_and_acknowledge(&identity, &loaded, retry),
        Err(crate::PublicCertificateInstallationError::Conflict)
    ));
    Ok(())
}

#[test]
fn mesh_local_installation_uses_its_exact_issuance_acknowledgement()
-> Result<(), Box<dyn std::error::Error>> {
    let issuance_id = MeshLocalCertificateIssuanceId::from_bytes([21; 16])?;
    let reference = SecretGenerationReference {
        secret_id: [22; 16],
        generation: 3,
    };
    let (loaded, _) = loaded_certificate(reference)?;
    let identity = RotatingHttpsIdentity::new(Revision::new(9), &loaded)?;
    let acknowledgements = AcknowledgementAuthority::default();
    PublicCertificateInstallationService::new(&acknowledgements).install_and_acknowledge(
        &identity,
        &loaded,
        PublicCertificateInstallationRequest {
            source: PublicCertificateSource::MeshLocalIssuance(issuance_id),
            source_revision: Revision::new(10),
            gateway_node_id: NodeId::from_bytes([2; 16])?,
            gateway_incarnation: 3,
            actor_principal_id: PrincipalId::from_bytes([4; 16])?,
            now: UnixMicros::new(500),
        },
    )?;
    let command = acknowledgements.command()?;
    let AuthoritativeCommand::AcknowledgeMeshLocalCertificateInstallation(command) = command else {
        return Err("wrong mesh-local acknowledgement command".into());
    };
    assert_eq!(command.issuance_id, issuance_id);
    assert_eq!(command.certificate, reference);
    Ok(())
}

fn loaded_certificate(
    reference: SecretGenerationReference,
) -> Result<(LoadedPublicCertificate, [u8; 32]), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let local = LocalWrappingKey::open_or_create(&directory.path().join("node.key"))?;
    let authority = CertificateAuthority::new()?;
    let issued = authority.issue_node("files.example.test")?;
    let bundle = PublicCertificateBundle::new(
        vec![issued.certificate_der().to_vec()],
        issued.private_key().to_vec(),
    )?;
    let context = SecretContext::new(
        PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND,
        reference.secret_id,
        reference.generation,
    )?;
    let (secret, recipients) = encrypt_secret(
        context,
        &bundle.encode()?,
        &[local.public_key()],
        &mut FixedRandom(11),
    )?;
    let record = SecretGenerationRecord {
        secret,
        recipients,
        revision: Revision::new(8),
    };
    let loaded =
        PublicCertificateLoadingService::new(SecretAuthority(record), &local).load(reference)?;
    Ok((loaded, bundle.digest()))
}

struct SecretAuthority(SecretGenerationRecord);

impl SecretGenerationAuthority for SecretAuthority {
    fn secret_generation(
        &self,
        context: SecretContext,
    ) -> Result<Option<SecretGenerationRecord>, SecretGenerationAuthorityError> {
        Ok((self.0.secret.context() == context).then(|| self.0.clone()))
    }
}

#[derive(Default)]
struct AcknowledgementAuthority {
    state: Mutex<AcknowledgementState>,
}

#[derive(Default)]
struct AcknowledgementState {
    command: Option<AuthoritativeCommand>,
    receipt: Option<CommandReceipt>,
    occurred_at: Option<UnixMicros>,
    commits: usize,
}

impl AcknowledgementAuthority {
    fn command(&self) -> Result<AuthoritativeCommand, Box<dyn std::error::Error>> {
        self.state
            .lock()
            .map_err(|_| "acknowledgement lock failed")?
            .command
            .clone()
            .ok_or_else(|| "acknowledgement command missing".into())
    }

    fn commit_count(&self) -> usize {
        self.state.lock().map_or(0, |state| state.commits)
    }
}

impl PublicCertificateInstallationAuthority for &AcknowledgementAuthority {
    fn resolve_public_certificate_installation(
        &self,
        _operation_id: OperationId,
    ) -> Result<
        Option<PublicCertificateInstallationReceipt>,
        PublicCertificateInstallationAuthorityError,
    > {
        let state = self
            .state
            .lock()
            .map_err(|_| PublicCertificateInstallationAuthorityError::Failed)?;
        Ok(state
            .receipt
            .zip(state.occurred_at)
            .map(
                |(receipt, occurred_at)| PublicCertificateInstallationReceipt {
                    receipt,
                    occurred_at,
                },
            ))
    }

    fn acknowledge_public_certificate_installation(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, PublicCertificateInstallationAuthorityError> {
        let entity = match command {
            AuthoritativeCommand::AcknowledgePublicCertificateInstallation(value) => {
                EntityReference {
                    kind: EntityKind::CertificateOrder,
                    id: value.order_id.as_bytes(),
                }
            }
            AuthoritativeCommand::AcknowledgeMeshLocalCertificateInstallation(value) => {
                EntityReference {
                    kind: EntityKind::MeshLocalCertificateIssuance,
                    id: value.issuance_id.as_bytes(),
                }
            }
            _ => return Err(PublicCertificateInstallationAuthorityError::Failed),
        };
        let receipt = CommandReceipt {
            disposition: ApplyDisposition::Applied,
            operation_id: context.operation_id,
            request_digest: command.request_digest(context),
            result_digest: [7; 32],
            committed_revision: Revision::new(11),
            committed_position: LogPosition { index: 11, term: 1 },
            applied_position: LogPosition { index: 11, term: 1 },
            entity,
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| PublicCertificateInstallationAuthorityError::Failed)?;
        state.command = Some(command.clone());
        state.receipt = Some(receipt);
        state.occurred_at = Some(context.occurred_at);
        state.commits = state.commits.saturating_add(1);
        Ok(receipt)
    }
}

struct FixedRandom(u8);

impl RandomSource for FixedRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        for byte in destination {
            *byte = self.0;
            self.0 = self.0.wrapping_add(1).max(1);
        }
        Ok(())
    }
}
