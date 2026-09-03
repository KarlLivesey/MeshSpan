// SPDX-License-Identifier: GPL-2.0-only

use std::sync::Mutex;

use meshspan_certificates::{CertificateAuthority, PublicCertificateBundle};
use meshspan_domain::{
    CertificateOrderId, EntropyError, NodeId, OperationId, PrincipalId, RandomSource, Revision,
    UnixMicros,
};
use meshspan_metadata::{
    ApplyDisposition, AuthoritativeCommand, CommandContext, CommandReceipt, EntityKind,
    EntityReference, LogPosition, PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND, PublicCertificateSource,
    SecretGenerationRecord, SecretGenerationReference,
};
use meshspan_secret_envelope::{SecretContext, encrypt_secret};

use crate::{
    LocalWrappingKey, PublicCertificateInstallationAuthority,
    PublicCertificateInstallationAuthorityError, PublicCertificateInstallationRequest,
    PublicCertificateInstallationService, PublicCertificateLoadingService, RotatingHttpsIdentity,
    SecretGenerationAuthority, SecretGenerationAuthorityError,
};

#[test]
fn live_installation_is_acknowledged_once_and_ambiguous_retry_resolves_exactly()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let local = LocalWrappingKey::open_or_create(&directory.path().join("node.key"))?;
    let order_id = CertificateOrderId::from_bytes([1; 16])?;
    let reference = SecretGenerationReference {
        secret_id: order_id.as_bytes(),
        generation: 1,
    };
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
    assert_eq!(committed.bundle_digest, bundle.digest());
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
    assert_eq!(command.bundle_digest, bundle.digest());

    assert_eq!(
        service.install_and_acknowledge(&identity, &loaded, request)?,
        committed
    );
    assert_eq!(acknowledgements.commit_count(), 1);
    Ok(())
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
    ) -> Result<Option<CommandReceipt>, PublicCertificateInstallationAuthorityError> {
        Ok(self
            .state
            .lock()
            .map_err(|_| PublicCertificateInstallationAuthorityError::Failed)?
            .receipt)
    }

    fn acknowledge_public_certificate_installation(
        &self,
        context: CommandContext,
        command: &AuthoritativeCommand,
    ) -> Result<CommandReceipt, PublicCertificateInstallationAuthorityError> {
        let order_id = match command {
            AuthoritativeCommand::AcknowledgePublicCertificateInstallation(value) => value.order_id,
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
            entity: EntityReference {
                kind: EntityKind::CertificateOrder,
                id: order_id.as_bytes(),
            },
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| PublicCertificateInstallationAuthorityError::Failed)?;
        state.command = Some(command.clone());
        state.receipt = Some(receipt);
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
