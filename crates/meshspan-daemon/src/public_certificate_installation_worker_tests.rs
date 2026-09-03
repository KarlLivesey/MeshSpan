// SPDX-License-Identifier: GPL-2.0-only

use std::sync::{Arc, Mutex};

use meshspan_certificates::{CertificateAuthority, PublicCertificateBundle};
use meshspan_domain::{
    CertificateOrderId, EntropyError, NodeId, OperationId, PrincipalId, RandomSource, Revision,
    UnixMicros,
};
use meshspan_metadata::{
    ApplyDisposition, AuthoritativeCommand, CommandContext, CommandReceipt, EntityKind,
    EntityReference, LogPosition, PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND,
    PublicCertificateSelection, SecretGenerationRecord, SecretGenerationReference,
};
use meshspan_secret_envelope::{SecretContext, WrappingPublicKey, encrypt_secret};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use rustls::sign::CertifiedKey;

use crate::{
    LocalWrappingKey, PublicCertificateInstallationAuthority,
    PublicCertificateInstallationAuthorityError, PublicCertificateInstallationWorker,
    PublicCertificateInstallationWorkerComponents, PublicCertificateInstallationWorkerError,
    PublicCertificateInstallationWorkerOutcome, PublicCertificateSelectionAuthority,
    PublicCertificateSelectionAuthorityError, RotatingHttpsIdentity, SecretGenerationAuthority,
    SecretGenerationAuthorityError,
};

#[test]
fn completed_generation_replaces_bootstrap_and_acknowledges_exact_selection()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(None)?;
    let acknowledgements = Acknowledgements::default();
    let identity = fixture.identity.clone();
    let configured_by = fixture.selection.configured_by;
    let mut worker =
        PublicCertificateInstallationWorker::new(PublicCertificateInstallationWorkerComponents {
            selection: SelectionAuthority(Some(fixture.selection)),
            generation: GenerationAuthority(fixture.generation),
            decryptor: fixture.wrapping_key,
            acknowledgement: &acknowledgements,
            identity,
            gateway_node_id: fixture.node_id,
            gateway_incarnation: 7,
        })?;

    let outcome = worker.run_once(UnixMicros::new(500))?;
    assert!(matches!(
        outcome,
        PublicCertificateInstallationWorkerOutcome::Installed(_)
    ));
    assert_eq!(
        fixture
            .identity
            .current()?
            .ok_or("installed identity missing")?
            .revision,
        fixture.selection.order_revision
    );
    assert_eq!(acknowledgements.commit_count(), 1);
    assert_eq!(acknowledgements.actor()?, configured_by);
    assert_eq!(
        worker.run_once(UnixMicros::new(501))?,
        PublicCertificateInstallationWorkerOutcome::Current
    );
    assert_eq!(acknowledgements.commit_count(), 1);
    Ok(())
}

#[test]
fn selection_digest_mismatch_never_replaces_bootstrap_or_acknowledges()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = Fixture::new(Some([99; 32]))?;
    let acknowledgements = Acknowledgements::default();
    let identity = fixture.identity.clone();
    let mut worker =
        PublicCertificateInstallationWorker::new(PublicCertificateInstallationWorkerComponents {
            selection: SelectionAuthority(Some(fixture.selection)),
            generation: GenerationAuthority(fixture.generation),
            decryptor: fixture.wrapping_key,
            acknowledgement: &acknowledgements,
            identity,
            gateway_node_id: fixture.node_id,
            gateway_incarnation: 7,
        })?;

    assert_eq!(
        worker.run_once(UnixMicros::new(500)).err(),
        Some(PublicCertificateInstallationWorkerError::Failed)
    );
    assert_eq!(fixture.identity.current()?, None);
    assert_eq!(acknowledgements.commit_count(), 0);
    Ok(())
}

struct Fixture {
    node_id: NodeId,
    selection: PublicCertificateSelection,
    generation: SecretGenerationRecord,
    wrapping_key: LocalWrappingKey,
    identity: RotatingHttpsIdentity,
}

impl Fixture {
    fn new(selection_digest: Option<[u8; 32]>) -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let wrapping_key = LocalWrappingKey::open_or_create(&directory.path().join("node.key"))?;
        let authority = CertificateAuthority::new()?;
        let bootstrap = authority.issue_node("meshspan.local")?;
        let public = authority.issue_node("files.example.test")?;
        let identity = RotatingHttpsIdentity::new_bootstrap(certified_key(&bootstrap)?)?;
        let order_id = CertificateOrderId::from_bytes([11; 16])?;
        let reference = SecretGenerationReference {
            secret_id: order_id.as_bytes(),
            generation: 1,
        };
        let bundle = PublicCertificateBundle::new(
            vec![public.certificate_der().to_vec()],
            public.private_key().to_vec(),
        )?;
        let bundle_digest = bundle.digest();
        let generation =
            encrypted_generation(reference, &bundle.encode()?, wrapping_key.public_key())?;
        Ok(Self {
            node_id: NodeId::from_bytes([12; 16])?,
            selection: PublicCertificateSelection {
                order_id,
                certificate: reference,
                bundle_digest: selection_digest.unwrap_or(bundle_digest),
                configured_by: PrincipalId::from_bytes([13; 16])?,
                completed_at: UnixMicros::new(400),
                order_revision: Revision::new(20),
            },
            generation,
            wrapping_key,
            identity,
        })
    }
}

fn certified_key(
    certificate: &meshspan_certificates::IssuedCertificate,
) -> Result<Arc<CertifiedKey>, rustls::Error> {
    CertifiedKey::from_der(
        vec![CertificateDer::from(certificate.certificate_der().to_vec())],
        PrivatePkcs8KeyDer::from(certificate.private_key().to_vec()).into(),
        &meshspan_rustls_provider::provider(),
    )
    .map(Arc::new)
}

fn encrypted_generation(
    reference: SecretGenerationReference,
    plaintext: &[u8],
    recipient: WrappingPublicKey,
) -> Result<SecretGenerationRecord, Box<dyn std::error::Error>> {
    let (secret, recipients) = encrypt_secret(
        SecretContext::new(
            PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND,
            reference.secret_id,
            reference.generation,
        )?,
        plaintext,
        &[recipient],
        &mut FixedRandom(71),
    )?;
    Ok(SecretGenerationRecord {
        secret,
        recipients,
        revision: Revision::new(1),
    })
}

struct SelectionAuthority(Option<PublicCertificateSelection>);

impl PublicCertificateSelectionAuthority for SelectionAuthority {
    fn latest_public_certificate(
        &self,
    ) -> Result<Option<PublicCertificateSelection>, PublicCertificateSelectionAuthorityError> {
        Ok(self.0)
    }
}

struct GenerationAuthority(SecretGenerationRecord);

impl SecretGenerationAuthority for GenerationAuthority {
    fn secret_generation(
        &self,
        context: SecretContext,
    ) -> Result<Option<SecretGenerationRecord>, SecretGenerationAuthorityError> {
        Ok((self.0.secret.context() == context).then(|| self.0.clone()))
    }
}

#[derive(Default)]
struct Acknowledgements {
    state: Mutex<AcknowledgementState>,
}

#[derive(Default)]
struct AcknowledgementState {
    context: Option<CommandContext>,
    receipt: Option<CommandReceipt>,
    commits: usize,
}

impl Acknowledgements {
    fn commit_count(&self) -> usize {
        self.state.lock().map_or(0, |state| state.commits)
    }

    fn actor(&self) -> Result<PrincipalId, Box<dyn std::error::Error>> {
        self.state
            .lock()
            .map_err(|_| "acknowledgement state unavailable")?
            .context
            .map(|context| context.actor_principal_id)
            .ok_or_else(|| "acknowledgement context missing".into())
    }
}

impl PublicCertificateInstallationAuthority for &Acknowledgements {
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
        let AuthoritativeCommand::AcknowledgePublicCertificateInstallation(value) = command else {
            return Err(PublicCertificateInstallationAuthorityError::Failed);
        };
        let receipt = CommandReceipt {
            disposition: ApplyDisposition::Applied,
            operation_id: context.operation_id,
            request_digest: command.request_digest(context),
            result_digest: [77; 32],
            committed_revision: Revision::new(21),
            committed_position: LogPosition { index: 21, term: 1 },
            applied_position: LogPosition { index: 21, term: 1 },
            entity: EntityReference {
                kind: EntityKind::CertificateOrder,
                id: value.order_id.as_bytes(),
            },
        };
        let mut state = self
            .state
            .lock()
            .map_err(|_| PublicCertificateInstallationAuthorityError::Failed)?;
        state.context = Some(context);
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
