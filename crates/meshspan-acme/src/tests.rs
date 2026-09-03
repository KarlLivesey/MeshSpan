// SPDX-License-Identifier: GPL-2.0-only

use std::collections::BTreeMap;
use std::future::Future;

use meshspan_contracts::{
    BoundedBytes, CertificateChallenge, CertificateChallengeKind, CertificateChallengeRequest,
    ContractError, ContractVersion, RequestContext,
};
use meshspan_domain::{OperationId, Revision, UnixMicros};
use sha2::{Digest, Sha256};

use crate::{
    Dns01Challenge, Dns01Payload, DnsTxtProvider, DnsTxtReceipt, Http01Challenge, Http01Payload,
};

#[tokio::test]
async fn http_publication_is_shared_bounded_expiring_and_epoch_fenced()
-> Result<(), Box<dyn std::error::Error>> {
    let mut publisher = Http01Challenge::new();
    let reader = publisher.clone();
    let request = http_request(7, b"token.thumbprint")?;
    let receipt = publisher.publish(&request).await?;
    assert_eq!(publisher.publish(&request).await?, receipt);
    assert_eq!(
        reader.response("token", UnixMicros::new(199))?,
        Some(b"token.thumbprint".to_vec())
    );
    assert_eq!(reader.response("token", UnixMicros::new(200))?, None);

    let conflict = http_request(7, b"different.thumbprint")?;
    assert_eq!(
        publisher.publish(&conflict).await,
        Err(ContractError::Conflict)
    );
    let newer = http_request(8, b"replacement.thumbprint")?;
    publisher.publish(&newer).await?;
    assert_eq!(publisher.publish(&request).await, Err(ContractError::Stale));
    assert_eq!(
        publisher.cleanup(&request, receipt).await,
        Err(ContractError::Stale)
    );
    Ok(())
}

#[tokio::test]
async fn dns_publication_uses_exact_provider_receipt_for_probe_and_cleanup()
-> Result<(), Box<dyn std::error::Error>> {
    let provider = MemoryDns::default();
    let mut challenge = Dns01Challenge::new(provider);
    let payload = Dns01Payload::new("_acme-challenge.files.example.test", b"txt-value")?;
    let request = request(
        CertificateChallengeKind::Dns01,
        "files.example.test",
        payload.encode()?,
        9,
    )?;
    let receipt = challenge.publish(&request).await?;
    let provider = challenge.into_provider();
    let mut challenge = Dns01Challenge::new(provider);
    assert!(challenge.is_visible(&request, receipt).await?);
    let mut stale = receipt;
    stale.publication_digest[0] ^= 1;
    assert_eq!(
        challenge.cleanup(&request, stale).await,
        Err(ContractError::Stale)
    );
    challenge.cleanup(&request, receipt).await?;
    assert!(!challenge.is_visible(&request, receipt).await?);
    Ok(())
}

fn http_request(
    epoch: u64,
    key_authorization: &[u8],
) -> Result<CertificateChallengeRequest, Box<dyn std::error::Error>> {
    request(
        CertificateChallengeKind::Http01,
        "files.example.test",
        Http01Payload::new("token", key_authorization)?.encode()?,
        epoch,
    )
}

fn request(
    kind: CertificateChallengeKind,
    identifier: &str,
    challenge: meshspan_contracts::VersionedPayload,
    epoch: u64,
) -> Result<CertificateChallengeRequest, Box<dyn std::error::Error>> {
    Ok(CertificateChallengeRequest {
        context: RequestContext {
            contract_version: ContractVersion::V1_0,
            operation_id: OperationId::from_bytes([1; 16])?,
            deadline: UnixMicros::new(100),
            expected_revision: Some(Revision::new(3)),
        },
        kind,
        identifier: BoundedBytes::copy_from(identifier.as_bytes(), 253)?,
        challenge,
        expires_at: UnixMicros::new(200),
        order_epoch: epoch,
    })
}

#[derive(Default)]
struct MemoryDns {
    records: BTreeMap<String, (Vec<u8>, DnsTxtReceipt)>,
}

impl DnsTxtProvider for MemoryDns {
    fn receipt(&self, name: &str, value: &[u8], order_epoch: u64) -> DnsTxtReceipt {
        dns_receipt(name, value, order_epoch)
    }

    fn publish_txt(
        &mut self,
        name: &str,
        value: &[u8],
        order_epoch: u64,
    ) -> impl Future<Output = Result<DnsTxtReceipt, ContractError>> + Send {
        let receipt = dns_receipt(name, value, order_epoch);
        self.records
            .insert(name.to_owned(), (value.to_vec(), receipt));
        std::future::ready(Ok(receipt))
    }

    fn is_txt_visible(
        &self,
        name: &str,
        value: &[u8],
        receipt: DnsTxtReceipt,
    ) -> impl Future<Output = Result<bool, ContractError>> + Send {
        std::future::ready(Ok(self
            .records
            .get(name)
            .is_some_and(|record| record.0 == value && record.1 == receipt)))
    }

    fn remove_txt(
        &mut self,
        name: &str,
        value: &[u8],
        receipt: DnsTxtReceipt,
    ) -> impl Future<Output = Result<(), ContractError>> + Send {
        if !self
            .records
            .get(name)
            .is_some_and(|record| record.0 == value && record.1 == receipt)
        {
            return std::future::ready(Err(ContractError::Stale));
        }
        self.records.remove(name);
        std::future::ready(Ok(()))
    }
}

fn dns_receipt(name: &str, value: &[u8], order_epoch: u64) -> DnsTxtReceipt {
    let mut digest = Sha256::new();
    digest.update(name.as_bytes());
    digest.update(value);
    digest.update(order_epoch.to_be_bytes());
    DnsTxtReceipt {
        provider_digest: digest.finalize().into(),
    }
}
