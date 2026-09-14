// SPDX-License-Identifier: GPL-2.0-only

//! Full-plaintext and current-protection verification before sharing an encrypted layout.

use super::{
    BTreeSet, CodingScheme, CompletedStage, ContentAcknowledgementClass,
    ContentAcknowledgementEvidence, ContentPublicationError, ContentPublicationRequest,
    ContentReadError, ContentReadRequest, ContentShardRouter, ContractError, DurableContentReader,
    FailureScenario, ManifestPublication, PlacementPolicy, ProtectedContentPublisher,
    ProtectionConfiguration, ProtectionPolicySource, RandomSource, VolumeContentKeys, map_catalog,
    map_contract,
};
use crate::{PublishedContentReference, VerifiedContentReuse};
use std::io::Write;

impl<Router, Coding, Placement, Random, Keys, Policies>
    ProtectedContentPublisher<Router, Coding, Placement, Random, Keys, Policies>
where
    Router: ContentShardRouter,
    Coding: CodingScheme,
    Placement: PlacementPolicy,
    Random: RandomSource,
    Keys: VolumeContentKeys,
    Policies: ProtectionPolicySource,
{
    pub(super) fn verify_existing_layout(
        &mut self,
        request: ContentPublicationRequest,
        candidate: ManifestPublication,
        completed: CompletedStage,
    ) -> Result<Option<VerifiedContentReuse>, ContentPublicationError> {
        if candidate.format_version != 2
            || request.format_version != 2
            || completed.logical_length == 0
            || completed.logical_length != request.logical_length
            || candidate.logical_length != completed.logical_length
            || candidate.content_digest != completed.content_digest
        {
            return Ok(None);
        }
        let Some(content) = self
            .catalog
            .committed_content_by_manifest(candidate.manifest_id)
            .map_err(map_catalog)?
        else {
            return Ok(None);
        };
        if content.manifest != candidate {
            return Err(ContentPublicationError::Corrupt);
        }
        let layout = self
            .catalog
            .committed_layout(content)
            .map_err(map_catalog)?;
        if layout.request.volume_id != request.volume_id {
            return Ok(None);
        }
        let protection = self.policies.configuration(request.volume_id)?;
        let read = reuse_read(request, content);
        let Some((receipts, achieved)) = self.verify_reuse_protection(read, &protection)? else {
            return Ok(None);
        };
        let mut plaintext = PlaintextIdentity::default();
        match self.stream_range(read, &mut plaintext) {
            Ok(()) => {}
            Err(ContentReadError::Unavailable | ContentReadError::Corrupt) => return Ok(None),
            Err(error) => return Err(publication_read_error(error)),
        }
        if plaintext.bytes != completed.logical_length
            || plaintext.digest.finalize().as_bytes() != &completed.content_digest
        {
            return Ok(None);
        }
        Ok(Some(VerifiedContentReuse {
            request,
            content,
            evidence: ContentAcknowledgementEvidence {
                configured_class: protection.acknowledgement_policy.class,
                acknowledged_class: protection.acknowledgement_policy.class,
                fallback_applied: false,
                content_scope: protection.content_scope,
                required_shard_receipts: receipts,
                eventual_shard_receipts: 0,
                pending_eventual_shards: 0,
                policy_evidence_digest: protection.reuse_policy_digest(request),
                achieved_protection_digest: achieved,
                pending_debt_digest: *blake3::hash(b"meshspan.content-reuse.no-debt.v1\0")
                    .as_bytes(),
            },
        }))
    }

    fn verify_reuse_protection(
        &self,
        read: ContentReadRequest,
        protection: &ProtectionConfiguration,
    ) -> Result<Option<(u64, [u8; 32])>, ContentPublicationError> {
        let layout = self
            .catalog
            .committed_layout(read.content)
            .map_err(map_catalog)?;
        let count = read.length.div_ceil(layout.layout.chunk_bytes);
        let mut receipts = 0_u64;
        let mut achieved = blake3::Hasher::new();
        achieved.update(b"meshspan.content-reuse.verified-shards.v1\0");
        achieved.update(&read.operation_id.as_bytes());
        achieved.update(&read.content.manifest.root_digest);
        for index in 0..count {
            let stripe = self
                .catalog
                .active_protected_stripe(layout.request, read.content, index)
                .map_err(map_catalog)?;
            if !protection.reuse_satisfies(&self.placement, &stripe)? {
                return Ok(None);
            }
            for receipt in stripe.receipts.as_slice() {
                if self
                    .read_shard(read, *receipt)
                    .map_err(publication_read_error)?
                    .is_none()
                {
                    return Ok(None);
                }
                achieved.update(&receipt.target_id.as_bytes());
                achieved.update(&receipt.target_generation.to_be_bytes());
                achieved.update(&receipt.shard.stripe_index.to_be_bytes());
                achieved.update(&receipt.shard.shard_index.to_be_bytes());
                achieved.update(&receipt.length.to_be_bytes());
                achieved.update(&receipt.digest);
                receipts = receipts
                    .checked_add(1)
                    .ok_or(ContentPublicationError::Corrupt)?;
            }
        }
        Ok(Some((receipts, achieved.finalize().into())))
    }
}

impl ProtectionConfiguration {
    fn reuse_satisfies<Placement: PlacementPolicy>(
        &self,
        placement: &Placement,
        stripe: &crate::CommittedProtectedStripe,
    ) -> Result<bool, ContentPublicationError> {
        // The first implementation reuses only complete layouts, without inherited repair debt.
        if stripe.receipts.len() != usize::from(stripe.stripe.coding_layout().total_slices()) {
            return Ok(false);
        }
        let assessment = match self.assess_recorded(placement, stripe) {
            Ok(assessment) => assessment,
            Err(ContractError::InvalidInput) => return Ok(false),
            Err(error) => return Err(map_contract(error)),
        };
        if !assessment.sufficient_receipts
            || !assessment.protection_satisfied
            || !assessment.locality_satisfied
        {
            return Ok(false);
        }
        let targets = stripe
            .receipts
            .as_slice()
            .iter()
            .map(|receipt| receipt.target_id)
            .collect::<Vec<_>>();
        let hosts = targets
            .iter()
            .filter_map(|target| self.topology.target_host(*target))
            .collect::<BTreeSet<_>>();
        if targets.len() < usize::from(self.minimum_durable_targets)
            || hosts.len() < usize::from(self.minimum_distinct_nodes)
        {
            return Ok(false);
        }
        if self.required_scenarios.is_empty() {
            return Ok(true);
        }
        let required = placement
            .assess_recorded(meshspan_contracts::PlacementAssessmentRequest {
                coding_layout: stripe.stripe.coding_layout(),
                recorded_targets: &targets,
                scenarios: &self.required_scenarios,
                topology: &self.topology,
                candidates: &self.candidates,
                cells: &self.cells,
            })
            .map_err(map_contract)?;
        Ok(required.sufficient_receipts
            && required.protection_satisfied
            && required.locality_satisfied)
    }

    fn reuse_policy_digest(&self, request: ContentPublicationRequest) -> [u8; 32] {
        let mut digest = blake3::Hasher::new();
        digest.update(b"meshspan.content-reuse.policy.v1\0");
        digest.update(&request.operation_id.as_bytes());
        digest.update(&request.request_digest);
        digest.update(&self.topology_revision.get().to_be_bytes());
        digest.update(&self.capacity_revision.get().to_be_bytes());
        digest.update(&self.minimum_durable_targets.to_be_bytes());
        digest.update(&self.minimum_distinct_nodes.to_be_bytes());
        digest.update(&[match self.acknowledgement_policy.class {
            ContentAcknowledgementClass::Eventual => 1,
            ContentAcknowledgementClass::Strong => 2,
        }]);
        hash_scenarios(&mut digest, &self.scenarios);
        hash_scenarios(&mut digest, &self.required_scenarios);
        for cell in &self.cells {
            digest.update(&[1]);
            digest.update(&cell.cell_id.as_bytes());
            digest.update(&[
                match cell.role {
                    meshspan_contracts::PlacementCellRole::RequiredBeforeCommit => 1,
                    meshspan_contracts::PlacementCellRole::Eventual => 2,
                    meshspan_contracts::PlacementCellRole::Excluded => 3,
                },
                u8::from(cell.complete_local),
            ]);
            digest.update(&cell.minimum_durable_targets.unwrap_or(0).to_be_bytes());
            digest.update(&cell.minimum_distinct_nodes.unwrap_or(0).to_be_bytes());
            hash_scenarios(&mut digest, cell.local_scenarios.as_slice());
        }
        digest.update(&[0]);
        digest.finalize().into()
    }
}

fn hash_scenarios(digest: &mut blake3::Hasher, scenarios: &[FailureScenario]) {
    for scenario in scenarios {
        digest.update(&[1]);
        for term in scenario.terms() {
            digest.update(&[1]);
            digest.update(&term.class_id.as_bytes());
            digest.update(&term.failure_count.to_be_bytes());
        }
        digest.update(&[0]);
    }
    digest.update(&[0]);
}

fn reuse_read(
    request: ContentPublicationRequest,
    content: PublishedContentReference,
) -> ContentReadRequest {
    ContentReadRequest {
        operation_id: request.operation_id,
        content,
        offset: 0,
        length: content.manifest.logical_length,
        authorization_revision: request.authorization_revision,
        deadline: request.deadline,
        observed_at: request.observed_at,
    }
}

#[derive(Default)]
struct PlaintextIdentity {
    digest: blake3::Hasher,
    bytes: u64,
}

impl Write for PlaintextIdentity {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.bytes = self
            .bytes
            .checked_add(u64::try_from(bytes.len()).map_err(std::io::Error::other)?)
            .ok_or_else(|| std::io::Error::other("content identity length overflow"))?;
        self.digest.update(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn publication_read_error(error: ContentReadError) -> ContentPublicationError {
    match error {
        ContentReadError::InvalidInput => ContentPublicationError::InvalidInput,
        ContentReadError::Conflict => ContentPublicationError::Conflict,
        ContentReadError::Corrupt => ContentPublicationError::Corrupt,
        ContentReadError::Unavailable => ContentPublicationError::Unavailable,
        ContentReadError::Io(error) => ContentPublicationError::Io(error),
    }
}
