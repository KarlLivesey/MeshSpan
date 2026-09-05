// SPDX-License-Identifier: GPL-2.0-only

//! Replaceable destination resolution for metadata-backup placement.

use std::collections::BTreeMap;

use meshspan_backup::{
    DirectoryBackupProvider, DirectoryBackupProviderError, SharedBackupProvider,
};
use meshspan_contracts::BackupProvider;
use meshspan_domain::{BackupDestinationId, TargetId};
use meshspan_metadata::{BackupDestinationBinding, BackupDestinationRecord};
use thiserror::Error;

use crate::{
    BackupPublicationAuthority, BackupPublicationError, BackupPublicationOutcome,
    BackupPublicationRequest, MetadataBackupDestinationWriter, MetadataBackupPublisher,
};

/// Resolves one exact replicated destination binding to a live provider implementation.
pub trait MetadataBackupProviderResolver {
    /// Returns a provider fenced to the destination's exact identity and generation.
    ///
    /// # Errors
    ///
    /// Rejects unsupported, unavailable, stale or contradictory bindings before provider IO.
    fn resolve(
        &mut self,
        destination: &BackupDestinationRecord,
    ) -> Result<Box<dyn BackupProvider>, MetadataBackupProviderResolutionError>;
}

/// One already opened destination shared with the incoming backup service.
#[derive(Clone)]
pub struct RegisteredBackupTarget {
    /// Exact destination whose provider is shared.
    pub destination_id: BackupDestinationId,
    /// Exact replicated target identity.
    pub target_id: TargetId,
    /// Current marker-fenced generation.
    pub target_generation: u64,
    /// Sole owner of the destination catalogue, never reopened by the resolver.
    pub provider: SharedBackupProvider<DirectoryBackupProvider>,
}

/// In-process resolver for exact registered-folder backup destinations.
pub struct RegisteredTargetBackupProviderResolver {
    targets: BTreeMap<BackupDestinationId, RegisteredBackupTarget>,
}

impl RegisteredTargetBackupProviderResolver {
    /// Validates one finite active-target inventory before any destination is resolved.
    ///
    /// # Errors
    ///
    /// Rejects duplicate destination identities or zero target generations.
    pub fn new(
        targets: impl IntoIterator<Item = RegisteredBackupTarget>,
    ) -> Result<Self, MetadataBackupProviderResolutionError> {
        let mut indexed = BTreeMap::new();
        for target in targets {
            if target.target_generation == 0
                || indexed.insert(target.destination_id, target).is_some()
            {
                return Err(MetadataBackupProviderResolutionError::Invalid);
            }
        }
        Ok(Self { targets: indexed })
    }
}

impl MetadataBackupProviderResolver for RegisteredTargetBackupProviderResolver {
    fn resolve(
        &mut self,
        destination: &BackupDestinationRecord,
    ) -> Result<Box<dyn BackupProvider>, MetadataBackupProviderResolutionError> {
        let BackupDestinationBinding::RegisteredTarget {
            target_id,
            target_generation,
        } = destination.binding
        else {
            return Err(MetadataBackupProviderResolutionError::Unsupported);
        };
        let target = self
            .targets
            .get(&destination.destination_id)
            .ok_or(MetadataBackupProviderResolutionError::Unavailable)?;
        if target.target_id != target_id || target.target_generation != target_generation {
            return Err(MetadataBackupProviderResolutionError::Stale);
        }
        Ok(Box::new(target.provider.clone()))
    }
}

/// Destination writer which composes generic placement with generic provider resolution.
pub struct ResolvingMetadataBackupDestinationWriter<'a, Authority, Resolver> {
    publisher: MetadataBackupPublisher<'a, Authority>,
    resolver: &'a mut Resolver,
}

impl<'a, Authority, Resolver> ResolvingMetadataBackupDestinationWriter<'a, Authority, Resolver> {
    /// Binds an authoritative publisher to one runtime provider resolver.
    #[must_use]
    pub const fn new(authority: &'a Authority, resolver: &'a mut Resolver) -> Self {
        Self {
            publisher: MetadataBackupPublisher::new(authority),
            resolver,
        }
    }
}

impl<Authority, Resolver> MetadataBackupDestinationWriter
    for ResolvingMetadataBackupDestinationWriter<'_, Authority, Resolver>
where
    Authority: BackupPublicationAuthority,
    Resolver: MetadataBackupProviderResolver,
{
    fn publish_destination(
        &mut self,
        destination: &BackupDestinationRecord,
        request: &BackupPublicationRequest<'_>,
    ) -> Result<BackupPublicationOutcome, BackupPublicationError> {
        if destination.destination_id != request.destination_id
            || destination.binding.provider_generation() == 0
        {
            return Err(BackupPublicationError::InvalidProjection);
        }
        let mut provider = self.resolver.resolve(destination)?;
        self.publisher.publish(provider.as_mut(), request)
    }
}

/// Closed provider-resolution failure before any backup bytes are sent.
#[derive(Debug, Error)]
pub enum MetadataBackupProviderResolutionError {
    /// This build has no implementation for the configured binding kind.
    #[error("metadata backup destination provider is unsupported")]
    Unsupported,
    /// The exact provider is temporarily unavailable.
    #[error("metadata backup destination provider is unavailable")]
    Unavailable,
    /// Runtime provider identity or generation contradicts replicated configuration.
    #[error("metadata backup destination provider binding is stale")]
    Stale,
    /// Replicated or local provider configuration is malformed.
    #[error("metadata backup destination provider configuration is invalid")]
    Invalid,
    /// The local directory provider failed to open safely.
    #[error("metadata backup directory provider failed")]
    Directory(#[from] DirectoryBackupProviderError),
}
