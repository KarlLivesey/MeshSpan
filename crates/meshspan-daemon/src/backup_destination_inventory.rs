// SPDX-License-Identifier: GPL-2.0-only

//! Bounded live inventory and caller-bound keyset continuations.

use meshspan_api_contract::{
    BackupDestinationFailureRelationship as Failure, BackupDestinationProvider as Provider,
    BackupDestinationStatus as State, BackupDestinationSummary, ListBackupDestinationsQuery,
    ListBackupDestinationsResponse,
};
use meshspan_domain::{BackupDestinationId, PrincipalId};
use meshspan_metadata::{
    AuthoritativeRepository, BackupDestinationBinding as Binding, BackupDestinationCursor,
    BackupDestinationRecord, BackupDestinationState, BackupFailureRelationship, PageLimit,
};

use super::BackupDestinationError as Error;
use crate::create_mesh_setup::{format_uuid, parse_uuid};

pub(super) fn list(
    repository: &AuthoritativeRepository,
    principal: PrincipalId,
    query: &ListBackupDestinationsQuery,
) -> Result<ListBackupDestinationsResponse, Error> {
    meshspan_api_contract::validate_list_backup_destinations_query(query)
        .map_err(|_| Error::InvalidInput)?;
    let limit = query.limit.unwrap_or(50);
    let prefix = format!(
        "v1.bkd.{}.{}.{limit}.",
        format_uuid(repository.partition_id().as_bytes()),
        format_uuid(principal.as_bytes())
    );
    let revision = repository
        .current_revision()
        .map_err(|_| Error::Failed)?
        .get();
    let after = query
        .cursor
        .as_ref()
        .map(|cursor| {
            let suffix = cursor.strip_prefix(&prefix).ok_or(Error::InvalidInput)?;
            let (observed, identity) = suffix.split_once('.').ok_or(Error::InvalidInput)?;
            let observed_revision = observed.parse::<u64>().map_err(|_| Error::InvalidInput)?;
            // A continuation may observe newer settings, but never a projection older
            // than its previous page. Current permissions are rechecked independently.
            if observed_revision == 0
                || observed_revision > revision
                || observed_revision.to_string() != observed
            {
                return Err(Error::InvalidInput);
            }
            let destination_id = BackupDestinationId::from_bytes(
                parse_uuid(identity).map_err(|_| Error::InvalidInput)?,
            )
            .map_err(|_| Error::InvalidInput)?;
            Ok::<_, Error>(BackupDestinationCursor { destination_id })
        })
        .transpose()?;
    let page = repository
        .backup_destinations(
            after,
            PageLimit::new(usize::from(limit)).map_err(|_| Error::InvalidInput)?,
        )
        .map_err(|_| Error::Failed)?;
    let next_page_url = page.next.map(|cursor| {
        format!(
            "/api/latest/admin/backups/destinations?limit={limit}&cursor={prefix}{revision}.{}",
            format_uuid(cursor.destination_id.as_bytes())
        )
    });
    let response = ListBackupDestinationsResponse {
        destinations: page.items.into_iter().map(project).collect(),
        next_page_url,
    };
    meshspan_api_contract::encode_list_backup_destinations_response(&response)
        .map_err(|_| Error::Failed)?;
    Ok(response)
}

fn project(record: BackupDestinationRecord) -> BackupDestinationSummary {
    let provider = match record.binding {
        Binding::RegisteredTarget { target_id, .. } => Provider::RegisteredTarget {
            target_id: format_uuid(target_id.as_bytes()),
        },
        Binding::FederatedMesh { remote_mesh_id, .. } => Provider::FederatedMesh {
            remote_mesh_id: format_uuid(remote_mesh_id.as_bytes()),
        },
        Binding::ComponentProvider { instance_id, .. } => Provider::ComponentProvider {
            instance_id: format_uuid(instance_id.as_bytes()),
        },
    };
    BackupDestinationSummary {
        destination_id: format_uuid(record.destination_id.as_bytes()),
        name: record.display_name,
        provider,
        provider_generation: record.binding.provider_generation().to_string(),
        state: match record.state {
            BackupDestinationState::Active => State::Active,
            BackupDestinationState::Paused => State::Paused,
            BackupDestinationState::Retired => State::Retired,
        },
        failure_relationship: match record.failure_relationship {
            BackupFailureRelationship::Unknown => Failure::Unknown,
            BackupFailureRelationship::Overlapping => Failure::Overlapping,
            BackupFailureRelationship::Independent => Failure::Independent,
        },
        revision: record.revision.get(),
    }
}

/// Query fields are converted explicitly, never through permissive JSON coercion.
pub(crate) fn parse_query(raw: Option<&str>) -> Result<ListBackupDestinationsQuery, Error> {
    let raw = raw.unwrap_or_default();
    if raw.len() > 512 || !crate::native_query::has_valid_percent_encoding(raw.as_bytes()) {
        return Err(Error::InvalidInput);
    }
    let mut query = ListBackupDestinationsQuery::default();
    for (name, value) in form_urlencoded::parse(raw.as_bytes()) {
        match name.as_ref() {
            "limit"
                if query.limit.is_none()
                    && !value.is_empty()
                    && value.bytes().all(|byte| byte.is_ascii_digit()) =>
            {
                query.limit = Some(value.parse().map_err(|_| Error::InvalidInput)?);
            }
            "cursor" if query.cursor.is_none() => query.cursor = Some(value.into_owned()),
            _ => return Err(Error::InvalidInput),
        }
    }
    meshspan_api_contract::validate_list_backup_destinations_query(&query)
        .map_err(|_| Error::InvalidInput)?;
    Ok(query)
}
