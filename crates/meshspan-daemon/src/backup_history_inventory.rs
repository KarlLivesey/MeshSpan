// SPDX-License-Identifier: GPL-2.0-only

use meshspan_api_contract::{
    BackupRunStatus, BackupRunSummary, ListBackupRunsQuery, ListBackupRunsResponse,
};
use meshspan_domain::PrincipalId;
use meshspan_metadata::{
    AuthoritativeRepository, MetadataBackupRun, MetadataBackupRunState, PageLimit,
};

use crate::backup_schedule_administration::BackupScheduleError as Error;
use crate::create_mesh_setup::format_uuid;

pub(super) fn list(
    repository: &AuthoritativeRepository,
    principal: PrincipalId,
    query: &ListBackupRunsQuery,
) -> Result<ListBackupRunsResponse, Error> {
    meshspan_api_contract::validate_list_backup_runs_query(query)
        .map_err(|_| Error::InvalidInput)?;
    let limit = query.limit.unwrap_or(25);
    let prefix = format!(
        "v1.bkr.{}.{}.{limit}.",
        format_uuid(repository.partition_id().as_bytes()),
        format_uuid(principal.as_bytes())
    );
    let revision = repository
        .current_revision()
        .map_err(|_| Error::Failed)?
        .get();
    let before = query
        .cursor
        .as_ref()
        .map(|cursor| {
            let suffix = cursor.strip_prefix(&prefix).ok_or(Error::InvalidInput)?;
            let (observed, sequence) = suffix.split_once('.').ok_or(Error::InvalidInput)?;
            let observed = positive_decimal(observed)?;
            if observed > revision {
                return Err(Error::InvalidInput);
            }
            positive_decimal(sequence)
        })
        .transpose()?;
    let page = repository
        .metadata_backup_runs(
            before,
            PageLimit::new(usize::from(limit)).map_err(|_| Error::InvalidInput)?,
        )
        .map_err(|_| Error::Failed)?;
    let response = ListBackupRunsResponse {
        runs: page.items.into_iter().map(project).collect(),
        next_page_url: page.next.map(|sequence| {
            format!(
                "/api/latest/admin/backups/runs?limit={limit}&cursor={prefix}{revision}.{sequence}"
            )
        }),
    };
    meshspan_api_contract::encode_list_backup_runs_response(&response)
        .map_err(|_| Error::Failed)?;
    Ok(response)
}

fn positive_decimal(value: &str) -> Result<u64, Error> {
    let parsed = value.parse::<i64>().map_err(|_| Error::InvalidInput)?;
    if parsed <= 0 || parsed.to_string() != value {
        return Err(Error::InvalidInput);
    }
    u64::try_from(parsed).map_err(|_| Error::InvalidInput)
}

fn project(run: MetadataBackupRun) -> BackupRunSummary {
    BackupRunSummary {
        backup_id: format_uuid(run.backup_id.as_bytes()),
        run_sequence: run.run_sequence.to_string(),
        schedule_sequence: run.schedule_sequence.to_string(),
        scheduled_for_epoch_micros: run.scheduled_for.get(),
        completed_at_epoch_micros: run.completed_at.map(meshspan_domain::UnixMicros::get),
        state: match run.state {
            MetadataBackupRunState::Queued => BackupRunStatus::Queued,
            MetadataBackupRunState::Claimed => BackupRunStatus::Claimed,
            MetadataBackupRunState::Recorded => BackupRunStatus::Recorded,
            MetadataBackupRunState::Protected => BackupRunStatus::Protected,
            MetadataBackupRunState::Incomplete => BackupRunStatus::Incomplete,
        },
        minimum_verified_copies: run.minimum_verified_copies,
        minimum_independent_copies: run.minimum_independent_copies,
    }
}

pub(crate) fn parse_query(raw: Option<&str>) -> Result<ListBackupRunsQuery, Error> {
    let raw = raw.unwrap_or_default();
    if raw.len() > 512 || !crate::native_query::has_valid_percent_encoding(raw.as_bytes()) {
        return Err(Error::InvalidInput);
    }
    let mut query = ListBackupRunsQuery::default();
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
    meshspan_api_contract::validate_list_backup_runs_query(&query)
        .map_err(|_| Error::InvalidInput)?;
    Ok(query)
}
