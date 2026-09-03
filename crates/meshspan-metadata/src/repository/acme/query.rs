// SPDX-License-Identifier: GPL-2.0-only

//! Complete ACME configuration reads and bounded actionable-order admission.

use meshspan_contracts::BoundedItems;
use meshspan_domain::{AcmeConfigurationId, CertificateOrderId, Revision, UnixMicros};
use rusqlite::{OptionalExtension, params};

use super::{
    AcmeChallengeKind, CertificateOrderRecord, MAXIMUM_CERTIFICATE_NAMES, ORDER_CLAIMED,
    ORDER_QUEUED, SecretGenerationReference, decode_order_inner, exact, positive,
    validate_configuration,
};
use crate::PartitionDatabase;
use crate::repository::{Page, PageLimit, RepositoryError};

/// Complete immutable configuration required to execute one certificate order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AcmeConfigurationRecord {
    /// Stable configuration revision identity.
    pub config_id: AcmeConfigurationId,
    /// Validated HTTPS ACME directory endpoint.
    pub directory_url: String,
    /// Exact encrypted ACME account-key generation.
    pub account_key: SecretGenerationReference,
    /// HTTP-01 or DNS-01 challenge family.
    pub challenge_kind: AcmeChallengeKind,
    /// Optional encrypted automatic DNS publisher settings.
    pub challenge_settings: Option<SecretGenerationReference>,
    /// Canonical, sorted, lower-case certificate names.
    pub certificate_names: Vec<String>,
    /// Immutable authoritative configuration revision.
    pub revision: Revision,
}

/// Stable seek position in the actionable certificate-order index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DueCertificateOrderCursor {
    next_attempt_at: UnixMicros,
    created_at: UnixMicros,
    order_id: CertificateOrderId,
}

/// Latest completed certificate generation eligible for automatic renewal.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertificateRenewalCandidate {
    /// Completed order whose certificate is approaching expiry.
    pub source_order_id: CertificateOrderId,
    /// Immutable configuration reused by the replacement order.
    pub config_id: AcmeConfigurationId,
    /// Exact validated expiry of the currently selected generation.
    pub not_after: UnixMicros,
    /// Latest authoritative revision of the completed source order.
    pub revision: Revision,
}

/// Stable seek position in the automatic certificate-renewal index.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DueCertificateRenewalCursor {
    not_after: UnixMicros,
    completed_at: UnixMicros,
    source_order_id: CertificateOrderId,
}

impl DueCertificateRenewalCursor {
    /// Reconstructs a cursor after a public boundary validates its fields.
    #[must_use]
    pub const fn new(
        not_after: UnixMicros,
        completed_at: UnixMicros,
        source_order_id: CertificateOrderId,
    ) -> Self {
        Self {
            not_after,
            completed_at,
            source_order_id,
        }
    }

    /// Returns the certificate-expiry seek key.
    #[must_use]
    pub const fn not_after(self) -> UnixMicros {
        self.not_after
    }

    /// Returns the completed-at seek key.
    #[must_use]
    pub const fn completed_at(self) -> UnixMicros {
        self.completed_at
    }

    /// Returns the final stable source-order seek key.
    #[must_use]
    pub const fn source_order_id(self) -> CertificateOrderId {
        self.source_order_id
    }
}

impl DueCertificateOrderCursor {
    /// Reconstructs a cursor after a public boundary validates its fields.
    #[must_use]
    pub const fn new(
        next_attempt_at: UnixMicros,
        created_at: UnixMicros,
        order_id: CertificateOrderId,
    ) -> Self {
        Self {
            next_attempt_at,
            created_at,
            order_id,
        }
    }

    /// Returns the earliest-attempt seek key.
    #[must_use]
    pub const fn next_attempt_at(self) -> UnixMicros {
        self.next_attempt_at
    }

    /// Returns the original creation seek key.
    #[must_use]
    pub const fn created_at(self) -> UnixMicros {
        self.created_at
    }

    /// Returns the final stable identity seek key.
    #[must_use]
    pub const fn order_id(self) -> CertificateOrderId {
        self.order_id
    }
}

pub(super) fn configuration(
    database: &PartitionDatabase,
    config_id: AcmeConfigurationId,
) -> Result<Option<AcmeConfigurationRecord>, RepositoryError> {
    let stored = database
        .connection()
        .query_row(
            "SELECT directory_url, account_key_secret_id, account_key_secret_generation,
                    challenge_kind, challenge_settings_secret_id,
                    challenge_settings_secret_generation, revision
             FROM acme_configurations WHERE config_id = ?1",
            [config_id.as_bytes().as_slice()],
            |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, Option<Vec<u8>>>(4)?,
                    row.get::<_, Option<i64>>(5)?,
                    row.get::<_, i64>(6)?,
                ))
            },
        )
        .optional()?;
    let Some(stored) = stored else {
        return Ok(None);
    };
    let certificate_names = configuration_names(database, config_id)?;
    let account_key = SecretGenerationReference {
        secret_id: exact(stored.1)?,
        generation: positive(stored.2)?,
    };
    let challenge_kind = parse_challenge_kind(stored.3)?;
    let challenge_settings = parse_optional_secret(stored.4, stored.5)?;
    let candidate = crate::ConfigureAcme {
        config_id,
        directory_url: stored.0,
        account_key,
        challenge_kind,
        challenge_settings,
        certificate_names: BoundedItems::new(certificate_names.clone(), MAXIMUM_CERTIFICATE_NAMES)
            .map_err(|_| RepositoryError::CorruptState)?,
    };
    validate_configuration(&candidate).map_err(|_| RepositoryError::CorruptState)?;
    Ok(Some(AcmeConfigurationRecord {
        config_id,
        directory_url: candidate.directory_url,
        account_key,
        challenge_kind,
        challenge_settings,
        certificate_names,
        revision: Revision::new(positive(stored.6)?),
    }))
}

pub(super) fn due_orders(
    database: &PartitionDatabase,
    now: UnixMicros,
    after: Option<&DueCertificateOrderCursor>,
    limit: PageLimit,
) -> Result<Page<CertificateOrderRecord, DueCertificateOrderCursor>, RepositoryError> {
    let lower_attempt = after.map_or(i64::MIN, |cursor| cursor.next_attempt_at.get());
    let lower_created = after.map_or(i64::MIN, |cursor| cursor.created_at.get());
    let lower_id = after.map_or([0; 16], |cursor| cursor.order_id.as_bytes());
    let sql_limit = i64::try_from(limit.get().saturating_add(1))
        .map_err(|_| RepositoryError::InvalidPageLimit)?;
    let mut statement = database.connection().prepare(
        "SELECT o.order_id, o.config_id, o.state, o.next_attempt_at, o.attempt_count,
                o.certificate_secret_id, o.certificate_secret_generation, o.revision,
                c.claim_generation, c.worker_node_id, c.worker_incarnation, c.fence,
                c.lease_expires_at, o.created_at
         FROM certificate_orders o
         LEFT JOIN certificate_order_claims c
           ON c.order_id = o.order_id AND c.state = 1
         WHERE o.next_attempt_at <= ?1
           AND (o.state = ?2 OR (o.state = ?3 AND c.lease_expires_at <= ?1))
           AND (o.next_attempt_at, o.created_at, o.order_id) > (?4, ?5, ?6)
         ORDER BY o.next_attempt_at, o.created_at, o.order_id
         LIMIT ?7",
    )?;
    let rows = statement.query_map(
        params![
            now.get(),
            ORDER_QUEUED,
            ORDER_CLAIMED,
            lower_attempt,
            lower_created,
            lower_id.as_slice(),
            sql_limit,
        ],
        |row| {
            let order = decode_order_inner(row).map_err(|_| rusqlite::Error::InvalidQuery)?;
            let created_at = UnixMicros::new(row.get(13)?);
            Ok((order, created_at))
        },
    )?;
    let mut records = Vec::with_capacity(limit.get().saturating_add(1));
    for row in rows {
        records.push(row?);
    }
    let next = (records.len() > limit.get()).then(|| cursor(&records[limit.get() - 1]));
    records.truncate(limit.get());
    Ok(Page {
        items: records.into_iter().map(|(record, _)| record).collect(),
        next,
    })
}

pub(super) fn due_renewals(
    database: &PartitionDatabase,
    renew_by: UnixMicros,
    after: Option<&DueCertificateRenewalCursor>,
    limit: PageLimit,
) -> Result<Page<CertificateRenewalCandidate, DueCertificateRenewalCursor>, RepositoryError> {
    let lower_expiry = after.map_or(i64::MIN, |cursor| cursor.not_after.get());
    let lower_completed = after.map_or(i64::MIN, |cursor| cursor.completed_at.get());
    let lower_id = after.map_or([0; 16], |cursor| cursor.source_order_id.as_bytes());
    let sql_limit = i64::try_from(limit.get().saturating_add(1))
        .map_err(|_| RepositoryError::InvalidPageLimit)?;
    let mut statement = database.connection().prepare(
        "SELECT o.order_id, o.config_id, o.certificate_not_after, o.completed_at, o.revision
         FROM certificate_orders o
         WHERE o.state = 3
           AND o.certificate_not_after <= ?1
           AND NOT EXISTS (
               SELECT 1 FROM certificate_orders active
               WHERE active.config_id = o.config_id AND active.state IN (1, 2)
           )
           AND NOT EXISTS (
               SELECT 1 FROM certificate_orders newer
               WHERE newer.config_id = o.config_id
                 AND newer.state = 3
                 AND (newer.completed_at, newer.order_id) > (o.completed_at, o.order_id)
           )
           AND (o.certificate_not_after, o.completed_at, o.order_id) > (?2, ?3, ?4)
         ORDER BY o.certificate_not_after, o.completed_at, o.order_id
         LIMIT ?5",
    )?;
    let rows = statement.query_map(
        params![
            renew_by.get(),
            lower_expiry,
            lower_completed,
            lower_id.as_slice(),
            sql_limit,
        ],
        |row| {
            let source_order_bytes =
                exact(row.get(0)?).map_err(|_| rusqlite::Error::InvalidQuery)?;
            let source_order_id = CertificateOrderId::from_bytes(source_order_bytes)
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
            let config_bytes = exact(row.get(1)?).map_err(|_| rusqlite::Error::InvalidQuery)?;
            let config_id = AcmeConfigurationId::from_bytes(config_bytes)
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
            let not_after = UnixMicros::new(row.get(2)?);
            let completed_at = UnixMicros::new(row.get(3)?);
            let revision =
                Revision::new(positive(row.get(4)?).map_err(|_| rusqlite::Error::InvalidQuery)?);
            Ok((
                CertificateRenewalCandidate {
                    source_order_id,
                    config_id,
                    not_after,
                    revision,
                },
                completed_at,
            ))
        },
    )?;
    let mut records = Vec::with_capacity(limit.get().saturating_add(1));
    for row in rows {
        records.push(row?);
    }
    let next = (records.len() > limit.get()).then(|| renewal_cursor(&records[limit.get() - 1]));
    records.truncate(limit.get());
    Ok(Page {
        items: records.into_iter().map(|(record, _)| record).collect(),
        next,
    })
}

fn configuration_names(
    database: &PartitionDatabase,
    config_id: AcmeConfigurationId,
) -> Result<Vec<String>, RepositoryError> {
    let mut statement = database.connection().prepare(
        "SELECT dns_name FROM acme_configuration_names
         WHERE config_id = ?1 ORDER BY ordinal LIMIT ?2",
    )?;
    let rows = statement.query_map(
        params![
            config_id.as_bytes().as_slice(),
            i64::try_from(MAXIMUM_CERTIFICATE_NAMES.saturating_add(1))
                .map_err(|_| RepositoryError::CapacityExceeded)?,
        ],
        |row| row.get::<_, String>(0),
    )?;
    let names = rows.collect::<Result<Vec<_>, _>>()?;
    if names.is_empty() || names.len() > MAXIMUM_CERTIFICATE_NAMES {
        return Err(RepositoryError::CorruptState);
    }
    Ok(names)
}

fn parse_challenge_kind(value: i64) -> Result<AcmeChallengeKind, RepositoryError> {
    match value {
        1 => Ok(AcmeChallengeKind::Http01),
        2 => Ok(AcmeChallengeKind::Dns01),
        _ => Err(RepositoryError::CorruptState),
    }
}

fn parse_optional_secret(
    id: Option<Vec<u8>>,
    generation: Option<i64>,
) -> Result<Option<SecretGenerationReference>, RepositoryError> {
    match (id, generation) {
        (None, None) => Ok(None),
        (Some(id), Some(generation)) => Ok(Some(SecretGenerationReference {
            secret_id: exact(id)?,
            generation: positive(generation)?,
        })),
        _ => Err(RepositoryError::CorruptState),
    }
}

fn cursor(value: &(CertificateOrderRecord, UnixMicros)) -> DueCertificateOrderCursor {
    DueCertificateOrderCursor::new(value.0.next_attempt_at, value.1, value.0.order_id)
}

fn renewal_cursor(
    value: &(CertificateRenewalCandidate, UnixMicros),
) -> DueCertificateRenewalCursor {
    DueCertificateRenewalCursor::new(value.0.not_after, value.1, value.0.source_order_id)
}
