// SPDX-License-Identifier: GPL-2.0-only

//! Immutable ACME configuration and single-worker fenced certificate orders.

mod order_checkpoint;
mod query;

use meshspan_domain::{AcmeConfigurationId, CertificateOrderId, NodeId, Revision, UnixMicros};
use rusqlite::{OptionalExtension, Row, Transaction, params};
use sha2::{Digest, Sha256};

use super::apply::to_i64;
use super::{AuthoritativeRepository, EntityKind, EntityReference, RepositoryError};
use crate::{
    ACME_ACCOUNT_KEY_SECRET_KIND, ACME_CHALLENGE_SETTINGS_SECRET_KIND,
    AcknowledgePublicCertificateInstallation, AcmeChallengeKind, CertificateOrderCompletion,
    ClaimCertificateOrder, CommandContext, CompleteCertificateOrder, ConfigureAcme,
    PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND, ProvisionAcme, QueueCertificateOrder,
    RenewCertificateOrder, SecretGenerationReference,
};

pub use order_checkpoint::CertificateOrderCheckpointRecord;
pub(super) use order_checkpoint::checkpoint;
pub use query::{
    AcmeConfigurationRecord, CertificateRenewalCandidate, DueCertificateOrderCursor,
    DueCertificateRenewalCursor, PublicCertificateSelection, PublicCertificateSource,
};

const ORDER_QUEUED: i64 = 1;
const ORDER_CLAIMED: i64 = 2;
const ORDER_COMPLETE: i64 = 3;
const CLAIM_ACTIVE: i64 = 1;
const CLAIM_COMPLETE: i64 = 2;
const CLAIM_SUPERSEDED: i64 = 3;
const ACTIVE_NODE: i64 = 2;
const GATEWAY_ROLE_CODE: i64 = 2;
const MAXIMUM_LEASE_MICROS: i64 = 15 * 60 * 1_000_000;
const MAXIMUM_CERTIFICATE_NAMES: usize = 256;
const MAXIMUM_DIRECTORY_URL_BYTES: usize = 2_048;

/// Durable certificate-order lifecycle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CertificateOrderState {
    /// Awaiting an eligible worker and its earliest attempt instant.
    Queued,
    /// Owned by one unexpired fenced claim.
    Claimed,
    /// Bound to one validated encrypted certificate generation.
    Complete,
}

/// Current certificate-order execution claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertificateOrderClaim {
    /// Monotonic attempt generation.
    pub generation: u64,
    /// Exact worker node.
    pub worker_node_id: NodeId,
    /// Exact worker process incarnation.
    pub worker_incarnation: u64,
    /// Unpredictable live fence.
    pub fence: u64,
    /// Authority-agreed lease end.
    pub lease_expires_at: UnixMicros,
}

/// Exact durable ACME order state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CertificateOrderRecord {
    /// Stable order identity.
    pub order_id: CertificateOrderId,
    /// Immutable ACME configuration identity.
    pub config_id: AcmeConfigurationId,
    /// Current lifecycle.
    pub state: CertificateOrderState,
    /// Earliest next claim instant.
    pub next_attempt_at: UnixMicros,
    /// Total fenced attempts created.
    pub attempt_count: u64,
    /// Issued encrypted certificate generation, when complete.
    pub certificate: Option<SecretGenerationReference>,
    /// Current active claim.
    pub claim: Option<CertificateOrderClaim>,
    /// Latest authoritative revision.
    pub revision: Revision,
}

/// Durable proof that one gateway selected an exact certificate for new TLS handshakes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicCertificateInstallationRecord {
    /// Issued order whose bundle was installed.
    pub order_id: CertificateOrderId,
    /// Gateway which loaded and selected the bundle.
    pub gateway_node_id: NodeId,
    /// Gateway process incarnation which performed the installation.
    pub gateway_incarnation: u64,
    /// Exact encrypted certificate generation installed.
    pub certificate: SecretGenerationReference,
    /// Digest of the decrypted canonical bundle.
    pub bundle_digest: [u8; 32],
    /// Authority-agreed acknowledgement instant.
    pub installed_at: UnixMicros,
    /// Revision which committed the acknowledgement.
    pub revision: Revision,
}

/// Exact progress across all gateways encrypted into one issued generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PublicCertificateRolloutSummary {
    /// Completed certificate order.
    pub order_id: CertificateOrderId,
    /// Exact encrypted generation selected by the order.
    pub certificate: SecretGenerationReference,
    /// Canonical bundle digest every acknowledgement must match.
    pub bundle_digest: [u8; 32],
    /// Gateway recipients included in the immutable encrypted generation.
    pub required_gateway_count: u64,
    /// Required gateways which have durably acknowledged live selection.
    pub installed_gateway_count: u64,
    /// Whether every required gateway has acknowledged this exact generation.
    pub complete: bool,
    /// Authoritative order revision the rollout is based on.
    pub order_revision: Revision,
}

pub(super) fn configure(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: &ConfigureAcme,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_configuration(value)?;
    require_secret(transaction, ACME_ACCOUNT_KEY_SECRET_KIND, value.account_key)?;
    if let Some(settings) = value.challenge_settings {
        require_secret(transaction, ACME_CHALLENGE_SETTINGS_SECRET_KIND, settings)?;
    }
    transaction.execute(
        "INSERT INTO acme_configurations(
            config_id, directory_url, account_key_secret_id, account_key_secret_generation,
            challenge_kind, challenge_settings_secret_id,
            challenge_settings_secret_generation, created_by, created_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
        params![
            value.config_id.as_bytes().as_slice(),
            value.directory_url,
            value.account_key.secret_id.as_slice(),
            to_i64(value.account_key.generation)?,
            challenge_code(value.challenge_kind),
            value.challenge_settings.map(|secret| secret.secret_id),
            value
                .challenge_settings
                .map(|secret| to_i64(secret.generation))
                .transpose()?,
            context.actor_principal_id.as_bytes().as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    for (ordinal, name) in value.certificate_names.as_slice().iter().enumerate() {
        transaction.execute(
            "INSERT INTO acme_configuration_names(config_id, ordinal, dns_name)
             VALUES (?1, ?2, ?3)",
            params![
                value.config_id.as_bytes().as_slice(),
                i64::try_from(ordinal).map_err(|_| RepositoryError::CapacityExceeded)?,
                name,
            ],
        )?;
    }
    Ok(config_entity(value.config_id))
}

pub(super) fn provision(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: &ProvisionAcme,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    if value.initial_order.config_id != value.configuration.config_id
        || value.initial_order.next_attempt_at < context.occurred_at
        || value.intent_digest == [0; 32]
    {
        return Err(RepositoryError::InvalidCommand);
    }
    require_matching_generation(
        &value.account_key_generation,
        ACME_ACCOUNT_KEY_SECRET_KIND,
        value.configuration.account_key,
    )?;
    match (
        value.configuration.challenge_settings,
        value.challenge_settings_generation.as_deref(),
    ) {
        (None, None) => {}
        (Some(reference), Some(generation)) => {
            require_matching_generation(
                generation,
                ACME_CHALLENGE_SETTINGS_SECRET_KIND,
                reference,
            )?;
        }
        _ => return Err(RepositoryError::InvalidCommand),
    }

    super::secret_generation::commit(
        transaction,
        context,
        &value.account_key_generation,
        revision,
    )?;
    if let Some(settings) = &value.challenge_settings_generation {
        super::secret_generation::commit(transaction, context, settings, revision)?;
    }
    configure(transaction, context, &value.configuration, revision)?;
    transaction.execute(
        "UPDATE acme_configurations SET provisioning_intent_digest = ?1 WHERE config_id = ?2",
        params![
            value.intent_digest.as_slice(),
            value.configuration.config_id.as_bytes().as_slice()
        ],
    )?;
    queue(transaction, context, value.initial_order, revision)
}

fn require_matching_generation(
    generation: &crate::CommitSecretGeneration,
    expected_kind: u16,
    expected: SecretGenerationReference,
) -> Result<(), RepositoryError> {
    let context = generation.secret.context;
    if context.kind() == expected_kind
        && context.id() == expected.secret_id
        && context.generation() == expected.generation
    {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

pub(super) fn queue(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: QueueCertificateOrder,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    let config_exists = transaction.query_row(
        "SELECT EXISTS(SELECT 1 FROM acme_configurations WHERE config_id = ?1)",
        [value.config_id.as_bytes().as_slice()],
        |row| row.get::<_, i64>(0),
    )?;
    if config_exists != 1 || value.next_attempt_at < context.occurred_at {
        return Err(RepositoryError::InvalidCommand);
    }
    transaction.execute(
        "INSERT INTO certificate_orders(
            order_id, config_id, state, next_attempt_at, attempt_count,
            certificate_secret_id, certificate_secret_generation, certificate_not_before,
            certificate_not_after, completed_at, result_digest, created_by, created_at, revision
         ) VALUES (?1, ?2, ?3, ?4, 0, NULL, NULL, NULL, NULL, NULL, NULL, ?5, ?6, ?7)",
        params![
            value.order_id.as_bytes().as_slice(),
            value.config_id.as_bytes().as_slice(),
            ORDER_QUEUED,
            value.next_attempt_at.get(),
            context.actor_principal_id.as_bytes().as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(order_entity(value.order_id))
}

pub(super) fn claim(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: ClaimCertificateOrder,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_lease(context.occurred_at, value.lease_expires_at)?;
    validate_worker(transaction, value.worker_node_id, value.worker_incarnation)?;
    let (state, next_attempt_at) = order_transition_state(transaction, value.order_id)?;
    if state == ORDER_COMPLETE || next_attempt_at > context.occurred_at.get() {
        return Err(RepositoryError::InvalidCommand);
    }
    let active = active_claim(transaction, value.order_id)?;
    match (state, active) {
        (ORDER_QUEUED, None) => {}
        (ORDER_CLAIMED, Some(current))
            if current.lease_expires_at.get() <= context.occurred_at.get() =>
        {
            supersede_claim(transaction, context, value.order_id, current, revision)?;
        }
        (ORDER_QUEUED | ORDER_CLAIMED, _) => return Err(RepositoryError::InvalidCommand),
        _ => return Err(RepositoryError::CorruptState),
    }
    let expected_generation = latest_claim_generation(transaction, value.order_id)?
        .checked_add(1)
        .ok_or(RepositoryError::CapacityExceeded)?;
    if value.claim_generation != expected_generation || value.fence == 0 {
        return Err(RepositoryError::InvalidCommand);
    }
    transaction.execute(
        "INSERT INTO certificate_order_claims(
            order_id, claim_generation, worker_node_id, worker_incarnation, fence, claimed_at,
            lease_expires_at, state, finished_at, result_digest, retry_at, revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, NULL, NULL, NULL, ?9)",
        params![
            value.order_id.as_bytes().as_slice(),
            to_i64(value.claim_generation)?,
            value.worker_node_id.as_bytes().as_slice(),
            to_i64(value.worker_incarnation)?,
            to_i64(value.fence)?,
            context.occurred_at.get(),
            value.lease_expires_at.get(),
            CLAIM_ACTIVE,
            to_i64(revision.get())?,
        ],
    )?;
    let changed = transaction.execute(
        "UPDATE certificate_orders
         SET state = ?1, attempt_count = attempt_count + 1, revision = ?2
         WHERE order_id = ?3 AND state IN (?4, ?5)",
        params![
            ORDER_CLAIMED,
            to_i64(revision.get())?,
            value.order_id.as_bytes().as_slice(),
            ORDER_QUEUED,
            ORDER_CLAIMED,
        ],
    )?;
    exactly_one(changed)?;
    Ok(order_entity(value.order_id))
}

pub(super) fn renew(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: RenewCertificateOrder,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_lease(context.occurred_at, value.lease_expires_at)?;
    validate_worker(transaction, value.worker_node_id, value.worker_incarnation)?;
    let current = require_live_claim(
        transaction,
        context,
        value.order_id,
        value.claim_generation,
        value.worker_node_id,
        value.worker_incarnation,
        value.fence,
    )?;
    if value.lease_expires_at <= current.lease_expires_at {
        return Err(RepositoryError::InvalidCommand);
    }
    let changed = transaction.execute(
        "UPDATE certificate_order_claims SET lease_expires_at = ?1, revision = ?2
         WHERE order_id = ?3 AND claim_generation = ?4 AND state = ?5",
        params![
            value.lease_expires_at.get(),
            to_i64(revision.get())?,
            value.order_id.as_bytes().as_slice(),
            to_i64(value.claim_generation)?,
            CLAIM_ACTIVE,
        ],
    )?;
    exactly_one(changed)?;
    update_order_revision(transaction, value.order_id, revision)?;
    Ok(order_entity(value.order_id))
}

pub(super) fn complete(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: &CompleteCertificateOrder,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_worker(transaction, value.worker_node_id, value.worker_incarnation)?;
    require_live_claim(
        transaction,
        context,
        value.order_id,
        value.claim_generation,
        value.worker_node_id,
        value.worker_incarnation,
        value.fence,
    )?;
    let completion = completion_values(
        transaction,
        context,
        value.order_id,
        &value.outcome,
        revision,
    )?;
    let changed = transaction.execute(
        "UPDATE certificate_order_claims
         SET state = ?1, finished_at = ?2, result_digest = ?3, retry_at = ?4, revision = ?5
         WHERE order_id = ?6 AND claim_generation = ?7 AND state = ?8",
        params![
            CLAIM_COMPLETE,
            context.occurred_at.get(),
            completion.claim_digest.as_slice(),
            completion.retry_at,
            to_i64(revision.get())?,
            value.order_id.as_bytes().as_slice(),
            to_i64(value.claim_generation)?,
            CLAIM_ACTIVE,
        ],
    )?;
    exactly_one(changed)?;
    let changed = transaction.execute(
        "UPDATE certificate_orders SET
            state = ?1, next_attempt_at = ?2, certificate_secret_id = ?3,
            certificate_secret_generation = ?4, certificate_not_before = ?5,
            certificate_not_after = ?6, completed_at = ?7, result_digest = ?8, revision = ?9
         WHERE order_id = ?10 AND state = ?11",
        params![
            completion.order_state,
            completion.next_attempt_at,
            completion.certificate.map(|value| value.secret_id),
            completion
                .certificate
                .map(|value| to_i64(value.generation))
                .transpose()?,
            completion.not_before,
            completion.not_after,
            completion.completed_at,
            completion.order_digest.as_ref().map(<[u8; 32]>::as_slice),
            to_i64(revision.get())?,
            value.order_id.as_bytes().as_slice(),
            ORDER_CLAIMED,
        ],
    )?;
    exactly_one(changed)?;
    if matches!(&value.outcome, CertificateOrderCompletion::Issued { .. }) {
        transaction.execute(
            "DELETE FROM certificate_order_checkpoints WHERE order_id = ?1",
            [value.order_id.as_bytes().as_slice()],
        )?;
    }
    Ok(order_entity(value.order_id))
}

pub(super) fn acknowledge_installation(
    transaction: &Transaction<'_>,
    context: CommandContext,
    value: AcknowledgePublicCertificateInstallation,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    validate_worker(
        transaction,
        value.gateway_node_id,
        value.gateway_incarnation,
    )?;
    validate_installation_order(transaction, value)?;
    if let Some(existing) =
        existing_installation(transaction, value.order_id, value.gateway_node_id)?
    {
        if existing.gateway_incarnation == value.gateway_incarnation
            && existing.certificate == value.certificate
            && existing.bundle_digest == value.bundle_digest
        {
            return Ok(order_entity(value.order_id));
        }
        return Err(RepositoryError::InvalidCommand);
    }
    transaction.execute(
        "INSERT INTO public_certificate_installations(
            order_id, gateway_node_id, gateway_incarnation, certificate_secret_kind,
            certificate_secret_id, certificate_secret_generation, bundle_digest, installed_at,
            revision
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
        params![
            value.order_id.as_bytes().as_slice(),
            value.gateway_node_id.as_bytes().as_slice(),
            to_i64(value.gateway_incarnation)?,
            i64::from(PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND),
            value.certificate.secret_id.as_slice(),
            to_i64(value.certificate.generation)?,
            value.bundle_digest.as_slice(),
            context.occurred_at.get(),
            to_i64(revision.get())?,
        ],
    )?;
    Ok(order_entity(value.order_id))
}

impl AuthoritativeRepository {
    /// Returns one complete immutable ACME configuration revision.
    ///
    /// # Errors
    ///
    /// Fails closed when persisted secret references, challenge settings, names or revision are
    /// malformed.
    pub fn acme_configuration(
        &self,
        config_id: AcmeConfigurationId,
    ) -> Result<Option<AcmeConfigurationRecord>, RepositoryError> {
        query::configuration(&self.database, config_id)
    }

    /// Returns a bounded stable page of queued or expired-claim certificate orders due now.
    ///
    /// # Errors
    ///
    /// Rejects invalid limits and fails closed for malformed order or claim state.
    pub fn due_certificate_orders(
        &self,
        now: UnixMicros,
        after: Option<&DueCertificateOrderCursor>,
        limit: super::PageLimit,
    ) -> Result<super::Page<CertificateOrderRecord, DueCertificateOrderCursor>, RepositoryError>
    {
        query::due_orders(&self.database, now, after, limit)
    }

    /// Returns latest completed certificate generations whose renewal window has opened.
    ///
    /// A configuration with a queued or claimed replacement is excluded, so concurrent schedulers
    /// cannot create a renewal storm. Only the latest completed order per configuration is visible.
    ///
    /// # Errors
    ///
    /// Rejects invalid limits and fails closed for malformed persisted certificate state.
    pub fn due_certificate_renewals(
        &self,
        renew_by: UnixMicros,
        after: Option<&DueCertificateRenewalCursor>,
        limit: super::PageLimit,
    ) -> Result<
        super::Page<CertificateRenewalCandidate, DueCertificateRenewalCursor>,
        RepositoryError,
    > {
        query::due_renewals(&self.database, renew_by, after, limit)
    }

    /// Returns one exact ACME order and its current live claim.
    ///
    /// # Errors
    ///
    /// Fails closed when persisted lifecycle, identity or claim state is malformed.
    pub fn certificate_order(
        &self,
        order_id: CertificateOrderId,
    ) -> Result<Option<CertificateOrderRecord>, RepositoryError> {
        self.database
            .connection()
            .query_row(
                "SELECT o.order_id, o.config_id, o.state, o.next_attempt_at, o.attempt_count,
                        o.certificate_secret_id, o.certificate_secret_generation, o.revision,
                        c.claim_generation, c.worker_node_id, c.worker_incarnation, c.fence,
                        c.lease_expires_at
                 FROM certificate_orders o
                 LEFT JOIN certificate_order_claims c
                   ON c.order_id = o.order_id AND c.state = ?2
                 WHERE o.order_id = ?1",
                params![order_id.as_bytes().as_slice(), CLAIM_ACTIVE],
                decode_order,
            )
            .optional()
            .map_err(RepositoryError::from)
    }

    /// Returns the globally selected newest completed public-certificate generation.
    ///
    /// # Errors
    ///
    /// Fails closed when persisted completion or configuration evidence is malformed.
    pub fn latest_public_certificate(
        &self,
    ) -> Result<Option<PublicCertificateSelection>, RepositoryError> {
        let acme = query::latest_public_certificate(&self.database)?;
        let external = super::external_certificate::latest_public_certificate(&self.database)?;
        let local = super::mesh_local_certificate::latest_public_certificate(&self.database)?;
        Ok(super::external_certificate::newest_selection(
            super::external_certificate::newest_selection(acme, external),
            local,
        ))
    }

    /// Returns one gateway's exact certificate-installation proof.
    ///
    /// # Errors
    ///
    /// Fails closed when persisted identity, generation or digest fields are malformed.
    pub fn public_certificate_installation(
        &self,
        order_id: CertificateOrderId,
        gateway_node_id: NodeId,
    ) -> Result<Option<PublicCertificateInstallationRecord>, RepositoryError> {
        self.database
            .connection()
            .query_row(
                "SELECT order_id, gateway_node_id, gateway_incarnation,
                        certificate_secret_id, certificate_secret_generation, bundle_digest,
                        installed_at, revision
                 FROM public_certificate_installations
                 WHERE order_id = ?1 AND gateway_node_id = ?2",
                params![
                    order_id.as_bytes().as_slice(),
                    gateway_node_id.as_bytes().as_slice()
                ],
                decode_installation,
            )
            .optional()
            .map_err(RepositoryError::from)
    }

    /// Counts exact installation proofs against the immutable gateway-recipient set.
    ///
    /// # Errors
    ///
    /// Rejects missing, incomplete or malformed certificate orders and corrupt counts.
    pub fn public_certificate_rollout_summary(
        &self,
        order_id: CertificateOrderId,
    ) -> Result<PublicCertificateRolloutSummary, RepositoryError> {
        let connection = self.database.connection();
        let (secret_id, generation, digest, order_revision): (Vec<u8>, i64, Vec<u8>, i64) =
            connection
                .query_row(
                    "SELECT certificate_secret_id, certificate_secret_generation,
                            result_digest, revision
                     FROM certificate_orders WHERE order_id = ?1 AND state = ?2",
                    params![order_id.as_bytes().as_slice(), ORDER_COMPLETE],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()?
                .ok_or(RepositoryError::InvalidCommand)?;
        let certificate = SecretGenerationReference {
            secret_id: exact(secret_id)?,
            generation: positive(generation)?,
        };
        let bundle_digest = exact(digest)?;
        let required: i64 = connection.query_row(
            "SELECT count(DISTINCT r.owner_id) FROM secret_recipient_envelopes e
             JOIN secret_wrapping_recipients r
               ON r.key_fingerprint = e.recipient_key_fingerprint
             WHERE e.secret_kind = ?1 AND e.secret_id = ?2 AND e.secret_generation = ?3
               AND r.recipient_kind = 1",
            params![
                i64::from(PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND),
                certificate.secret_id.as_slice(),
                to_i64(certificate.generation)?,
            ],
            |row| row.get(0),
        )?;
        let installed: i64 = connection.query_row(
            "SELECT count(*) FROM public_certificate_installations
             WHERE order_id = ?1 AND certificate_secret_id = ?2
               AND certificate_secret_generation = ?3 AND bundle_digest = ?4",
            params![
                order_id.as_bytes().as_slice(),
                certificate.secret_id.as_slice(),
                to_i64(certificate.generation)?,
                bundle_digest.as_slice(),
            ],
            |row| row.get(0),
        )?;
        let required_gateway_count = parse_count(required)?;
        let installed_gateway_count = parse_count(installed)?;
        if required_gateway_count == 0 || installed_gateway_count > required_gateway_count {
            return Err(RepositoryError::CorruptState);
        }
        Ok(PublicCertificateRolloutSummary {
            order_id,
            certificate,
            bundle_digest,
            required_gateway_count,
            installed_gateway_count,
            complete: installed_gateway_count == required_gateway_count,
            order_revision: Revision::new(positive(order_revision)?),
        })
    }
}

fn validate_installation_order(
    transaction: &Transaction<'_>,
    value: AcknowledgePublicCertificateInstallation,
) -> Result<(), RepositoryError> {
    if value.gateway_incarnation == 0
        || value.certificate.secret_id != value.order_id.as_bytes()
        || value.certificate.generation == 0
        || value.bundle_digest == [0; 32]
        || value.observed_order_revision == Revision::ZERO
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let matches = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM certificate_orders o
            JOIN secret_recipient_envelopes e
              ON e.secret_kind = ?1
             AND e.secret_id = o.certificate_secret_id
             AND e.secret_generation = o.certificate_secret_generation
            JOIN secret_wrapping_recipients r
              ON r.key_fingerprint = e.recipient_key_fingerprint
            WHERE o.order_id = ?2 AND o.state = ?3
              AND o.certificate_secret_id = ?4 AND o.certificate_secret_generation = ?5
              AND o.result_digest = ?6 AND o.revision = ?7
              AND r.recipient_kind = 1 AND r.owner_id = ?8
         )",
        params![
            i64::from(PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND),
            value.order_id.as_bytes().as_slice(),
            ORDER_COMPLETE,
            value.certificate.secret_id.as_slice(),
            to_i64(value.certificate.generation)?,
            value.bundle_digest.as_slice(),
            to_i64(value.observed_order_revision.get())?,
            value.gateway_node_id.as_bytes().as_slice(),
        ],
        |row| row.get::<_, i64>(0),
    )?;
    if matches == 1 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn existing_installation(
    transaction: &Transaction<'_>,
    order_id: CertificateOrderId,
    gateway_node_id: NodeId,
) -> Result<Option<PublicCertificateInstallationRecord>, RepositoryError> {
    transaction
        .query_row(
            "SELECT order_id, gateway_node_id, gateway_incarnation,
                    certificate_secret_id, certificate_secret_generation, bundle_digest,
                    installed_at, revision
             FROM public_certificate_installations
             WHERE order_id = ?1 AND gateway_node_id = ?2",
            params![
                order_id.as_bytes().as_slice(),
                gateway_node_id.as_bytes().as_slice()
            ],
            decode_installation,
        )
        .optional()
        .map_err(RepositoryError::from)
}

fn decode_installation(row: &Row<'_>) -> rusqlite::Result<PublicCertificateInstallationRecord> {
    decode_installation_inner(row).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn decode_installation_inner(
    row: &Row<'_>,
) -> Result<PublicCertificateInstallationRecord, RepositoryError> {
    Ok(PublicCertificateInstallationRecord {
        order_id: CertificateOrderId::from_bytes(exact(row.get(0)?)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        gateway_node_id: NodeId::from_bytes(exact(row.get(1)?)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        gateway_incarnation: positive(row.get(2)?)?,
        certificate: SecretGenerationReference {
            secret_id: exact(row.get(3)?)?,
            generation: positive(row.get(4)?)?,
        },
        bundle_digest: exact(row.get(5)?)?,
        installed_at: UnixMicros::new(row.get(6)?),
        revision: Revision::new(positive(row.get(7)?)?),
    })
}

fn parse_count(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value).map_err(|_| RepositoryError::CorruptState)
}

struct CompletionValues {
    order_state: i64,
    next_attempt_at: i64,
    certificate: Option<SecretGenerationReference>,
    not_before: Option<i64>,
    not_after: Option<i64>,
    completed_at: Option<i64>,
    order_digest: Option<[u8; 32]>,
    claim_digest: [u8; 32],
    retry_at: Option<i64>,
}

fn completion_values(
    transaction: &Transaction<'_>,
    context: CommandContext,
    order_id: CertificateOrderId,
    outcome: &CertificateOrderCompletion,
    revision: Revision,
) -> Result<CompletionValues, RepositoryError> {
    match outcome {
        CertificateOrderCompletion::Retry {
            failure_digest,
            retry_at,
        } if *failure_digest != [0; 32] && *retry_at > context.occurred_at => {
            Ok(CompletionValues {
                order_state: ORDER_QUEUED,
                next_attempt_at: retry_at.get(),
                certificate: None,
                not_before: None,
                not_after: None,
                completed_at: None,
                order_digest: None,
                claim_digest: *failure_digest,
                retry_at: Some(retry_at.get()),
            })
        }
        CertificateOrderCompletion::Issued {
            certificate,
            not_before,
            not_after,
            result_digest,
        } if *not_after > *not_before
            && *not_after > context.occurred_at
            && *result_digest != [0; 32] =>
        {
            let secret_context = certificate.secret.context;
            if secret_context.kind() != PUBLIC_CERTIFICATE_BUNDLE_SECRET_KIND
                || secret_context.id() != order_id.as_bytes()
                || secret_context.generation() != 1
            {
                return Err(RepositoryError::InvalidCommand);
            }
            super::secret_generation::commit(transaction, context, certificate, revision)?;
            let reference = SecretGenerationReference {
                secret_id: secret_context.id(),
                generation: secret_context.generation(),
            };
            Ok(CompletionValues {
                order_state: ORDER_COMPLETE,
                next_attempt_at: context.occurred_at.get(),
                certificate: Some(reference),
                not_before: Some(not_before.get()),
                not_after: Some(not_after.get()),
                completed_at: Some(context.occurred_at.get()),
                order_digest: Some(*result_digest),
                claim_digest: *result_digest,
                retry_at: None,
            })
        }
        _ => Err(RepositoryError::InvalidCommand),
    }
}

fn validate_configuration(value: &ConfigureAcme) -> Result<(), RepositoryError> {
    if !value.directory_url.starts_with("https://")
        || value.directory_url.len() > MAXIMUM_DIRECTORY_URL_BYTES
        || value.directory_url.len() <= "https://".len()
        || value.directory_url.contains('#')
        || value
            .directory_url
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || byte.is_ascii_control())
        || value.certificate_names.is_empty()
        || value.certificate_names.len() > MAXIMUM_CERTIFICATE_NAMES
        || matches!(value.challenge_kind, AcmeChallengeKind::Http01)
            && value.challenge_settings.is_some()
    {
        return Err(RepositoryError::InvalidCommand);
    }
    let mut previous: Option<&str> = None;
    for name in value.certificate_names.as_slice() {
        if !valid_dns_name(name) || previous.is_some_and(|prior| prior >= name.as_str()) {
            return Err(RepositoryError::InvalidCommand);
        }
        previous = Some(name);
    }
    Ok(())
}

fn valid_dns_name(value: &str) -> bool {
    let name = value.strip_prefix("*.").unwrap_or(value);
    !name.is_empty()
        && value.len() <= 253
        && name.is_ascii()
        && name.contains('.')
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && label
                    .as_bytes()
                    .first()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .as_bytes()
                    .last()
                    .is_some_and(u8::is_ascii_alphanumeric)
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'.' | b'*')
        })
}

fn require_secret(
    transaction: &Transaction<'_>,
    kind: u16,
    secret: SecretGenerationReference,
) -> Result<(), RepositoryError> {
    if secret.secret_id == [0; 16] || secret.generation == 0 {
        return Err(RepositoryError::InvalidCommand);
    }
    let exists = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM secret_generations
            WHERE secret_kind = ?1 AND secret_id = ?2 AND generation = ?3
         )",
        params![
            i64::from(kind),
            secret.secret_id.as_slice(),
            to_i64(secret.generation)?,
        ],
        |row| row.get::<_, i64>(0),
    )?;
    if exists == 1 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

pub(super) fn validate_worker(
    transaction: &Transaction<'_>,
    node_id: NodeId,
    incarnation: u64,
) -> Result<(), RepositoryError> {
    if incarnation == 0 {
        return Err(RepositoryError::InvalidCommand);
    }
    let eligible = transaction.query_row(
        "SELECT EXISTS(
            SELECT 1 FROM nodes n
            JOIN node_roles r ON r.node_id = n.node_id AND r.role_code = ?3
            WHERE n.node_id = ?1 AND n.current_incarnation = ?2
              AND n.state = ?4 AND n.retired_at IS NULL
         )",
        params![
            node_id.as_bytes().as_slice(),
            to_i64(incarnation)?,
            GATEWAY_ROLE_CODE,
            ACTIVE_NODE,
        ],
        |row| row.get::<_, i64>(0),
    )?;
    if eligible == 1 {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn validate_lease(now: UnixMicros, expires_at: UnixMicros) -> Result<(), RepositoryError> {
    let duration = expires_at
        .get()
        .checked_sub(now.get())
        .ok_or(RepositoryError::InvalidCommand)?;
    if duration > 0 && duration <= MAXIMUM_LEASE_MICROS {
        Ok(())
    } else {
        Err(RepositoryError::InvalidCommand)
    }
}

fn order_transition_state(
    transaction: &Transaction<'_>,
    order_id: CertificateOrderId,
) -> Result<(i64, i64), RepositoryError> {
    transaction
        .query_row(
            "SELECT state, next_attempt_at FROM certificate_orders WHERE order_id = ?1",
            [order_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?
        .ok_or(RepositoryError::InvalidCommand)
}

fn active_claim(
    transaction: &Transaction<'_>,
    order_id: CertificateOrderId,
) -> Result<Option<CertificateOrderClaim>, RepositoryError> {
    transaction
        .query_row(
            "SELECT claim_generation, worker_node_id, worker_incarnation, fence, lease_expires_at
             FROM certificate_order_claims WHERE order_id = ?1 AND state = ?2",
            params![order_id.as_bytes().as_slice(), CLAIM_ACTIVE],
            |row| {
                Ok((
                    row.get::<_, i64>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, i64>(2)?,
                    row.get::<_, i64>(3)?,
                    row.get::<_, i64>(4)?,
                ))
            },
        )
        .optional()?
        .map(decode_claim)
        .transpose()
}

fn decode_claim(
    value: (i64, Vec<u8>, i64, i64, i64),
) -> Result<CertificateOrderClaim, RepositoryError> {
    Ok(CertificateOrderClaim {
        generation: positive(value.0)?,
        worker_node_id: NodeId::from_bytes(exact(value.1)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        worker_incarnation: positive(value.2)?,
        fence: positive(value.3)?,
        lease_expires_at: UnixMicros::new(value.4),
    })
}

fn require_live_claim(
    transaction: &Transaction<'_>,
    context: CommandContext,
    order_id: CertificateOrderId,
    generation: u64,
    worker_node_id: NodeId,
    worker_incarnation: u64,
    fence: u64,
) -> Result<CertificateOrderClaim, RepositoryError> {
    let (state, _) = order_transition_state(transaction, order_id)?;
    let claim = active_claim(transaction, order_id)?.ok_or(RepositoryError::InvalidCommand)?;
    if state != ORDER_CLAIMED
        || claim.generation != generation
        || claim.worker_node_id != worker_node_id
        || claim.worker_incarnation != worker_incarnation
        || claim.fence != fence
        || claim.lease_expires_at <= context.occurred_at
    {
        Err(RepositoryError::InvalidCommand)
    } else {
        Ok(claim)
    }
}

fn supersede_claim(
    transaction: &Transaction<'_>,
    context: CommandContext,
    order_id: CertificateOrderId,
    claim: CertificateOrderClaim,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let digest: [u8; 32] = Sha256::digest(b"meshspan:expired-acme-claim:v1").into();
    let changed = transaction.execute(
        "UPDATE certificate_order_claims
         SET state = ?1, finished_at = ?2, result_digest = ?3, revision = ?4
         WHERE order_id = ?5 AND claim_generation = ?6 AND state = ?7",
        params![
            CLAIM_SUPERSEDED,
            context.occurred_at.get(),
            digest.as_slice(),
            to_i64(revision.get())?,
            order_id.as_bytes().as_slice(),
            to_i64(claim.generation)?,
            CLAIM_ACTIVE,
        ],
    )?;
    exactly_one(changed)
}

fn latest_claim_generation(
    transaction: &Transaction<'_>,
    order_id: CertificateOrderId,
) -> Result<u64, RepositoryError> {
    let value = transaction.query_row(
        "SELECT COALESCE(MAX(claim_generation), 0)
         FROM certificate_order_claims WHERE order_id = ?1",
        [order_id.as_bytes().as_slice()],
        |row| row.get::<_, i64>(0),
    )?;
    u64::try_from(value).map_err(|_| RepositoryError::CorruptState)
}

fn update_order_revision(
    transaction: &Transaction<'_>,
    order_id: CertificateOrderId,
    revision: Revision,
) -> Result<(), RepositoryError> {
    let changed = transaction.execute(
        "UPDATE certificate_orders SET revision = ?1 WHERE order_id = ?2 AND state = ?3",
        params![
            to_i64(revision.get())?,
            order_id.as_bytes().as_slice(),
            ORDER_CLAIMED,
        ],
    )?;
    exactly_one(changed)
}

fn decode_order(row: &Row<'_>) -> rusqlite::Result<CertificateOrderRecord> {
    decode_order_inner(row).map_err(|_| rusqlite::Error::InvalidQuery)
}

fn decode_order_inner(row: &Row<'_>) -> Result<CertificateOrderRecord, RepositoryError> {
    let state = match row.get::<_, i64>(2)? {
        ORDER_QUEUED => CertificateOrderState::Queued,
        ORDER_CLAIMED => CertificateOrderState::Claimed,
        ORDER_COMPLETE => CertificateOrderState::Complete,
        _ => return Err(RepositoryError::CorruptState),
    };
    let certificate = match (
        row.get::<_, Option<Vec<u8>>>(5)?,
        row.get::<_, Option<i64>>(6)?,
    ) {
        (None, None) => None,
        (Some(id), Some(generation)) => Some(SecretGenerationReference {
            secret_id: exact(id)?,
            generation: positive(generation)?,
        }),
        _ => return Err(RepositoryError::CorruptState),
    };
    let claim = row
        .get::<_, Option<i64>>(8)?
        .map(|generation| {
            decode_claim((
                generation,
                row.get(9)?,
                row.get(10)?,
                row.get(11)?,
                row.get(12)?,
            ))
        })
        .transpose()?;
    if (state == CertificateOrderState::Claimed) != claim.is_some()
        || (state == CertificateOrderState::Complete) != certificate.is_some()
    {
        return Err(RepositoryError::CorruptState);
    }
    Ok(CertificateOrderRecord {
        order_id: CertificateOrderId::from_bytes(exact(row.get(0)?)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        config_id: AcmeConfigurationId::from_bytes(exact(row.get(1)?)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        state,
        next_attempt_at: UnixMicros::new(row.get(3)?),
        attempt_count: u64::try_from(row.get::<_, i64>(4)?)
            .map_err(|_| RepositoryError::CorruptState)?,
        certificate,
        claim,
        revision: Revision::new(positive(row.get(7)?)?),
    })
}

fn exactly_one(changed: usize) -> Result<(), RepositoryError> {
    if changed == 1 {
        Ok(())
    } else {
        Err(RepositoryError::CorruptState)
    }
}

fn positive(value: i64) -> Result<u64, RepositoryError> {
    u64::try_from(value)
        .ok()
        .filter(|value| *value != 0)
        .ok_or(RepositoryError::CorruptState)
}

fn exact<const LENGTH: usize>(value: Vec<u8>) -> Result<[u8; LENGTH], RepositoryError> {
    value.try_into().map_err(|_| RepositoryError::CorruptState)
}

fn challenge_code(kind: AcmeChallengeKind) -> i64 {
    match kind {
        AcmeChallengeKind::Http01 => 1,
        AcmeChallengeKind::Dns01 => 2,
    }
}

fn config_entity(config_id: AcmeConfigurationId) -> EntityReference {
    EntityReference {
        kind: EntityKind::AcmeConfiguration,
        id: config_id.as_bytes(),
    }
}

fn order_entity(order_id: CertificateOrderId) -> EntityReference {
    EntityReference {
        kind: EntityKind::CertificateOrder,
        id: order_id.as_bytes(),
    }
}
