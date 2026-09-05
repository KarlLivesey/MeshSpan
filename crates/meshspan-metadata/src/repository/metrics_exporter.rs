// SPDX-License-Identifier: GPL-2.0-only

//! One typed, revisioned exporter policy on the existing component-configuration boundary.

use meshspan_domain::{ComponentInstanceId, MeshId, Revision, uuid_v8};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sha2::{Digest, Sha256};

use super::{EntityReference, RepositoryError, component};
use crate::metrics_exporter_command::MAX_METRICS_CONFIGURATION_BYTES;
use crate::{
    CommandContext, ConfigureComponent, ConfigureMetricsExporter, CreateComponent,
    MetricsExporterPolicy, RecordName,
};

const IMPLEMENTATION: &str = "meshspan-openmetrics";
const COMPONENT_KIND: u8 = 10;

/// Active immutable exporter policy, with a sequence independent of unrelated metadata writes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MetricsExporterConfiguration {
    /// Exact mesh-derived component instance.
    pub instance_id: ComponentInstanceId,
    /// Current immutable component configuration sequence.
    pub sequence: u64,
    /// Revision at which this configuration became active.
    pub revision: Revision,
    /// Complete validated non-secret policy.
    pub policy: MetricsExporterPolicy,
}

/// Derives the single built-in exporter component identity within an owning mesh.
///
/// # Errors
/// Rejects an invalid generated component identity.
pub fn metrics_exporter_instance_id(
    mesh: MeshId,
) -> Result<ComponentInstanceId, meshspan_domain::IdentifierError> {
    let mut digest = Sha256::new();
    digest.update(b"meshspan.metrics-exporter.instance.v1\0");
    digest.update(mesh.as_bytes());
    let mut bytes = [0; 16];
    bytes.copy_from_slice(&digest.finalize()[..16]);
    ComponentInstanceId::from_bytes(uuid_v8(bytes))
}

pub(super) fn configure(
    transaction: &Transaction<'_>,
    context: CommandContext,
    command: &ConfigureMetricsExporter,
    revision: Revision,
) -> Result<EntityReference, RepositoryError> {
    command
        .policy
        .validate()
        .map_err(|_| RepositoryError::InvalidCommand)?;
    let current = load(transaction)?;
    let sequence = current.as_ref().map_or(0, |value| value.sequence);
    if sequence != command.expected_sequence {
        return Err(RepositoryError::StaleRevision);
    }
    for principal in &command.policy.allowed_principals {
        let exists: bool = transaction.query_row(
            "SELECT EXISTS(SELECT 1 FROM users JOIN principals USING(principal_id)
             WHERE principal_id = ?1 AND principal_kind = 1)",
            [principal.as_bytes().as_slice()],
            |row| row.get(0),
        )?;
        if !exists {
            return Err(RepositoryError::InvalidCommand);
        }
    }
    let instance_id = identity(transaction)?;
    let canonical_configuration = command
        .policy
        .encode()
        .map_err(|_| RepositoryError::InvalidCommand)?;
    let configuration_digest = Sha256::digest(&canonical_configuration).into();
    if current.is_some() {
        component::configure(
            transaction,
            context,
            &ConfigureComponent {
                instance_id,
                schema_version: 1,
                canonical_configuration,
                configuration_digest,
            },
            revision,
        )
    } else {
        component::create(
            transaction,
            context,
            &CreateComponent {
                instance_id,
                component_kind: COMPONENT_KIND,
                name: RecordName::new("Metrics exporter")
                    .map_err(|_| RepositoryError::InvalidCommand)?,
                implementation_id: IMPLEMENTATION.to_owned(),
                contract_major: 1,
                contract_minor: 0,
                schema_version: 1,
                canonical_configuration,
                configuration_digest,
            },
            revision,
        )
    }
}

struct StoredConfiguration {
    sequence: i64,
    revision: i64,
    descriptor_valid: bool,
    payload: Option<Vec<u8>>,
    digest: Option<Vec<u8>>,
    configuration_valid: Option<bool>,
}

pub(super) fn load(
    connection: &Connection,
) -> Result<Option<MetricsExporterConfiguration>, RepositoryError> {
    let instance_id = identity(connection)?;
    let maximum_bytes = i64::try_from(MAX_METRICS_CONFIGURATION_BYTES)
        .map_err(|_| RepositoryError::CapacityExceeded)?;
    // The LEFT JOIN distinguishes an absent component from a corrupt dangling head. SQL bounds
    // hostile payloads before materialising them, and joins by the exact active configuration.
    let stored = connection
        .query_row(
            "SELECT i.active_config_revision, i.revision,
            i.component_kind = ?2 AND i.implementation_id = ?3 AND i.contract_major = 1
                AND i.contract_minor = 0 AND i.scope_kind = 1 AND i.scope_id IS NULL
                AND i.desired_state = 1 AND i.retired_at IS NULL,
            substr(c.canonical_config, 1, ?4), c.config_digest,
            c.schema_version = 1 AND c.state = 2 AND c.secret_generation_id IS NULL
                AND length(c.canonical_config) <= ?5
         FROM component_instances i LEFT JOIN component_configurations c
            ON c.instance_id = i.instance_id AND c.config_revision = i.active_config_revision
         WHERE i.instance_id = ?1",
            params![
                instance_id.as_bytes().as_slice(),
                COMPONENT_KIND,
                IMPLEMENTATION,
                maximum_bytes + 1,
                maximum_bytes
            ],
            |row| {
                Ok(StoredConfiguration {
                    sequence: row.get(0)?,
                    revision: row.get(1)?,
                    descriptor_valid: row.get(2)?,
                    payload: row.get(3)?,
                    digest: row.get(4)?,
                    configuration_valid: row.get(5)?,
                })
            },
        )
        .optional()?;
    stored
        .map(|stored| decode_configuration(instance_id, stored))
        .transpose()
}

fn decode_configuration(
    instance_id: ComponentInstanceId,
    stored: StoredConfiguration,
) -> Result<MetricsExporterConfiguration, RepositoryError> {
    if !stored.descriptor_valid
        || stored.configuration_valid != Some(true)
        || stored.sequence <= 0
        || stored.revision <= 0
    {
        return Err(RepositoryError::CorruptState);
    }
    let payload = stored.payload.ok_or(RepositoryError::CorruptState)?;
    let digest = stored.digest.ok_or(RepositoryError::CorruptState)?;
    if digest.as_slice() != Sha256::digest(&payload).as_slice() {
        return Err(RepositoryError::CorruptState);
    }
    Ok(MetricsExporterConfiguration {
        instance_id,
        sequence: u64::try_from(stored.sequence).map_err(|_| RepositoryError::CorruptState)?,
        revision: Revision::new(
            u64::try_from(stored.revision).map_err(|_| RepositoryError::CorruptState)?,
        ),
        policy: MetricsExporterPolicy::decode(&payload)
            .map_err(|_| RepositoryError::CorruptState)?,
    })
}

fn identity(connection: &Connection) -> Result<ComponentInstanceId, RepositoryError> {
    let mut statement =
        connection.prepare("SELECT mesh_id FROM meshes ORDER BY mesh_id LIMIT 2")?;
    let meshes = statement
        .query_map([], |row| row.get::<_, [u8; 16]>(0))?
        .collect::<Result<Vec<_>, _>>()?;
    let [mesh] = meshes.as_slice() else {
        return Err(RepositoryError::CorruptState);
    };
    let mesh = MeshId::from_bytes(*mesh).map_err(|_| RepositoryError::CorruptState)?;
    metrics_exporter_instance_id(mesh).map_err(|_| RepositoryError::CorruptState)
}
