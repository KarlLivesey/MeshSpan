// SPDX-License-Identifier: GPL-2.0-only

//! Explicit opt-in and exact consumer allow-list for the built-in metrics exporter.

use meshspan_domain::PrincipalId;

/// Maximum directly authorised exporter consumers; this is not a connection limit.
pub const MAX_METRICS_EXPORTER_CONSUMERS: usize = 64;
pub(crate) const MAX_METRICS_CONFIGURATION_BYTES: usize = 7 + 16 * MAX_METRICS_EXPORTER_CONSUMERS;

/// Public non-secret exporter policy, stored as an immutable component configuration.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct MetricsExporterPolicy {
    /// Explicit opt-in. Missing configuration is disabled.
    pub enabled: bool,
    /// Strictly ordered, distinct user principals allowed to scrape using current credentials.
    pub allowed_principals: Vec<PrincipalId>,
}

impl MetricsExporterPolicy {
    /// Checks bounded canonical identity order and useful enabled configuration.
    ///
    /// # Errors
    /// Rejects duplicates, unsorted identities, excess consumers and enabled empty policies.
    pub fn validate(&self) -> Result<(), crate::RepositoryCommandError> {
        if self.allowed_principals.len() > MAX_METRICS_EXPORTER_CONSUMERS
            || (self.enabled && self.allowed_principals.is_empty())
            || self
                .allowed_principals
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(crate::RepositoryCommandError::InvalidComponent);
        }
        Ok(())
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, crate::RepositoryCommandError> {
        self.validate()?;
        let count = u16::try_from(self.allowed_principals.len())
            .map_err(|_| crate::RepositoryCommandError::InvalidComponent)?;
        let mut bytes = Vec::with_capacity(7 + self.allowed_principals.len() * 16);
        bytes.extend_from_slice(b"MSM\x01");
        bytes.push(u8::from(self.enabled));
        bytes.extend_from_slice(&count.to_be_bytes());
        for principal in &self.allowed_principals {
            bytes.extend_from_slice(&principal.as_bytes());
        }
        Ok(bytes)
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, crate::RepositoryCommandError> {
        let invalid = crate::RepositoryCommandError::InvalidComponent;
        if bytes.len() < 7
            || bytes.len() > MAX_METRICS_CONFIGURATION_BYTES
            || &bytes[..4] != b"MSM\x01"
        {
            return Err(invalid);
        }
        let enabled = match bytes[4] {
            0 => false,
            1 => true,
            _ => return Err(invalid),
        };
        let count = usize::from(u16::from_be_bytes([bytes[5], bytes[6]]));
        if count > MAX_METRICS_EXPORTER_CONSUMERS || bytes.len() != 7 + count * 16 {
            return Err(invalid);
        }
        let mut allowed_principals = Vec::with_capacity(count);
        for identity in bytes[7..].as_chunks::<16>().0 {
            allowed_principals.push(PrincipalId::from_bytes(*identity).map_err(|_| invalid)?);
        }
        let policy = Self {
            enabled,
            allowed_principals,
        };
        policy.validate()?;
        Ok(policy)
    }
}

/// Atomically replaces the mesh-wide metrics policy at one expected configuration sequence.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConfigureMetricsExporter {
    /// Zero creates the initial disabled-or-enabled configuration; otherwise exact active sequence.
    pub expected_sequence: u64,
    /// Complete replacement policy, not a patch or an implicit broad grant.
    pub policy: MetricsExporterPolicy,
}
