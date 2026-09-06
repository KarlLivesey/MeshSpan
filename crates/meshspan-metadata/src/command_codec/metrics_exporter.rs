// SPDX-License-Identifier: GPL-2.0-only

use super::{MetadataCommandCodecError, decoder::Decoder, encoder::Encoder};
use crate::metrics_exporter_command::MAX_METRICS_CONFIGURATION_BYTES;
use crate::{ConfigureMetricsExporter, MetricsExporterPolicy};

pub(super) const CONFIGURE_METRICS_EXPORTER: u16 = 76;

pub(super) fn encode(
    encoder: &mut Encoder,
    value: &ConfigureMetricsExporter,
) -> Result<(), MetadataCommandCodecError> {
    if value.expected_sequence >= i64::MAX as u64 {
        return Err(MetadataCommandCodecError::Invalid);
    }
    let policy = value.policy.encode()?;
    encoder.u16(CONFIGURE_METRICS_EXPORTER)?;
    encoder.u64(value.expected_sequence)?;
    encoder.bytes(&policy, MAX_METRICS_CONFIGURATION_BYTES)
}

pub(super) fn decode(
    decoder: &mut Decoder<'_>,
) -> Result<ConfigureMetricsExporter, MetadataCommandCodecError> {
    let expected_sequence = decoder.u64()?;
    if expected_sequence >= i64::MAX as u64 {
        return Err(MetadataCommandCodecError::Invalid);
    }
    let bytes = decoder.bytes(MAX_METRICS_CONFIGURATION_BYTES)?;
    Ok(ConfigureMetricsExporter {
        expected_sequence,
        policy: MetricsExporterPolicy::decode(&bytes)?,
    })
}
