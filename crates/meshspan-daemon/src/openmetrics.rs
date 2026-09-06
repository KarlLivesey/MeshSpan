// SPDX-License-Identifier: GPL-2.0-only

//! `OpenMetrics` 1.0 encoding over the typed local observation contract; no IO or dynamic labels.

use std::fmt::Write;
use std::time::Duration;

use meshspan_contracts::{
    ContractError, LatencyHistogram, METRIC_LATENCY_BOUNDARIES_MICROS, RuntimeMetricSnapshot,
};

#[path = "openmetrics_catalogue.rs"]
mod catalogue;
use catalogue::{Descriptor, Measurement, describe};

/// Exact negotiated media type of the built-in metrics exporter.
pub const OPENMETRICS_CONTENT_TYPE: &str =
    "application/openmetrics-text; version=1.0.0; charset=utf-8";
/// Hard output budget, independent of ordinary JSON response limits.
pub const MAX_OPENMETRICS_BYTES: usize = meshspan_api_contract::MAX_METRICS_EXPORT_BYTES;

/// Encodes a validated snapshot using fixed version-one names and histogram buckets.
///
/// Empty snapshots produce only EOF. Missing measurements are never filled with zero.
/// No user-provided names, labels, timestamps, exemplars or raw errors are accepted.
///
/// # Errors
/// Rejects contradictory source evidence or an output exceeding the fixed response budget.
pub fn encode_openmetrics(snapshot: &RuntimeMetricSnapshot) -> Result<Vec<u8>, ContractError> {
    snapshot.validate()?;
    let mut families = snapshot.samples().iter().map(describe).collect::<Vec<_>>();
    families.sort_unstable_by_key(|family| family.name);
    let mut output = String::new();
    for family in families {
        write_family(&mut output, &family).map_err(|_| ContractError::InternalContract)?;
    }
    output.push_str("# EOF\n");
    // The closed fixed-size catalogue bounds allocation before this final guard.
    if output.len() > MAX_OPENMETRICS_BYTES {
        return Err(ContractError::ResourceExhausted);
    }
    Ok(output.into_bytes())
}

fn write_family(output: &mut String, family: &Descriptor<'_>) -> std::fmt::Result {
    let name = format!("meshspan_v1_{}", family.name);
    let (kind, unit) = match family.measurement {
        Measurement::Counter(_) => ("counter", None),
        Measurement::Gauge(_) => ("gauge", None),
        Measurement::Bytes(_) => ("gauge", Some("bytes")),
        Measurement::Seconds(_) => ("gauge", Some("seconds")),
        Measurement::Latency(_) => ("histogram", Some("seconds")),
    };
    writeln!(output, "# TYPE {name} {kind}")?;
    if let Some(unit) = unit {
        writeln!(output, "# UNIT {name} {unit}")?;
    }
    writeln!(output, "# HELP {name} {}", family.help)?;
    match family.measurement {
        Measurement::Counter(value) => writeln!(output, "{name}_total {value}"),
        Measurement::Gauge(value) | Measurement::Bytes(value) => writeln!(output, "{name} {value}"),
        Measurement::Seconds(value) => writeln!(output, "{name} {}", seconds(value)),
        Measurement::Latency(value) => write_histogram(output, &name, value),
    }
}

fn write_histogram(output: &mut String, name: &str, value: &LatencyHistogram) -> std::fmt::Result {
    for (boundary, count) in METRIC_LATENCY_BOUNDARIES_MICROS.iter().zip(value.buckets) {
        writeln!(
            output,
            "{name}_bucket{{le=\"{}\"}} {count}",
            seconds(Duration::from_micros(*boundary))
        )?;
    }
    writeln!(output, "{name}_bucket{{le=\"+Inf\"}} {}", value.count)?;
    writeln!(output, "{name}_count {}", value.count)?;
    writeln!(output, "{name}_sum {}", seconds(value.sum))
}

fn seconds(duration: Duration) -> String {
    // Keep the producer's complete integer precision; downstream ingestors may use float64.
    format!("{}.{:09}", duration.as_secs(), duration.subsec_nanos())
}

#[cfg(test)]
#[path = "openmetrics_tests.rs"]
mod tests;
