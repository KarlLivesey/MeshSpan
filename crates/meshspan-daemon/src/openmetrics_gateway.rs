// SPDX-License-Identifier: GPL-2.0-only

use super::Measurement;
use meshspan_contracts::{GatewayProtocol, GatewayTransferMetric};

pub(super) fn dispatches(protocol: GatewayProtocol) -> (&'static str, &'static str) {
    match protocol {
        GatewayProtocol::Https => (
            "https_dispatches",
            "HTTPS handler dispatches ended, including cancellations.",
        ),
        GatewayProtocol::Smb => (
            "smb_dispatches",
            "Complete SMB payload dispatches ended, including cancellations.",
        ),
    }
}

pub(super) fn dispatch_errors(protocol: GatewayProtocol) -> (&'static str, &'static str) {
    match protocol {
        GatewayProtocol::Https => (
            "https_server_error_responses",
            "HTTPS dispatches returning a 5xx response.",
        ),
        GatewayProtocol::Smb => (
            "smb_dispatch_errors",
            "SMB handler errors; excludes ordinary protocol error-status responses.",
        ),
    }
}

pub(super) fn cancelled_dispatches(protocol: GatewayProtocol) -> (&'static str, &'static str) {
    match protocol {
        GatewayProtocol::Https => (
            "https_cancelled_dispatches",
            "HTTPS dispatch futures dropped before returning a response.",
        ),
        GatewayProtocol::Smb => (
            "smb_cancelled_dispatches",
            "SMB dispatch futures dropped before returning.",
        ),
    }
}

pub(super) fn dispatch_duration(protocol: GatewayProtocol) -> (&'static str, &'static str) {
    match protocol {
        GatewayProtocol::Https => (
            "https_dispatch_duration_seconds",
            "HTTPS handler lifetime; excludes subsequent response-body streaming.",
        ),
        GatewayProtocol::Smb => (
            "smb_dispatch_duration_seconds",
            "SMB payload handler lifetime; excludes response socket writes.",
        ),
    }
}

pub(super) fn name_and_help(
    protocol: GatewayProtocol,
    value: &GatewayTransferMetric,
) -> (&'static str, &'static str) {
    match (protocol, value) {
        (GatewayProtocol::Https, GatewayTransferMetric::ReceivedBytes(_)) => (
            "https_received_bytes",
            "HTTP protocol bytes read after TLS decoding, including headers and framing.",
        ),
        (GatewayProtocol::Https, GatewayTransferMetric::SentBytes(_)) => (
            "https_sent_bytes",
            "HTTP protocol bytes accepted by the TLS writer, not peer application delivery.",
        ),
        (GatewayProtocol::Smb, GatewayTransferMetric::ReceivedBytes(_)) => (
            "smb_received_bytes",
            "SMB socket bytes read, including Direct TCP framing and encrypted payloads.",
        ),
        (GatewayProtocol::Smb, GatewayTransferMetric::SentBytes(_)) => (
            "smb_sent_bytes",
            "SMB socket bytes accepted by the writer, not peer application delivery.",
        ),
        (GatewayProtocol::Https, GatewayTransferMetric::ReadErrors(_)) => (
            "https_read_errors",
            "HTTPS stream read polls returning IO errors; excludes clean EOF.",
        ),
        (GatewayProtocol::Https, GatewayTransferMetric::WriteErrors(_)) => (
            "https_write_errors",
            "HTTPS write, flush and shutdown polls returning IO errors.",
        ),
        (GatewayProtocol::Smb, GatewayTransferMetric::ReadErrors(_)) => (
            "smb_read_errors",
            "SMB stream read polls returning IO errors; excludes clean EOF.",
        ),
        (GatewayProtocol::Smb, GatewayTransferMetric::WriteErrors(_)) => (
            "smb_write_errors",
            "SMB write, flush and shutdown polls returning IO errors.",
        ),
    }
}

pub(super) fn measurement(value: &GatewayTransferMetric) -> Measurement<'_> {
    let (GatewayTransferMetric::ReceivedBytes(value)
    | GatewayTransferMetric::SentBytes(value)
    | GatewayTransferMetric::ReadErrors(value)
    | GatewayTransferMetric::WriteErrors(value)) = value;
    Measurement::Counter(*value)
}
