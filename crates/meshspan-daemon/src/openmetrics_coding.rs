// SPDX-License-Identifier: GPL-2.0-only

use super::Measurement;
use meshspan_contracts::{CodingMetric, CodingOperation};

pub(super) fn name_and_help(
    kind: CodingOperation,
    value: &CodingMetric,
) -> (&'static str, &'static str) {
    use CodingMetric::{Calls, Duration, Failures, InputBytes, MissingDataCalls, OutputBytes};
    use CodingOperation::{Encode, Reconstruct};
    let name = match (kind, value) {
        (Encode, Calls(_)) => "coding_encode_calls",
        (Encode, Failures(_)) => "coding_encode_failures",
        (Encode, InputBytes(_)) => "coding_encode_input_bytes",
        (Encode, OutputBytes(_)) => "coding_encode_output_bytes",
        (Encode, MissingDataCalls(_)) => "coding_encode_missing_data_calls",
        (Encode, Duration(_)) => "coding_encode_duration_seconds",
        (Reconstruct, Calls(_)) => "coding_reconstruct_calls",
        (Reconstruct, Failures(_)) => "coding_reconstruct_failures",
        (Reconstruct, InputBytes(_)) => "coding_reconstruct_input_bytes",
        (Reconstruct, OutputBytes(_)) => "coding_reconstruct_output_bytes",
        (Reconstruct, MissingDataCalls(_)) => "coding_reconstruct_missing_data_calls",
        (Reconstruct, Duration(_)) => "coding_reconstruct_duration_seconds",
    };
    let help = match value {
        Calls(_) => "Coding calls which returned, including failures and replay.",
        Failures(_) => "Coding calls returning errors, not all failed file reads.",
        InputBytes(_) => {
            "Bytes supplied to returned coding calls, including failed input and replay."
        }
        OutputBytes(_) => {
            "Bytes returned by successful coding calls, including recovery slices and replay."
        }
        MissingDataCalls(_) => {
            "Reconstruction requests lacking systematic slices, including failures; zero for encode. Not a mesh availability assessment."
        }
        Duration(_) => "Time inside the coding implementation, excluding storage and network IO.",
    };
    (name, help)
}

pub(super) fn measurement(value: &CodingMetric) -> Measurement<'_> {
    match value {
        CodingMetric::Calls(value)
        | CodingMetric::Failures(value)
        | CodingMetric::InputBytes(value)
        | CodingMetric::OutputBytes(value)
        | CodingMetric::MissingDataCalls(value) => Measurement::Counter(*value),
        CodingMetric::Duration(value) => Measurement::Latency(value),
    }
}
