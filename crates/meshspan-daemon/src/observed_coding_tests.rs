// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use meshspan_contracts::{CodingMetric, ContractVersion, RuntimeMetric, RuntimeMetricSource};
use meshspan_domain::OperationId;

#[test]
fn real_coding_counts_healthy_degraded_and_failed_reconstruction()
-> Result<(), Box<dyn std::error::Error>> {
    let observations = RuntimeObservations::default();
    let coding = ObservedCoding::new(
        meshspan_coding::ReedSolomonCoding::new(),
        observations.clone(),
    );
    let context = RequestContext {
        contract_version: ContractVersion::V1_0,
        operation_id: OperationId::from_bytes([1; 16])?,
        deadline: UnixMicros::new(1),
        expected_revision: None,
    };
    let layout = CodingLayout::new(2, 1, 8)?;
    let logical = BoundedBytes::copy_from(b"abcdefghijklmnop", 16)?;
    let slices = coding.encode(context, layout, &logical)?;
    assert_eq!(slices.len(), 3);
    let mut request = ReconstructionRequest {
        context,
        layout,
        available_slices: BoundedItems::new(
            slices.as_slice().iter().cloned().map(Some).collect(),
            3,
        )?,
        slice_digests: BoundedItems::new(
            slices
                .as_slice()
                .iter()
                .map(|slice| *blake3::hash(slice.as_slice()).as_bytes())
                .collect(),
            3,
        )?,
        logical_length: 16,
        logical_digest: *blake3::hash(logical.as_slice()).as_bytes(),
    };
    assert_eq!(coding.reconstruct(&request)?, logical);
    request.available_slices = BoundedItems::new(
        vec![
            None,
            Some(slices.as_slice()[1].clone()),
            Some(slices.as_slice()[2].clone()),
        ],
        3,
    )?;
    assert_eq!(coding.reconstruct(&request)?, logical);
    request.available_slices =
        BoundedItems::new(vec![None, None, Some(slices.as_slice()[2].clone())], 3)?;
    assert_eq!(coding.reconstruct(&request), Err(ContractError::Corrupt));
    let samples = observations.collect_metrics()?;
    for metric in [
        CodingMetric::Calls(1),
        CodingMetric::Failures(0),
        CodingMetric::InputBytes(16),
        CodingMetric::OutputBytes(24),
        CodingMetric::MissingDataCalls(0),
    ] {
        assert!(
            samples
                .samples()
                .contains(&RuntimeMetric::Coding(CodingOperation::Encode, metric))
        );
    }
    for metric in [
        CodingMetric::Calls(3),
        CodingMetric::Failures(1),
        CodingMetric::InputBytes(48),
        CodingMetric::OutputBytes(32),
        CodingMetric::MissingDataCalls(2),
    ] {
        assert!(
            samples
                .samples()
                .contains(&RuntimeMetric::Coding(CodingOperation::Reconstruct, metric))
        );
    }
    Ok(())
}
