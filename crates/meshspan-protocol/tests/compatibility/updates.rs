// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use meshspan_protocol::v1::{
    ProbeUpdateReadiness, UpdateReadinessResult, UpdateWorkloadObservation, UpdateWorkloadState,
};

#[test]
fn update_readiness_round_trip_requires_bound_identity_positions_and_report()
-> Result<(), Box<dyn std::error::Error>> {
    let query = ProbeUpdateReadiness {
        rollout_id: vec![1; 16],
        quorum_plan_digest: vec![2; 32],
        minimum_applied_index: 7,
    };
    let result = UpdateReadinessResult {
        rollout_id: vec![1; 16],
        node_id: vec![3; 16],
        incarnation: 2,
        quorum_plan_digest: vec![2; 32],
        applied_index: 7,
        committed_index: 8,
        persistence_blocked: false,
        listeners_bound: true,
        runtime_report: b"{}".to_vec(),
        observed_at_unix_micros: 1000,
        local_content_scan: None,
    };
    for message in [
        Message::ProbeUpdateReadiness(query.clone()),
        Message::UpdateReadinessResult(result.clone()),
    ] {
        let envelope = ControlEnvelope {
            header: Some(valid_header()),
            message: Some(message),
        };
        assert_eq!(
            decode_control_frame(&encode_control_frame(&envelope, limits()?)?, limits()?)?
                .into_inner(),
            envelope
        );
    }
    let mut invalid = vec![result; 6];
    invalid[0].incarnation = 0;
    invalid[1].applied_index = 9;
    invalid[2].runtime_report = Vec::new();
    invalid[3].runtime_report = vec![0; 8193];
    invalid[4].observed_at_unix_micros = 0;
    invalid[5].quorum_plan_digest = vec![0; 31];
    for result in invalid {
        let envelope = ControlEnvelope {
            header: Some(valid_header()),
            message: Some(Message::UpdateReadinessResult(result)),
        };
        assert!(encode_control_frame(&envelope, limits()?).is_err());
    }
    let missing_header = ControlEnvelope {
        header: None,
        message: Some(Message::ProbeUpdateReadiness(query)),
    };
    assert!(encode_control_frame(&missing_header, limits()?).is_err());
    Ok(())
}

#[test]
fn update_scan_observations_reject_unbound_unknown_and_future_claims()
-> Result<(), Box<dyn std::error::Error>> {
    let scan = UpdateWorkloadObservation {
        excluded_node_id: vec![4; 16],
        excluded_node_incarnation: 1,
        preparation_sequence: 3,
        preparation_log_index: 7,
        metadata_revision: 5,
        state: UpdateWorkloadState::LocalContentChecked.into(),
        observed_at_unix_micros: 900,
        volumes_checked: 2,
        publications_checked: 3,
        stripes_checked: 4,
        current_volume_id: Some(vec![5; 16]),
        excluded_targets: 2,
    };
    let result = UpdateReadinessResult {
        rollout_id: vec![1; 16],
        node_id: vec![3; 16],
        incarnation: 2,
        quorum_plan_digest: vec![2; 32],
        applied_index: 7,
        committed_index: 8,
        persistence_blocked: false,
        listeners_bound: true,
        runtime_report: b"{}".to_vec(),
        observed_at_unix_micros: 1000,
        local_content_scan: Some(scan.clone()),
    };
    let envelope = |scan| ControlEnvelope {
        header: Some(valid_header()),
        message: Some(Message::UpdateReadinessResult(UpdateReadinessResult {
            local_content_scan: Some(scan),
            ..result.clone()
        })),
    };
    for state in [
        UpdateWorkloadState::Checking,
        UpdateWorkloadState::LocalContentChecked,
        UpdateWorkloadState::Unavailable,
    ] {
        let frame = envelope(UpdateWorkloadObservation {
            state: state.into(),
            ..scan.clone()
        });
        assert_eq!(
            decode_control_frame(&encode_control_frame(&frame, limits()?)?, limits()?)?
                .into_inner(),
            frame
        );
    }
    let mut invalid = vec![scan; 9];
    invalid[0].excluded_node_id = vec![1; 15];
    invalid[1].excluded_node_incarnation = 0;
    invalid[2].preparation_sequence = 0;
    invalid[3].preparation_log_index = 8;
    invalid[4].metadata_revision = 0;
    invalid[5].state = 0;
    invalid[6].state = 99;
    invalid[7].observed_at_unix_micros = 1001;
    invalid[8].current_volume_id = Some(Vec::new());
    for value in invalid {
        assert!(encode_control_frame(&envelope(value), limits()?).is_err());
    }
    Ok(())
}
