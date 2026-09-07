// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use meshspan_protocol::v1::{ProbeUpdateReadiness, UpdateReadinessResult};

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
