// SPDX-License-Identifier: GPL-2.0-only

use crate::*;

fn run() -> BackupRunSummary {
    BackupRunSummary {
        backup_id: "01900000-0000-7000-8000-000000000001".to_owned(),
        run_sequence: "9007199254740993".to_owned(),
        schedule_sequence: "1".to_owned(),
        scheduled_for_epoch_micros: 1,
        completed_at_epoch_micros: None,
        state: BackupRunStatus::Queued,
        minimum_verified_copies: 2,
        minimum_independent_copies: 1,
    }
}

#[test]
fn backup_history_preserves_lossless_sequences_and_terminal_outcomes()
-> Result<(), Box<dyn std::error::Error>> {
    for state in [
        BackupRunStatus::Queued,
        BackupRunStatus::Claimed,
        BackupRunStatus::Recorded,
        BackupRunStatus::Protected,
        BackupRunStatus::Incomplete,
    ] {
        let terminal = matches!(
            state,
            BackupRunStatus::Protected | BackupRunStatus::Incomplete
        );
        let mut item = run();
        item.state = state;
        item.completed_at_epoch_micros = terminal.then_some(2);
        let mut page = ListBackupRunsResponse {
            runs: vec![item],
            next_page_url: None,
        };
        let value: serde_json::Value =
            serde_json::from_slice(&encode_list_backup_runs_response(&page)?)?;
        assert_eq!(value["runs"][0]["run_sequence"], "9007199254740993");
        page.runs[0].completed_at_epoch_micros = (!terminal).then_some(2);
        assert!(encode_list_backup_runs_response(&page).is_err());
    }
    Ok(())
}

#[test]
fn backup_history_rejects_unsafe_pages_and_queries() {
    let page = ListBackupRunsResponse {
        runs: vec![run()],
        next_page_url: None,
    };
    let mut changed = page.clone();
    changed.runs.push(run());
    assert!(encode_list_backup_runs_response(&changed).is_err());
    for value in ["0", "01", "-1", "9999999999999999999"] {
        let mut changed = page.clone();
        changed.runs[0].run_sequence = value.to_owned();
        assert!(encode_list_backup_runs_response(&changed).is_err());
    }
    let mut changed = page.clone();
    changed.runs[0].minimum_independent_copies = 3;
    assert!(encode_list_backup_runs_response(&changed).is_err());
    for url in [
        "https://attacker.example/",
        "/api/latest/admin/backups/destinations?limit=1&cursor=x",
    ] {
        let mut changed = page.clone();
        changed.next_page_url = Some(url.to_owned());
        assert!(encode_list_backup_runs_response(&changed).is_err());
    }
    for limit in [0, 101] {
        assert!(
            validate_list_backup_runs_query(&ListBackupRunsQuery {
                limit: Some(limit),
                cursor: None
            })
            .is_err()
        );
    }
}
