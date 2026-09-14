// SPDX-License-Identifier: GPL-2.0-only

use super::{Error, Workspace};
use std::{fs, os::unix::fs::PermissionsExt as _};

#[test]
fn recovery_workspace_locks_intent_and_reopens_after_owner_exits()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().join("work");
    let workspace = Workspace::open(&root, &[1; 32])?;
    assert!(matches!(Workspace::open(&root, &[1; 32]), Err(Error::Busy)));
    let build = workspace.begin_build()?;
    fs::write(
        build.join("prepared.sqlite3"),
        b"incomplete unpublished database",
    )?;
    fs::write(
        build.join(".secrets.bin.meshspan-0.tmp"),
        b"incomplete encrypted spool",
    )?;
    drop(workspace);
    assert!(matches!(
        Workspace::open(&root, &[2; 32]),
        Err(Error::Conflict)
    ));
    assert!(build.join("prepared.sqlite3").exists());
    let workspace = Workspace::open(&root, &[1; 32])?;
    let rebuilt = workspace.begin_build()?;
    assert_eq!(fs::read_dir(&rebuilt)?.count(), 0);
    workspace.cleanup_build()?;
    assert!(!build.exists());
    Ok(())
}

#[test]
fn recovery_workspace_preserves_published_state_and_unknown_build_content()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().join("work");
    let workspace = Workspace::open(&root, &[1; 32])?;
    let build = workspace.begin_build()?;
    let snapshot = build.join("snapshot.sqlite3");
    fs::write(&snapshot, b"complete isolated state")?;
    workspace.publish_database(&snapshot)?;
    assert_eq!(
        fs::metadata(root.join("prepared.sqlite3"))?
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    fs::write(build.join("unrelated.txt"), b"keep me")?;
    assert!(matches!(workspace.cleanup_build(), Err(Error::Cleanup)));
    assert_eq!(fs::read(&snapshot)?, b"complete isolated state");
    assert_eq!(fs::read(build.join("unrelated.txt"))?, b"keep me");
    fs::remove_file(build.join("unrelated.txt"))?;
    workspace.cleanup_build()?;
    assert_eq!(
        fs::read(root.join("prepared.sqlite3"))?,
        b"complete isolated state"
    );
    drop(workspace);
    let workspace = Workspace::open(&root, &[1; 32])?;
    let build = workspace.begin_build()?;
    fs::write(build.join("snapshot.sqlite3"), b"replacement")?;
    assert!(
        workspace
            .publish_database(&build.join("snapshot.sqlite3"))
            .is_err()
    );
    assert_eq!(
        fs::read(root.join("prepared.sqlite3"))?,
        b"complete isolated state"
    );
    workspace.cleanup_build()?;
    Ok(())
}

#[test]
fn recovery_workspace_recovers_interrupted_marker_but_rejects_unowned_directories()
-> Result<(), Box<dyn std::error::Error>> {
    let temp = tempfile::tempdir()?;
    let root = temp.path().join("work");
    fs::create_dir(&root)?;
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))?;
    fs::write(root.join(".intent.meshspan-0.tmp"), b"partial marker")?;
    let workspace = Workspace::open(&root, &[1; 32])?;
    assert_eq!(fs::read(root.join("intent"))?, vec![1; 32]);
    assert!(!root.join(".intent.meshspan-0.tmp").exists());
    drop(workspace);
    fs::remove_file(root.join("intent"))?;
    fs::write(root.join("prepared.sqlite3"), b"do not adopt this file")?;
    assert!(matches!(
        Workspace::open(&root, &[1; 32]),
        Err(Error::Conflict)
    ));
    assert_eq!(
        fs::read(root.join("prepared.sqlite3"))?,
        b"do not adopt this file"
    );
    Ok(())
}
