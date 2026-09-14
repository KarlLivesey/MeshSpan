// SPDX-License-Identifier: GPL-2.0-only

//! Test-owned SQLite write locks establish a deterministic provider publication boundary.

use super::*;
use meshspan_domain::BackupDestinationId;
use rusqlite::{Connection, OpenFlags, params};
use sha2::{Digest as _, Sha256};

pub(super) struct ProviderGate {
    connection: Connection,
    objects: PathBuf,
    destination: BackupDestinationId,
}

pub(super) struct InterruptedUpload {
    pub object: BackupObjectIdentity,
    pub worker: NodeId,
    pub published_path: PathBuf,
}

pub(super) async fn lock_catalogues(
    fixtures: &[ProcessFixture; 3],
) -> TestResult<Vec<ProviderGate>> {
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        let mut catalogues = Vec::new();
        for fixture in fixtures {
            let directory = fixture.storage_path.join(".meshspan-backups");
            match fs::read_dir(directory) {
                Ok(entries) => {
                    for entry in entries {
                        let candidate = entry?.path().join("catalogue.sqlite3");
                        if candidate.is_file() {
                            catalogues.push(candidate);
                        }
                    }
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error.into()),
            }
        }
        if catalogues.len() == 3 {
            return catalogues
                .iter()
                .map(|file_path| lock_catalogue(file_path))
                .collect();
        }
        if Instant::now() >= deadline {
            return Err("three backup provider catalogues did not become ready".into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}

fn lock_catalogue(file_path: &Path) -> TestResult<ProviderGate> {
    let connection = Connection::open_with_flags(file_path, OpenFlags::SQLITE_OPEN_READ_WRITE)?;
    connection.busy_timeout(Duration::from_secs(2))?;
    let destination: Vec<u8> = connection.query_row(
        "SELECT destination_id FROM provider_state WHERE singleton = 1",
        [],
        |row| row.get(0),
    )?;
    let destination = BackupDestinationId::from_bytes(
        destination
            .try_into()
            .map_err(|_| "invalid provider destination")?,
    )?;
    connection.execute_batch("BEGIN IMMEDIATE")?;
    Ok(ProviderGate {
        connection,
        destination,
        objects: file_path
            .parent()
            .ok_or("catalogue parent missing")?
            .join("objects"),
    })
}

pub(super) fn release(gates: Vec<ProviderGate>) -> TestResult {
    for gate in gates {
        gate.connection.execute_batch("ROLLBACK")?;
    }
    Ok(())
}

pub(super) async fn wait_for_published_intent(
    fixture: &ProcessFixture,
    gates: &[ProviderGate],
    schedule: u64,
) -> TestResult<InterruptedUpload> {
    let repository = reader(fixture)?;
    let deadline = Instant::now() + WAIT_LIMIT;
    loop {
        if let Some(run) = repository.unfinished_metadata_backup_run()?
            && run.schedule_sequence >= schedule
        {
            for gate in gates {
                if let Some(intent) =
                    repository.backup_publication_intent(run.backup_id, gate.destination)?
                {
                    // This test targets this concrete provider's publication boundary. The
                    // filename is an observation only, never authority used by the product.
                    let published = gate.objects.join(format!(
                        "backup-{:032x}.msb",
                        u128::from_be_bytes(run.backup_id.as_bytes())
                    ));
                    if published.is_file() {
                        let bytes = fs::read(&published)?;
                        assert_eq!(bytes.len() as u64, intent.binding.object.byte_length);
                        assert_eq!(
                            <[u8; 32]>::from(Sha256::digest(&bytes)),
                            intent.binding.object.digest
                        );
                        assert!(repository.metadata_backup(run.backup_id)?.is_none());
                        let count: i64 = gate.connection.query_row(
                            "SELECT count(*) FROM backup_objects WHERE backup_id = ?1",
                            params![run.backup_id.as_bytes().as_slice()],
                            |row| row.get(0),
                        )?;
                        assert_eq!(count, 0, "gate must precede provider catalogue commit");
                        let claim = repository
                            .metadata_backup_run_claim(run.backup_id)?
                            .ok_or("publishing claim missing")?;
                        return Ok(InterruptedUpload {
                            object: intent.binding.object,
                            worker: claim.claim.worker_node_id,
                            published_path: published,
                        });
                    }
                }
            }
        }
        if Instant::now() >= deadline {
            return Err("no exact upload reached the locked provider catalogue".into());
        }
        sleep(RETRY_INTERVAL).await;
    }
}
