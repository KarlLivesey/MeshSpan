// SPDX-License-Identifier: GPL-2.0-only

//! One verified history connection per private runtime, with SQL kept off async workers.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use meshspan_domain::Clock as _;
use meshspan_filesystem::VersionPublicationStore;

use super::NativeGatewaySyncError;

#[derive(Clone)]
pub(crate) struct NativeGatewayHistory {
    pub(super) state_directory: PathBuf,
    store: Arc<Mutex<Option<VersionPublicationStore>>>,
}

impl NativeGatewayHistory {
    pub(crate) fn new(state_directory: &Path) -> Self {
        Self {
            state_directory: state_directory.to_path_buf(),
            store: Arc::new(Mutex::new(None)),
        }
    }

    /// The control runtime bounds callers. The mutex guards only a synchronous SQL operation;
    /// no network await or transaction crosses this worker's lifetime. Returned rows are owned.
    pub(super) async fn execute<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&mut VersionPublicationStore) -> Result<T, NativeGatewaySyncError>
        + Send
        + 'static,
    ) -> Result<T, NativeGatewaySyncError> {
        let history = self.clone();
        tokio::task::spawn_blocking(move || {
            let mut slot = history
                .store
                .lock()
                .map_err(|_| NativeGatewaySyncError::Unavailable)?;
            if slot.is_none() {
                let now = crate::OperatingSystemClock.now();
                *slot = Some(
                    VersionPublicationStore::open(&history.state_directory.join("filesystem"), now)
                        .map_err(|_| NativeGatewaySyncError::Unavailable)?,
                );
            }
            operation(slot.as_mut().ok_or(NativeGatewaySyncError::Unavailable)?)
        })
        .await
        .map_err(|_| NativeGatewaySyncError::Unavailable)?
    }
}

#[cfg(test)]
mod tests {
    use meshspan_domain::{NamespaceCommitId, UnixMicros, VolumeId};
    use meshspan_filesystem::{NamespaceHistoryLimits, NamespaceHistoryReceiveRequest};

    use super::*;

    #[tokio::test]
    async fn shared_history_observes_external_commits_and_preserves_scope_checks()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let history = NativeGatewayHistory::new(directory.path());
        let first = request(1)?;
        let initial = history
            .execute(move |store| {
                store
                    .begin_namespace_history_receive(&first)
                    .map_err(|_| NativeGatewaySyncError::Invalid)
            })
            .await?;
        assert_eq!(initial.commits, 0);
        assert!(!initial.completed);

        let second = request(2)?;
        let mut external = VersionPublicationStore::open(
            &directory.path().join("filesystem"),
            UnixMicros::new(11),
        )?;
        let expected = external.begin_namespace_history_receive(&second)?;
        drop(external);
        let replay = second.clone();
        assert_eq!(
            history
                .execute(move |store| store
                    .begin_namespace_history_receive(&replay)
                    .map_err(|_| NativeGatewaySyncError::Invalid))
                .await?,
            expected
        );

        let mut substituted = second.clone();
        substituted.scope_binding = [9; 32];
        assert!(matches!(
            history
                .execute(move |store| store
                    .begin_namespace_history_receive(&substituted)
                    .map_err(|_| NativeGatewaySyncError::Invalid))
                .await,
            Err(NativeGatewaySyncError::Invalid)
        ));
        let retry = second.clone();
        assert_eq!(
            history
                .execute(move |store| store
                    .begin_namespace_history_receive(&retry)
                    .map_err(|_| NativeGatewaySyncError::Invalid))
                .await?,
            expected
        );
        drop(history);
        let reopened = NativeGatewayHistory::new(directory.path());
        assert_eq!(
            reopened
                .execute(move |store| store
                    .begin_namespace_history_receive(&second)
                    .map_err(|_| NativeGatewaySyncError::Invalid))
                .await?,
            expected
        );
        Ok(())
    }

    #[tokio::test]
    async fn history_refuses_corrupt_database_before_serving_any_operation()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        std::fs::create_dir(directory.path().join("filesystem"))?;
        let database = directory
            .path()
            .join("filesystem/filesystem-branch.sqlite3");
        std::fs::write(&database, b"not a SQLite database")?;
        let history = NativeGatewayHistory::new(directory.path());
        assert!(matches!(
            history.execute(|_| Ok(())).await,
            Err(NativeGatewaySyncError::Unavailable)
        ));
        assert_eq!(std::fs::read(database)?, b"not a SQLite database");
        Ok(())
    }

    fn request(seed: u8) -> Result<NamespaceHistoryReceiveRequest, Box<dyn std::error::Error>> {
        Ok(NamespaceHistoryReceiveRequest {
            session_id: [seed; 32],
            scope_binding: [3; 32],
            volume_id: VolumeId::from_bytes([4; 16])?,
            requested_heads: vec![NamespaceCommitId::from_bytes([5; 16])?],
            limits: NamespaceHistoryLimits::DEFAULT,
            now: UnixMicros::new(10),
            expires_at: UnixMicros::new(20),
        })
    }
}
