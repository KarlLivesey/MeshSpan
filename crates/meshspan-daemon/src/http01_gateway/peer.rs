// SPDX-License-Identifier: GPL-2.0-only

//! One lazily opened reader per private runtime; requests never reopen/check the whole database.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use meshspan_cluster::{ConsensusNetwork, PeerControlRequest};
use meshspan_domain::{Clock as _, OperationId};
use meshspan_metadata::{AuthoritativeRepository, PartitionDatabase};
use meshspan_protocol::v1::{ControlEnvelope, Http01ChallengeResult, control_envelope::Message};

use crate::OperatingSystemClock;

#[derive(Clone)]
pub(crate) struct Http01PeerReader {
    database: PathBuf,
    reader: Arc<Mutex<Option<AuthoritativeRepository>>>,
}

impl Http01PeerReader {
    pub(crate) fn new(state_directory: &Path) -> Self {
        Self {
            database: state_directory.join("root-authority.sqlite3"),
            reader: Arc::default(),
        }
    }

    pub(crate) async fn handle(
        &self,
        network: &ConsensusNetwork,
        request: &PeerControlRequest,
    ) -> Result<ControlEnvelope, ()> {
        let envelope = request.envelope.as_inner();
        let header = envelope.header.as_ref().ok_or(())?;
        let Some(Message::FetchHttp01Challenge(query)) = &envelope.message else {
            return Err(());
        };
        let now = OperatingSystemClock.now();
        if header.deadline_unix_micros <= now.get() {
            return Err(());
        }
        let operation_id =
            OperationId::from_bytes(header.operation_id.as_slice().try_into().map_err(|_| ())?)
                .map_err(|_| ())?;
        let source = self.clone();
        let token = query.token.clone();
        let proof = tokio::task::spawn_blocking(move || {
            let mut reader = source.reader.lock().map_err(|_| ())?;
            if reader.is_none() {
                *reader = Some(AuthoritativeRepository::new(
                    PartitionDatabase::open_existing(&source.database, now).map_err(|_| ())?,
                ));
            }
            reader
                .as_ref()
                .ok_or(())?
                .public_http01_response(&token, OperatingSystemClock.now())
                .map_err(|_| ())
        })
        .await
        .map_err(|_| ())??;
        if header.deadline_unix_micros <= OperatingSystemClock.now().get() {
            return Err(());
        }
        Ok(ControlEnvelope {
            header: Some(
                network
                    .control_header(operation_id, header.deadline_unix_micros)
                    .map_err(|_| ())?,
            ),
            message: Some(Message::Http01ChallengeResult(Http01ChallengeResult {
                token: query.token.clone(),
                key_authorization: proof.as_ref().map(|(body, _)| body.clone()),
                expires_at_unix_micros: proof.map(|(_, expiry)| expiry.get()),
            })),
        })
    }
}
