// SPDX-License-Identifier: GPL-2.0-only

//! Withheld native store acknowledgement and replacement-consumer reconciliation.

use super::{
    BackupObjectIdentity, Client, DataFrame, FederatedBackupRequest, FederatedBackupScope, Message,
    PAYLOAD, RunningAuthority, StreamKind, TestResult, context, open_stream, receive_federation,
    replay, send_data_frame, send_federation,
};
use meshspan_domain::Clock;

impl Client<'_, '_> {
    pub(super) async fn recover_lost_store_result(
        &mut self,
        provider: &RunningAuthority,
        consumer: &RunningAuthority,
        object: BackupObjectIdentity,
    ) -> TestResult<()> {
        let request = FederatedBackupRequest::Store(meshspan_contracts::BackupStoreRequest {
            context: context(192)?,
            object,
        });
        let outbound = self.permit(&request).await?;
        let limits = self.session.limits.wire;
        let (mut send, mut receive) =
            open_stream(&self.session.connection, StreamKind::Federation).await?;
        send_federation(&mut send, outbound.envelope(), limits).await?;
        let ready = receive_federation(&mut receive, limits).await?;
        let ready = self.peers.authenticate_backup_response(
            &self.session.connection,
            &ready,
            &outbound.expectation()?,
            crate::OperatingSystemClock.now(),
            &mut replay()?,
        )?;
        ready.result_expectation()?;
        send_data_frame(
            &mut send,
            &DataFrame {
                offset: 0,
                bytes: PAYLOAD.to_vec(),
            },
            limits,
        )
        .await?;
        send.finish()?;
        // A fault at the client transport boundary consumes but withholds the final
        // response. No authenticated receipt/reference reaches the consumer. Receiving
        // it synchronises the fixture with server completion without a timing sleep.
        let discarded = receive_federation(&mut receive, limits).await?;
        assert!(matches!(
            discarded.as_inner().message,
            Some(Message::BackupResult(_))
        ));
        drop(discarded);
        drop(receive);
        drop(send);
        assert_usage(provider, self.scope, object.byte_length, 0)?;

        let authority = super::super::super::authority(consumer)?;
        let before = authority
            .reader()
            .federated_backup_route(object.backup_id, object.destination_id)?
            .ok_or("route before receipt recovery")?;
        assert!(
            authority
                .reader()
                .metadata_backup(object.backup_id)?
                .is_none()
        );
        assert!(
            authority
                .reader()
                .backup_copy(object.backup_id, object.destination_id)?
                .is_none()
        );
        // Recover the provider-owned reference through authenticated lookup, not a folder formula.
        let recovered =
            super::super::routing::lookup_provider(consumer, self.consumer, object, 193)?;
        super::super::routing::verify_provider(
            consumer,
            self.consumer,
            object,
            &recovered.object_reference,
            194,
        )?;
        assert_eq!(
            authority
                .reader()
                .federated_backup_route(object.backup_id, object.destination_id)?,
            Some(before)
        );
        assert_usage(provider, self.scope, object.byte_length, 0)
    }
}

pub(super) fn assert_usage(
    provider: &RunningAuthority,
    scope: FederatedBackupScope,
    committed: u64,
    reserved: u64,
) -> TestResult<()> {
    let local = meshspan_metadata::LocalDatabase::open_existing(
        &provider.directory.path().join("local.sqlite3"),
        crate::OperatingSystemClock.now(),
    )?;
    let usage = local
        .federated_storage_usage(scope.allocation_id)?
        .ok_or("allocation usage")?;
    assert_eq!(
        (usage.committed_bytes, usage.reserved_bytes),
        (committed, reserved)
    );
    Ok(())
}
