// SPDX-License-Identifier: GPL-2.0-only

use crate::backup_export_body::body;
use axum::body::to_bytes;
use std::{io, time::Duration};

#[tokio::test]
async fn backup_export_remote_provider_can_write_inside_its_async_fetch()
-> Result<(), Box<dyn std::error::Error>> {
    let runtime = tokio::runtime::Handle::current();
    // Larger than both channel slots: the remote fetch must make progress with backpressure,
    // not merely avoid a nested-runtime panic for one immediately accepted frame.
    let content = (0_u8..251)
        .cycle()
        .take(3 * 64 * 1024 + 17)
        .collect::<Vec<_>>();
    let expected = content.clone();
    let download = body(
        move |sink| {
            runtime.block_on(async {
                tokio::task::yield_now().await;
                sink.write_all(&content)
            })
        },
        Duration::from_secs(2),
    );
    let received =
        tokio::time::timeout(Duration::from_secs(3), to_bytes(download, expected.len())).await??;
    assert_eq!(received.as_ref(), expected);
    Ok(())
}

#[tokio::test]
async fn backup_export_drop_closes_a_backpressured_writer() -> Result<(), Box<dyn std::error::Error>>
{
    let (completed, outcome) = tokio::sync::oneshot::channel();
    let (started, running) = tokio::sync::oneshot::channel();
    let download = body(
        move |sink| {
            let _ = started.send(());
            let result = sink.write_all(&vec![1; 1024 * 1024]);
            let kind = result.as_ref().err().map(io::Error::kind);
            let _ = completed.send(kind);
            result
        },
        Duration::from_secs(5),
    );
    running.await?;
    drop(download);
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), outcome).await??,
        Some(io::ErrorKind::BrokenPipe)
    );
    Ok(())
}

#[tokio::test]
async fn backup_export_stalled_receiver_expires_without_buffering_whole_object()
-> Result<(), Box<dyn std::error::Error>> {
    let (completed, outcome) = tokio::sync::oneshot::channel();
    let download = body(
        move |sink| {
            let result = sink.write_all(&vec![1; 1024 * 1024]);
            let kind = result.as_ref().err().map(io::Error::kind);
            let _ = completed.send(kind);
            result
        },
        Duration::from_millis(25),
    );
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(1), outcome).await??,
        Some(io::ErrorKind::TimedOut)
    );
    assert!(to_bytes(download, 1024 * 1024).await.is_err());
    Ok(())
}

#[tokio::test]
async fn backup_export_failed_worker_is_not_successful_eof() {
    let download = body(
        |_| Err(io::Error::other("private provider detail")),
        Duration::from_secs(1),
    );
    let outcome = to_bytes(download, 1).await;
    assert!(outcome.is_err());
    assert!(!format!("{outcome:?}").contains("private provider detail"));
}
