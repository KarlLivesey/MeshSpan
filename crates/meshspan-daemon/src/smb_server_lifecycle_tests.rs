// SPDX-License-Identifier: GPL-2.0-only

use std::sync::{Arc, Mutex, mpsc};
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::{Notify, oneshot};
use tokio::time::timeout;

use super::{SmbConnectionHandler, SmbHandlerFuture, SmbServer, SmbServerLimits};

#[tokio::test]
async fn idle_maintenance_preserves_partial_frames_and_observes_cleanup()
-> Result<(), Box<dyn std::error::Error>> {
    let handler = MaintainedEcho {
        maintained: Arc::new(Notify::new()),
        shutdowns: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
    };
    let maintained = Arc::clone(&handler.maintained);
    let shutdowns = Arc::clone(&handler.shutdowns);
    let server = SmbServer::bind(
        "127.0.0.1:0".parse()?,
        SmbServerLimits::new(1_024, Duration::from_secs(2))?,
    )
    .await?;
    let address = server.local_addr()?;
    let (stop, stopped) = oneshot::channel();
    let observations = Arc::new(crate::runtime_observations::RuntimeObservations::default());
    let task = tokio::spawn(server.run_until(
        move || {
            Ok::<_, &'static str>(crate::gateway_measurements::ObservedSmbHandler::new(
                handler.clone(),
                observations.clone(),
            ))
        },
        async {
            drop(stopped.await);
        },
    ));
    let mut client = TcpStream::connect(address).await?;
    let proof = async {
        client.write_all(&[0, 0]).await?;
        timeout(Duration::from_secs(2), maintained.notified()).await?;
        client.write_all(&[0, 64]).await?;
        client.write_all(&[7; 64]).await?;
        let mut response = [0; 68];
        timeout(
            Duration::from_secs(2),
            tokio::io::AsyncReadExt::read_exact(&mut client, &mut response),
        )
        .await??;
        assert_eq!(&response[..4], &[0, 0, 0, 64]);
        assert_eq!(&response[4..], &[7; 64]);
        Ok::<_, Box<dyn std::error::Error>>(())
    }
    .await;
    stop.send(())
        .map_err(|()| "listener stopped before cancellation")?;
    drop(client);
    timeout(Duration::from_secs(2), task).await???;
    proof?;
    assert_eq!(shutdowns.load(std::sync::atomic::Ordering::SeqCst), 1);
    Ok(())
}

#[derive(Clone)]
struct MaintainedEcho {
    maintained: Arc<Notify>,
    shutdowns: Arc<std::sync::atomic::AtomicUsize>,
}

impl SmbConnectionHandler for MaintainedEcho {
    type Error = &'static str;

    fn handle(&mut self, request: Vec<u8>) -> SmbHandlerFuture<'_, Self::Error> {
        Box::pin(async { Ok(Some(request)) })
    }

    fn maintain(
        &mut self,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Duration, Self::Error>> + Send + '_>,
    > {
        Box::pin(async {
            self.maintained.notify_one();
            Ok(Duration::from_secs(1))
        })
    }

    fn shutdown(
        &mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Self::Error>> + Send + '_>>
    {
        Box::pin(async {
            self.shutdowns
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Ok(())
        })
    }
}

#[tokio::test]
#[ignore = "31-second proof that shutdown never abandons an owned blocking SMB operation"]
async fn shutdown_observes_blocking_work_past_the_old_drain_deadline()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let marker = directory.path().join("completed");
    let (release, released) = mpsc::channel();
    let handler = BlockingHandler {
        released: Arc::new(Mutex::new(Some(released))),
        marker: marker.clone(),
        started: Arc::new(Notify::new()),
        completed: Arc::new(Notify::new()),
    };
    let started = Arc::clone(&handler.started);
    let completed = Arc::clone(&handler.completed);
    let server = SmbServer::bind(
        "127.0.0.1:0".parse()?,
        SmbServerLimits::new(1_024, Duration::from_secs(2))?,
    )
    .await?;
    let address = server.local_addr()?;
    let (stop, stopped) = oneshot::channel();
    let mut task = tokio::spawn(server.run_until(
        move || Ok::<_, &'static str>(handler.clone()),
        async {
            drop(stopped.await);
        },
    ));
    let mut client = TcpStream::connect(address).await?;
    client.write_all(&[0, 0, 0, 64]).await?;
    client.write_all(&[0; 64]).await?;
    timeout(Duration::from_secs(2), started.notified()).await?;
    stop.send(())
        .map_err(|()| "listener stopped before cancellation")?;
    let premature = timeout(Duration::from_secs(31), &mut task).await;
    release.send(())?;
    timeout(Duration::from_secs(2), completed.notified()).await?;
    assert_eq!(std::fs::read(&marker)?, b"completed owned work");
    if let Ok(result) = premature {
        result??;
        return Err("SMB listener returned before its owned blocking operation completed".into());
    }
    timeout(Duration::from_secs(2), task).await???;
    Ok(())
}

#[derive(Clone)]
struct BlockingHandler {
    released: Arc<Mutex<Option<mpsc::Receiver<()>>>>,
    marker: std::path::PathBuf,
    started: Arc<Notify>,
    completed: Arc<Notify>,
}

impl SmbConnectionHandler for BlockingHandler {
    type Error = &'static str;

    fn handle(&mut self, _request: Vec<u8>) -> SmbHandlerFuture<'_, Self::Error> {
        Box::pin(async move {
            let released = self
                .released
                .lock()
                .map_err(|_| "release lock poisoned")?
                .take()
                .ok_or("duplicate blocking request")?;
            let started = Arc::clone(&self.started);
            let completed = Arc::clone(&self.completed);
            let marker = self.marker.clone();
            tokio::task::spawn_blocking(move || {
                started.notify_one();
                let result = released
                    .recv_timeout(Duration::from_secs(40))
                    .map_err(|_| "controlled worker was not released")
                    .and_then(|()| {
                        std::fs::write(marker, b"completed owned work")
                            .map_err(|_| "owned write failed")
                    });
                completed.notify_one();
                result
            })
            .await
            .map_err(|_| "worker join failed")??;
            Ok(None)
        })
    }
}

#[tokio::test]
async fn cleanup_failure_retains_dispatch_failure_after_other_clients_are_drained()
-> Result<(), Box<dyn std::error::Error>> {
    let server = SmbServer::bind(
        "127.0.0.1:0".parse()?,
        SmbServerLimits::new(1_024, Duration::from_secs(2))?,
    )
    .await?;
    let address = server.local_addr()?;
    let closed = Arc::new(Notify::new());
    let handler_closed = Arc::clone(&closed);
    let (stop, stopped) = oneshot::channel();
    let task = tokio::spawn(server.run_until(
        move || Ok::<_, &'static str>(FailingCleanup(Arc::clone(&handler_closed))),
        async {
            drop(stopped.await);
        },
    ));
    let mut client = TcpStream::connect(address).await?;
    client.write_all(&[0, 0, 0, 64]).await?;
    client.write_all(&[0; 64]).await?;
    timeout(Duration::from_secs(2), closed.notified()).await?;
    stop.send(()).map_err(|()| "listener stopped early")?;
    let result = timeout(Duration::from_secs(2), task).await??;
    match result {
        Err(super::SmbServerError::Cleanup {
            primary,
            first,
            additional_failures,
        }) => {
            assert!(primary.is_none());
            assert!(first.contains("original dispatch failure"));
            assert!(first.contains("cleanup failure"));
            assert_eq!(additional_failures, 0);
        }
        other => return Err(format!("expected retained cleanup failure, got {other:?}").into()),
    }
    Ok(())
}

struct FailingCleanup(Arc<Notify>);

impl SmbConnectionHandler for FailingCleanup {
    type Error = &'static str;

    fn handle(&mut self, _request: Vec<u8>) -> SmbHandlerFuture<'_, Self::Error> {
        Box::pin(async { Err("original dispatch failure") })
    }

    fn shutdown(
        &mut self,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), Self::Error>> + Send + '_>>
    {
        Box::pin(async {
            self.0.notify_one();
            Err("cleanup failure")
        })
    }
}

#[test]
fn failure_report_bounds_multibyte_handler_messages() {
    let message = "λ".repeat(1_000);
    let report = super::bounded_failure(format_args!("{message}"), 512);
    assert_eq!(report.len(), 512);
    assert_eq!(report.chars().count(), 256);
}
