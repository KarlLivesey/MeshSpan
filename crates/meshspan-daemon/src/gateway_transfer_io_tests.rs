// SPDX-License-Identifier: GPL-2.0-only

use super::*;
use crate::runtime_observations::RuntimeObservations;
use meshspan_contracts::{RuntimeMetric, RuntimeMetricSource};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn partial_pending_vectored_io_and_eof_count_only_actual_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let observations = RuntimeObservations::default();
    let (stream, mut peer) = tokio::io::duplex(3);
    let mut stream = ObservedGatewayIo::new(
        stream,
        GatewayProtocol::Smb,
        Some(Arc::new(observations.clone())),
    );
    let mut bytes = [0; 8];
    let mut buffer = ReadBuf::new(&mut bytes);
    let mut context = Context::from_waker(std::task::Waker::noop());
    assert!(
        Pin::new(&mut stream)
            .poll_read(&mut context, &mut buffer)
            .is_pending()
    );
    assert_eq!(stream.write(b"abcdef").await?, 3);
    assert!(
        Pin::new(&mut stream)
            .poll_write(&mut context, b"more")
            .is_pending()
    );
    peer.read_exact(&mut bytes[..3]).await?;
    assert_eq!(&bytes[..3], b"abc");
    assert_eq!(
        stream
            .write_vectored(&[IoSlice::new(b"de"), IoSlice::new(b"fg")])
            .await?,
        3
    );
    peer.read_exact(&mut bytes[..3]).await?;
    assert_eq!(&bytes[..3], b"def");
    peer.write_all(b"xyz").await?;
    assert_eq!(stream.read(&mut bytes).await?, 3);
    assert_eq!(&bytes[..3], b"xyz");
    drop(peer);
    assert_eq!(stream.read(&mut bytes).await?, 0);
    assert!(stream.write(b"lost").await.is_err());
    let samples = observations.collect_metrics()?;
    for metric in [
        GatewayTransferMetric::ReceivedBytes(3),
        GatewayTransferMetric::SentBytes(6),
        GatewayTransferMetric::ReadErrors(0),
        GatewayTransferMetric::WriteErrors(1),
    ] {
        assert!(samples.samples().contains(&RuntimeMetric::GatewayTransfer(
            GatewayProtocol::Smb,
            metric
        )));
    }
    Ok(())
}

#[tokio::test]
async fn io_errors_preserve_failure_without_claiming_transferred_bytes()
-> Result<(), Box<dyn std::error::Error>> {
    let observations = RuntimeObservations::default();
    let mut stream = ObservedGatewayIo::new(
        FailedIo,
        GatewayProtocol::Https,
        Some(Arc::new(observations.clone())),
    );
    assert!(stream.read(&mut [0]).await.is_err());
    assert!(stream.write(b"not written").await.is_err());
    assert!(stream.flush().await.is_err());
    assert!(stream.shutdown().await.is_err());
    let samples = observations.collect_metrics()?;
    for metric in [
        GatewayTransferMetric::ReceivedBytes(0),
        GatewayTransferMetric::SentBytes(0),
        GatewayTransferMetric::ReadErrors(1),
        GatewayTransferMetric::WriteErrors(3),
    ] {
        assert!(samples.samples().contains(&RuntimeMetric::GatewayTransfer(
            GatewayProtocol::Https,
            metric
        )));
    }
    Ok(())
}

struct FailedIo;

impl AsyncRead for FailedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _: &mut Context<'_>,
        _: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::from(io::ErrorKind::ConnectionReset)))
    }
}

impl AsyncWrite for FailedIo {
    fn poll_write(self: Pin<&mut Self>, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<usize>> {
        Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
    }
}
