// SPDX-License-Identifier: GPL-2.0-only

//! Observe completed IO polls without buffering, waiting, or altering transport behaviour.

use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use meshspan_contracts::{GatewayProtocol, GatewayTransferMetric, GatewayTransferObserver};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pub(crate) struct ObservedGatewayIo<IO> {
    inner: IO,
    protocol: GatewayProtocol,
    observer: Option<Arc<dyn GatewayTransferObserver>>,
}

impl<IO> ObservedGatewayIo<IO> {
    pub(crate) fn new(
        inner: IO,
        protocol: GatewayProtocol,
        observer: Option<Arc<dyn GatewayTransferObserver>>,
    ) -> Self {
        Self {
            inner,
            protocol,
            observer,
        }
    }

    fn observe(&self, increment: GatewayTransferMetric) {
        if let Some(observer) = &self.observer {
            observer.observe_transfer(self.protocol, increment);
        }
    }

    fn written(&self, result: &Poll<io::Result<usize>>) {
        match result {
            Poll::Ready(Ok(bytes)) => self.observe(GatewayTransferMetric::SentBytes(*bytes as u64)),
            Poll::Ready(Err(_)) => self.observe(GatewayTransferMetric::WriteErrors(1)),
            Poll::Pending => {}
        }
    }
}

impl<IO: AsyncRead + Unpin> AsyncRead for ObservedGatewayIo<IO> {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buffer.filled().len();
        let result = Pin::new(&mut this.inner).poll_read(context, buffer);
        match &result {
            Poll::Ready(Ok(())) => {
                let bytes = buffer.filled().len() - before;
                if bytes != 0 {
                    this.observe(GatewayTransferMetric::ReceivedBytes(bytes as u64));
                }
            }
            Poll::Ready(Err(_)) => this.observe(GatewayTransferMetric::ReadErrors(1)),
            Poll::Pending => {}
        }
        result
    }
}

impl<IO: AsyncWrite + Unpin> AsyncWrite for ObservedGatewayIo<IO> {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write(context, buffer);
        this.written(&result);
        result
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffers: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_write_vectored(context, buffers);
        this.written(&result);
        result
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_flush(context);
        if matches!(&result, Poll::Ready(Err(_))) {
            this.observe(GatewayTransferMetric::WriteErrors(1));
        }
        result
    }

    fn poll_shutdown(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.inner).poll_shutdown(context);
        if matches!(&result, Poll::Ready(Err(_))) {
            this.observe(GatewayTransferMetric::WriteErrors(1));
        }
        result
    }
}

#[cfg(test)]
#[path = "gateway_transfer_io_tests.rs"]
mod tests;
