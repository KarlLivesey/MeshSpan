// SPDX-License-Identifier: GPL-2.0-only

//! Bounded blocking-provider/async-HTTP bridge with cancellation and a hard transfer deadline.

use axum::body::{Body, Bytes, HttpBody};
use hyper::body::{Frame, SizeHint};
use std::{
    future::Future,
    io::{self, Write},
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::{runtime::Handle, sync::mpsc, task::JoinHandle, time::Instant};

const CHANNEL_FRAMES: usize = 2;
const FRAME_BYTES: usize = 64 * 1024;

/// Runs an owned blocking export job; dropping the body closes its sink immediately.
pub(crate) fn body(
    job: impl FnOnce(&mut dyn Write) -> io::Result<()> + Send + 'static,
    timeout: Duration,
) -> Body {
    let (sender, receiver) = mpsc::channel(CHANNEL_FRAMES);
    let runtime = Handle::current();
    // The router validates configured limits. Fail immediately if an extreme direct
    // caller still exceeds the platform clock range; never panic in body construction.
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    let worker = tokio::task::spawn_blocking(move || {
        let mut sink = ChannelWriter {
            sender,
            runtime,
            deadline,
        };
        job(&mut sink)
    });
    Body::new(ExportBody {
        receiver,
        worker,
        finished: false,
    })
}

struct ChannelWriter {
    sender: mpsc::Sender<Bytes>,
    runtime: Handle,
    deadline: Instant,
}

impl Write for ChannelWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if bytes.is_empty() {
            return Ok(0);
        }
        if Instant::now() >= self.deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "backup export deadline elapsed",
            ));
        }
        let count = bytes.len().min(FRAME_BYTES);
        let frame = Bytes::copy_from_slice(bytes.get(..count).ok_or_else(failed)?);
        self.runtime.block_on(async {
            tokio::time::timeout_at(self.deadline, self.sender.send(frame))
                .await
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::TimedOut, "backup export deadline elapsed")
                })?
                .map_err(|_| {
                    io::Error::new(io::ErrorKind::BrokenPipe, "backup export receiver closed")
                })
        })?;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

struct ExportBody {
    receiver: mpsc::Receiver<Bytes>,
    worker: JoinHandle<io::Result<()>>,
    finished: bool,
}

impl HttpBody for ExportBody {
    type Data = Bytes;
    type Error = io::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        if self.finished {
            return Poll::Ready(None);
        }
        match self.receiver.poll_recv(context) {
            Poll::Ready(Some(frame)) => return Poll::Ready(Some(Ok(Frame::data(frame)))),
            Poll::Pending => return Poll::Pending,
            Poll::Ready(None) => {}
        }
        match Pin::new(&mut self.worker).poll(context) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(outcome) => {
                self.finished = true;
                Poll::Ready(match outcome {
                    Ok(Ok(())) => None,
                    Ok(Err(_)) | Err(_) => Some(Err(failed())),
                })
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.finished
    }
    fn size_hint(&self) -> SizeHint {
        SizeHint::default()
    }
}

impl Drop for ExportBody {
    fn drop(&mut self) {
        self.receiver.close();
        // Cancel queued work. A running blocking provider cannot be forcibly interrupted;
        // closing the sink wakes blocked writes and its transfer deadline bounds remaining IO.
        if !self.finished {
            self.worker.abort();
        }
    }
}

fn failed() -> io::Error {
    io::Error::other("backup export did not complete")
}
