// SPDX-License-Identifier: GPL-2.0-only

//! Bounded blocking-provider/async-HTTP bridge with cancellation and a hard transfer deadline.

use axum::body::{Body, Bytes, HttpBody};
use hyper::body::{Frame, SizeHint};
use std::{
    future::Future,
    io::{self, Write},
    pin::{Pin, pin},
    sync::Arc,
    task::{Context, Poll, Wake, Waker},
    thread,
    time::{Duration, Instant},
};
use tokio::{sync::mpsc, task::JoinHandle};

const CHANNEL_FRAMES: usize = 2;
const FRAME_BYTES: usize = 64 * 1024;

/// Runs an owned blocking export job; dropping the body closes its sink immediately.
pub(crate) fn body(
    job: impl FnOnce(&mut dyn Write) -> io::Result<()> + Send + 'static,
    timeout: Duration,
) -> Body {
    let (sender, receiver) = mpsc::channel(CHANNEL_FRAMES);
    // The router validates configured limits. Fail immediately if an extreme direct
    // caller still exceeds the platform clock range; never panic in body construction.
    let deadline = Instant::now()
        .checked_add(timeout)
        .unwrap_or_else(Instant::now);
    let worker = tokio::task::spawn_blocking(move || {
        let mut sink = ChannelWriter { sender, deadline };
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
    deadline: Instant,
}

impl ChannelWriter {
    fn send_frame(&self, frame: Bytes) -> io::Result<()> {
        // The provider owns this blocking thread, but a remote provider may already be inside
        // Handle::block_on while fetching bytes. Poll only the channel future here: its receiver
        // wakes this thread when capacity opens or the body is dropped. No nested executor,
        // reactor or timer is needed; a parked writer still has an absolute monotonic deadline.
        let waker = Waker::from(Arc::new(WriterWake(thread::current())));
        let mut context = Context::from_waker(&waker);
        let mut send = pin!(self.sender.send(frame));
        loop {
            let remaining = self.deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "backup export deadline elapsed",
                ));
            }
            match send.as_mut().poll(&mut context) {
                Poll::Ready(result) => {
                    return result.map_err(|_| {
                        io::Error::new(io::ErrorKind::BrokenPipe, "backup export receiver closed")
                    });
                }
                // An unpark racing with this call retains its token. Spurious wakes simply
                // re-poll the channel and recompute the unchanged remaining deadline.
                Poll::Pending => thread::park_timeout(remaining),
            }
        }
    }
}

struct WriterWake(thread::Thread);

impl Wake for WriterWake {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
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
        self.send_frame(frame)?;
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
