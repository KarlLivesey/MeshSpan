// SPDX-License-Identifier: GPL-2.0-only

//! Owns Quinn's endpoint and connection drivers through preparation and terminal drainage.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::task::JoinSet;

// Resource admission, not a membership limit. Two endpoints plus at most 16,384 connection
// drivers (including completed drivers awaiting observation) share one transport generation.
const MAXIMUM_DRIVERS: usize = 16_386;
type Driver = Pin<Box<dyn Future<Output = ()> + Send>>;

enum Admission {
    Preparing(Vec<Driver>),
    Running(JoinSet<()>),
    Closed,
}

enum Drain {
    Pending,
    Joining(JoinSet<()>),
    Completed(Result<(), ()>),
}

pub(super) struct Drivers {
    admission: Mutex<Admission>,
    drain: tokio::sync::Mutex<Drain>,
    failures: AtomicU64,
    maximum: usize,
}

impl Drivers {
    pub(super) fn prepare() -> Arc<Self> {
        Arc::new(Self {
            admission: Mutex::new(Admission::Preparing(Vec::with_capacity(2))),
            drain: tokio::sync::Mutex::new(Drain::Pending),
            failures: AtomicU64::new(0),
            maximum: MAXIMUM_DRIVERS,
        })
    }

    pub(super) fn start(&self) {
        let mut admission = self.admission();
        let Admission::Preparing(prepared) = &mut *admission else {
            self.failed();
            return;
        };
        let mut jobs = JoinSet::new();
        for driver in std::mem::take(prepared) {
            jobs.spawn(driver);
        }
        *admission = Admission::Running(jobs);
    }

    pub(super) fn abort_preparation(&self) -> bool {
        let prepared = {
            let mut admission = self.admission();
            if !matches!(*admission, Admission::Preparing(_)) {
                return false;
            }
            std::mem::replace(&mut *admission, Admission::Closed)
        };
        // No runtime task was started: dropping queued driver futures releases their sockets
        // synchronously, including when constructing the second endpoint failed.
        drop(prepared);
        true
    }

    pub(super) async fn shutdown(&self) -> Result<(), ()> {
        // The shared state retains the JoinSet across cancellation. Never move it into the
        // calling future. Registration only takes the sync gate and never takes this lock.
        let mut drain = self.drain.lock().await;
        if matches!(*drain, Drain::Pending) {
            let admission = std::mem::replace(&mut *self.admission(), Admission::Closed);
            *drain = match admission {
                Admission::Running(mut jobs) => {
                    // MeshSpan workers and endpoint references are already gone. Driver
                    // cancellation only stops residual QUIC timers/IO, not admitted operations.
                    jobs.abort_all();
                    Drain::Joining(jobs)
                }
                Admission::Preparing(_) | Admission::Closed => {
                    self.failed();
                    Drain::Joining(JoinSet::new())
                }
            };
        }
        match &mut *drain {
            Drain::Joining(jobs) => {
                while let Some(result) = jobs.join_next().await {
                    if let Err(error) = result
                        && !error.is_cancelled()
                    {
                        self.failed();
                    }
                }
            }
            Drain::Completed(result) => return *result,
            Drain::Pending => return Err(()),
        }
        let result = if self.failures.load(Ordering::Acquire) == 0 {
            Ok(())
        } else {
            Err(())
        };
        *drain = Drain::Completed(result);
        result
    }

    pub(super) fn failed(&self) {
        self.failures.fetch_add(1, Ordering::Relaxed);
    }

    fn admission(&self) -> MutexGuard<'_, Admission> {
        self.admission.lock().unwrap_or_else(|poisoned| {
            self.failed();
            poisoned.into_inner()
        })
    }
}

impl fmt::Debug for Drivers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Drivers").finish_non_exhaustive()
    }
}

impl quinn::Runtime for Drivers {
    fn new_timer(&self, instant: std::time::Instant) -> Pin<Box<dyn quinn::AsyncTimer>> {
        quinn::TokioRuntime.new_timer(instant)
    }

    fn spawn(&self, driver: Driver) {
        let mut admission = self.admission();
        match &mut *admission {
            Admission::Preparing(prepared) if prepared.len() < 2 => prepared.push(driver),
            Admission::Running(jobs) => {
                while let Some(result) = jobs.try_join_next() {
                    if result.is_err() {
                        self.failed();
                    }
                }
                if jobs.len() < self.maximum {
                    jobs.spawn(driver);
                } else {
                    // Runtime::spawn cannot return an error. Dropping the unstarted driver
                    // prevents that connection from completing its handshake. Its caller's
                    // deadline bounds the attempt; shutdown disposes any residual protocol state.
                    self.failed();
                }
            }
            Admission::Preparing(_) => self.failed(),
            Admission::Closed => {} // Closed transport admits no new driver or operation.
        }
    }

    fn wrap_udp_socket(
        &self,
        socket: std::net::UdpSocket,
    ) -> std::io::Result<Arc<dyn quinn::AsyncUdpSocket>> {
        quinn::TokioRuntime.wrap_udp_socket(socket)
    }

    fn now(&self) -> std::time::Instant {
        quinn::TokioRuntime.now()
    }
}

#[cfg(test)]
mod tests;
