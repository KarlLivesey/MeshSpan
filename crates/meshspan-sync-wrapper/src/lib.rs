// SPDX-License-Identifier: GPL-2.0-only

//! Zero-cost static synchronisation proof for exclusively accessed values.
//!
//! Current Axum and Tower releases require the `sync_wrapper` package. Its upstream release is
//! Apache-2.0-only, so `MeshSpan` owns this deliberately narrow compatible surface. A wrapped value
//! is never exposed through shared access: every observation requires ownership or `&mut`. That
//! exclusivity is the complete safety argument for the `Sync` implementation and pinned
//! projection below.

#![no_std]
#![allow(unsafe_code)]

use core::fmt::{self, Debug, Formatter};
use core::pin::Pin;

/// Value which may be shared between threads but accessed only through ownership or `&mut`.
#[repr(transparent)]
pub struct SyncWrapper<T> {
    value: T,
}

impl<T> SyncWrapper<T> {
    /// Wraps one value without allocation or locking.
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self { value }
    }

    /// Returns the value through the caller's exclusive reference.
    #[must_use]
    pub const fn get_mut(&mut self) -> &mut T {
        &mut self.value
    }

    /// Projects an exclusive pinned wrapper reference to its value.
    #[must_use]
    pub fn get_pin_mut(self: Pin<&mut Self>) -> Pin<&mut T> {
        // SAFETY: `value` is structurally pinned with its transparent wrapper. This type never
        // moves or replaces `value` through a pinned reference, and every exposed value reference
        // is exclusive.
        unsafe { self.map_unchecked_mut(|wrapper| &mut wrapper.value) }
    }

    /// Consumes the wrapper and returns its value.
    #[must_use]
    pub fn into_inner(self) -> T {
        self.value
    }
}

// SAFETY: shared references expose no operation that observes or mutates `T`. Access to `T`
// requires ownership or an exclusive reference, both of which the Rust aliasing rules enforce.
unsafe impl<T> Sync for SyncWrapper<T> {}

impl<T> Debug for SyncWrapper<T> {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
        formatter.write_str("SyncWrapper")
    }
}

impl<T: Default> Default for SyncWrapper<T> {
    fn default() -> Self {
        Self::new(T::default())
    }
}

impl<T> From<T> for SyncWrapper<T> {
    fn from(value: T) -> Self {
        Self::new(value)
    }
}

#[cfg(test)]
mod tests {
    extern crate std;

    use core::future::Future;
    use core::mem::{align_of, size_of};
    use core::pin::Pin;
    use core::task::{Context, Poll};
    use std::boxed::Box;
    use std::rc::Rc;

    use super::SyncWrapper;

    #[test]
    fn wrapper_has_the_values_exact_layout_and_exclusive_access() {
        assert_eq!(size_of::<SyncWrapper<[u8; 37]>>(), size_of::<[u8; 37]>());
        assert_eq!(align_of::<SyncWrapper<u128>>(), align_of::<u128>());
        let mut wrapped = SyncWrapper::new(41_u8);
        *wrapped.get_mut() += 1;
        assert_eq!(wrapped.into_inner(), 42);
    }

    #[test]
    fn non_sync_value_becomes_sync_without_shared_value_access() {
        fn assert_sync<T: Sync>() {}
        assert_sync::<SyncWrapper<Rc<u8>>>();
    }

    #[test]
    fn pinned_projection_polls_a_non_unpin_future_without_moving_it() {
        let mut wrapped = Box::pin(SyncWrapper::new(OnePollFuture::default()));
        let mut context = Context::from_waker(std::task::Waker::noop());
        assert_eq!(
            wrapped.as_mut().get_pin_mut().poll(&mut context),
            Poll::Ready(7)
        );
    }

    #[derive(Default)]
    struct OnePollFuture {
        _pinned: core::marker::PhantomPinned,
    }

    impl Future for OnePollFuture {
        type Output = u8;

        fn poll(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<Self::Output> {
            Poll::Ready(7)
        }
    }
}
