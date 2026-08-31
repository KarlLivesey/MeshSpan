// SPDX-License-Identifier: GPL-2.0-only

use std::boxed::Box;

use hmac::{Hmac, KeyInit, Mac};
use rustls::crypto::hmac::{Hmac as RustlsHmac, Key, Tag};
use sha2::Sha256;

#[derive(Debug)]
pub(crate) struct Sha256Hmac;

pub(crate) static SHA256: Sha256Hmac = Sha256Hmac;

impl RustlsHmac for Sha256Hmac {
    fn with_key(&self, key: &[u8]) -> Box<dyn Key> {
        let inner = Hmac::<Sha256>::new_from_slice(key).ok();
        Box::new(Sha256Key(inner))
    }

    fn hash_output_len(&self) -> usize {
        32
    }
}

struct Sha256Key(Option<Hmac<Sha256>>);

impl Key for Sha256Key {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> Tag {
        let Some(mut inner) = self.0.clone() else {
            return Tag::new(&[0; 32]);
        };
        inner.update(first);
        for item in middle {
            inner.update(item);
        }
        inner.update(last);
        Tag::new(inner.finalize().into_bytes().as_ref())
    }

    fn tag_len(&self) -> usize {
        32
    }
}
