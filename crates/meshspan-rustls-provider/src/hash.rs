// SPDX-License-Identifier: GPL-2.0-only

use std::boxed::Box;

use rustls::crypto::hash::{Context, Hash, HashAlgorithm, Output};
use sha2::{Digest, Sha256};

#[derive(Debug)]
pub(crate) struct Sha256Hash;

pub(crate) static SHA256: Sha256Hash = Sha256Hash;

impl Hash for Sha256Hash {
    fn start(&self) -> Box<dyn Context> {
        Box::new(Sha256Context(Sha256::new()))
    }

    fn hash(&self, input: &[u8]) -> Output {
        Output::new(Sha256::digest(input).as_ref())
    }

    fn output_len(&self) -> usize {
        32
    }

    fn algorithm(&self) -> HashAlgorithm {
        HashAlgorithm::SHA256
    }
}

struct Sha256Context(Sha256);

impl Context for Sha256Context {
    fn fork_finish(&self) -> Output {
        Output::new(self.0.clone().finalize().as_ref())
    }

    fn fork(&self) -> Box<dyn Context> {
        Box::new(Self(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> Output {
        Output::new(self.0.finalize().as_ref())
    }

    fn update(&mut self, input: &[u8]) {
        self.0.update(input);
    }
}
