// SPDX-License-Identifier: GPL-2.0-only

use std::boxed::Box;

use p256::elliptic_curve::Generate;
use rustls::crypto::{ActiveKeyExchange, SharedSecret, SupportedKxGroup};
use rustls::{Error, NamedGroup, PeerMisbehaved};

#[derive(Debug)]
pub(crate) struct P256KeyExchangeGroup;

pub(crate) static SECP256R1: P256KeyExchangeGroup = P256KeyExchangeGroup;

impl SupportedKxGroup for P256KeyExchangeGroup {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let secret = p256::ecdh::EphemeralSecret::try_generate_from_rng(&mut getrandom::SysRng)
            .map_err(|_| Error::FailedToGetRandomBytes)?;
        let public = p256::PublicKey::from(&secret).to_sec1_bytes();
        Ok(Box::new(P256KeyExchange { secret, public }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }
}

struct P256KeyExchange {
    secret: p256::ecdh::EphemeralSecret,
    public: Box<[u8]>,
}

impl ActiveKeyExchange for P256KeyExchange {
    fn complete(self: Box<Self>, peer_public: &[u8]) -> Result<SharedSecret, Error> {
        let peer = p256::PublicKey::from_sec1_bytes(peer_public)
            .map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))?;
        Ok(self
            .secret
            .diffie_hellman(&peer)
            .raw_secret_bytes()
            .as_slice()
            .into())
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }
}
