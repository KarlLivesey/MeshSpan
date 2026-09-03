// SPDX-License-Identifier: GPL-2.0-only

//! ACME-facing adapter over `MeshSpan`'s bounded system and authoritative DNS resolver.

use meshspan_acme::AuthoritativeTxtObserver;
use meshspan_contracts::ContractError;
use meshspan_dns::AuthoritativeTxtResolver;

/// Cloneable in-process authoritative TXT observation capability.
#[derive(Clone, Debug)]
pub struct SystemAuthoritativeTxtObserver {
    resolver: AuthoritativeTxtResolver,
}

impl SystemAuthoritativeTxtObserver {
    /// Wraps a validated resolver without performing network work.
    #[must_use]
    pub const fn new(resolver: AuthoritativeTxtResolver) -> Self {
        Self { resolver }
    }
}

impl AuthoritativeTxtObserver for SystemAuthoritativeTxtObserver {
    async fn contains_txt(&self, name: &str, value: &[u8]) -> Result<bool, ContractError> {
        self.resolver
            .contains_txt(name, value)
            .await
            .map_err(|_| ContractError::Unavailable)
    }
}
