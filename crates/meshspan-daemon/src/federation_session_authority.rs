// SPDX-License-Identifier: GPL-2.0-only

//! Current paired-node identity, routing and relationship authority for native sessions.

use meshspan_cluster::{
    FederationAuthorityError, FederationAuthoritySource, FederationConnectionAuthority,
    federation_connection_authority,
};
use meshspan_domain::{FederationRelationshipId, NodeId, UnixMicros};
use meshspan_metadata::{AuthoritativeRepository, PageLimit, RepositoryError};
use std::{collections::BTreeMap, sync::Mutex};

pub(super) struct SessionAuthority {
    reader: Mutex<AuthoritativeRepository>,
    node: NodeId,
}

#[derive(Clone)]
pub(super) struct PairedRoute {
    pub(super) authority: FederationConnectionAuthority,
    pub(super) endpoint: String,
    pub(super) certificate: Vec<u8>,
}

impl SessionAuthority {
    pub(super) fn new(reader: AuthoritativeRepository, node: NodeId) -> Self {
        Self {
            reader: Mutex::new(reader),
            node,
        }
    }

    // These methods run on the blocking pool, or inside the explicit blocking section below.
    pub(super) fn route(
        &self,
        id: FederationRelationshipId,
        now: UnixMicros,
    ) -> Result<Option<PairedRoute>, FederationAuthorityError> {
        let reader = self
            .reader
            .lock()
            .map_err(|_| FederationAuthorityError::InvalidProjection)?;
        read_route(&reader, self.node, id, now)
    }

    pub(super) fn routes(
        &self,
        now: UnixMicros,
    ) -> Result<BTreeMap<FederationRelationshipId, PairedRoute>, FederationAuthorityError> {
        let reader = self
            .reader
            .lock()
            .map_err(|_| FederationAuthorityError::InvalidProjection)?;
        let mut after = None;
        let mut routes = BTreeMap::new();
        loop {
            let page =
                reader.federation_pairing_connections(self.node, after, PageLimit::new(64)?)?;
            for record in page.items {
                let id = record.connection.relationship_id;
                if let Some(route) = read_route(&reader, self.node, id, now)? {
                    routes.insert(id, route);
                }
            }
            let Some(next) = page.next else {
                break;
            };
            after = Some(next);
        }
        Ok(routes)
    }
}

impl FederationAuthoritySource for SessionAuthority {
    fn connection_authority(
        &self,
        id: FederationRelationshipId,
        now: UnixMicros,
    ) -> Result<Option<FederationConnectionAuthority>, FederationAuthorityError> {
        // The session library's synchronous authority callback must never do SQLite IO on
        // a Tokio executor worker. Native daemon runtimes use Tokio's multithreaded executor.
        tokio::task::block_in_place(|| {
            self.route(id, now)
                .map(|route| route.map(|value| value.authority))
        })
    }
}

fn read_route(
    reader: &AuthoritativeRepository,
    node: NodeId,
    id: FederationRelationshipId,
    now: UnixMicros,
) -> Result<Option<PairedRoute>, FederationAuthorityError> {
    let Some(record) = reader.hosted_federation_pairing(node, id)? else {
        return Ok(None);
    };
    let projected = match federation_connection_authority(reader, id, now) {
        Err(FederationAuthorityError::IdentityNotCurrent) => None,
        result => result?,
    };
    let Some(authority) = projected else {
        return Ok(None);
    };
    let local = record.connection.local.peer.trust_identity();
    let remote = record.connection.remote.peer.trust_identity();
    if authority.local_identity.certificate_fingerprint != local.certificate_fingerprint
        || authority.local_identity.verifying_key != local.verifying_key
        || authority.peer.certificate_fingerprint != remote.certificate_fingerprint
        || authority.peer.verifying_key != remote.verifying_key
    {
        return Err(RepositoryError::CorruptState.into());
    }
    Ok(Some(PairedRoute {
        authority,
        endpoint: record.connection.remote.peer.endpoint,
        certificate: record.connection.remote.peer.certificate_der,
    }))
}
