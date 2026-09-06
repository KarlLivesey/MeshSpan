// SPDX-License-Identifier: GPL-2.0-only

use meshspan_contracts::ContractError;
use meshspan_transport::PeerBinding;

use super::*;
use crate::remote_backup_authority::validate_peer_identity;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn bootstrap_node_can_use_remote_backup_without_a_join_activation_record()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = RunningAuthority::start().await?;
    let result = (|| -> Result<(), Box<dyn std::error::Error>> {
        let repository = fixture.reader.as_ref().ok_or("reader missing")?;
        assert!(repository.node_activation(fixture.node_id)?.is_none());
        let certificate = repository
            .active_node_certificate(fixture.node_id)?
            .ok_or("bootstrap certificate missing")?;
        let peer = PeerBinding {
            node_id: fixture.node_id,
            incarnation: 1,
            certificate_fingerprint: certificate.certificate_fingerprint,
        };
        validate_peer_identity(repository, peer, UnixMicros::new(20))?;
        for invalid in [
            PeerBinding {
                incarnation: 2,
                ..peer
            },
            PeerBinding {
                certificate_fingerprint: [0; 32],
                ..peer
            },
            PeerBinding {
                node_id: NodeId::from_bytes([123; 16])?,
                ..peer
            },
        ] {
            assert_eq!(
                validate_peer_identity(repository, invalid, UnixMicros::new(20)),
                Err(ContractError::Unauthorized)
            );
        }
        assert_eq!(
            validate_peer_identity(repository, peer, certificate.valid_until),
            Err(ContractError::Unauthorized)
        );
        Ok(())
    })();
    fixture.shutdown().await?;
    result
}
