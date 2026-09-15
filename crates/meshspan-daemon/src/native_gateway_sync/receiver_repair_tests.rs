// SPDX-License-Identifier: GPL-2.0-only

//! Exercise the real native transfer codec and importer after an authoritative repair.

use std::error::Error;
use std::path::Path;

use meshspan_domain::{NodeId, OperationId, UnixMicros, VolumeId};
use meshspan_filesystem::{
    DurableContentCatalog, PublishedContentReference, RepairProjectionCursor,
};
use meshspan_metadata::{AuthoritativeRepository, PartitionDatabase, ShardRepairEffectRecord};
use meshspan_protocol::v1::control_envelope::Message;
use meshspan_protocol::v1::{FetchNativeContentLayout, NativeContentLayoutPage};

use super::{
    ParsedContentRoute, decode_layout_header, decode_layout_page, decode_protected_stripes,
    import_contract, project_received_manifest,
};

/// Uses the enclosing real maintenance fixture's one-chunk publication and provider receipts.
pub(crate) fn assert_fresh_repaired_import(
    state_directory: &Path,
    effect: &ShardRepairEffectRecord,
    now: UnixMicros,
) -> Result<(), Box<dyn Error>> {
    let source = DurableContentCatalog::open(&state_directory.join("filesystem"), now)?;
    let content = source
        .committed_content_by_manifest(effect.manifest_id)?
        .ok_or("source repaired manifest")?;
    let request = FetchNativeContentLayout {
        publication_operation_id: content.publication_operation_id.as_bytes().to_vec(),
        manifest_id: effect.manifest_id.as_bytes().to_vec(),
        after_index: None,
        limit: 1,
    };
    let Message::NativeContentLayoutPage(page) =
        super::super::source::content_layout(state_directory, &request)?
    else {
        return Err("source returned another transfer response".into());
    };
    let header = decode_layout_header(&page)?;
    assert_eq!(header.manifest, content.manifest);
    assert_eq!(header.chunk_count, 1, "bounded maintenance fixture");
    assert!(page.next_index.is_none());
    let route = ParsedContentRoute {
        publication_operation_id: content.publication_operation_id,
        manifest_id: effect.manifest_id,
        target_id: effect.source_receipt.target_id,
        target_generation: effect.source_receipt.target_generation,
    };
    let directory = tempfile::tempdir()?;
    let mut receiver = DurableContentCatalog::open(directory.path(), now)?;
    let imported = import_response(&mut receiver, &page, &route, effect.volume_id, now)?;
    assert_eq!(
        imported.manifest, content.manifest,
        "repair cannot rewrite the immutable manifest"
    );
    assert_eq!(
        receiver
            .committed_protected_stripe(imported, effect.source_receipt.shard.stripe_index)?
            .receipts
            .as_slice(),
        &[effect.source_receipt],
        "publication export retains its original durable receipt, not a replacement placement"
    );
    let authority = AuthoritativeRepository::new(PartitionDatabase::open_existing(
        &state_directory.join("root-authority.sqlite3"),
        now,
    )?);
    assert_projection_scope(&authority, &mut receiver, effect.volume_id, route)?;
    project_received_manifest(&authority, &mut receiver, effect.volume_id, &route)?;
    assert_projected_receipt(&authority, &receiver, effect, imported)?;
    drop(receiver);
    let mut reopened = DurableContentCatalog::open(directory.path(), now)?;
    // This is also the retained-layout fast path used after a lost import response.
    project_received_manifest(&authority, &mut reopened, effect.volume_id, &route)?;
    assert_projected_receipt(&authority, &reopened, effect, imported)?;
    Ok(())
}

fn import_response(
    receiver: &mut DurableContentCatalog,
    page: &NativeContentLayoutPage,
    route: &ParsedContentRoute,
    volume: VolumeId,
    now: UnixMicros,
) -> Result<PublishedContentReference, Box<dyn Error>> {
    let header = decode_layout_header(page)?;
    let contract = import_contract(NodeId::from_bytes([127; 16])?, volume, route, header)?;
    let layout = decode_layout_page(page, route)?;
    let protected = decode_protected_stripes(page, contract, header, &layout)?;
    receiver.begin_layout_import(contract, header)?;
    receiver.append_layout_import_page(contract, header, &layout)?;
    for value in &protected {
        receiver
            .append_protected_layout_import_page(contract, std::slice::from_ref(&value.stripe))?;
    }
    receiver.seal_layout_import(contract, header)?;
    for value in &protected {
        for receipt in value.receipts.as_slice() {
            receiver.record_protected_receipt(contract, *receipt, now)?;
        }
    }
    Ok(PublishedContentReference {
        publication_operation_id: contract.operation_id,
        manifest: receiver.finish(contract, now)?,
    })
}

fn assert_projection_scope(
    authority: &AuthoritativeRepository,
    receiver: &mut DurableContentCatalog,
    volume: VolumeId,
    route: ParsedContentRoute,
) -> Result<(), Box<dyn Error>> {
    assert!(matches!(
        project_received_manifest(
            authority,
            receiver,
            VolumeId::from_bytes([125; 16])?,
            &route
        ),
        Err(super::NativeGatewaySyncError::Invalid)
    ));
    let wrong_publication = ParsedContentRoute {
        publication_operation_id: OperationId::from_bytes([124; 16])?,
        ..route
    };
    assert!(matches!(
        project_received_manifest(authority, receiver, volume, &wrong_publication),
        Err(super::NativeGatewaySyncError::Invalid)
    ));
    let content = receiver
        .committed_content_by_manifest(route.manifest_id)?
        .ok_or("fresh manifest")?;
    assert_eq!(
        receiver.repair_projection_cursor(authority.partition_id(), content)?,
        None
    );
    Ok(())
}

fn assert_projected_receipt(
    authority: &AuthoritativeRepository,
    receiver: &DurableContentCatalog,
    effect: &ShardRepairEffectRecord,
    imported: PublishedContentReference,
) -> Result<(), Box<dyn Error>> {
    assert_eq!(
        receiver.repair_projection_cursor(authority.partition_id(), imported)?,
        Some(RepairProjectionCursor {
            revision: effect.revision,
            effect_operation_id: effect.effect_operation_id,
        })
    );
    assert_eq!(
        receiver
            .committed_protected_stripe(imported, effect.source_receipt.shard.stripe_index)?
            .receipts
            .as_slice(),
        &[effect.replacement_receipt],
        "receiver must project the exact replacement before reporting coverage"
    );
    Ok(())
}
