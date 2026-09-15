// SPDX-License-Identifier: GPL-2.0-only

//! Real encrypted packs recover complete files without live providers or target journals.

use super::*;
use meshspan_contracts::{ContractVersion, ShardIdentity};
use meshspan_filesystem::{
    ContentEncryptionKey, DurableContentCatalog, RecoveryShardSource, VolumeContentKeys as _,
};
use meshspan_storage::{RecoveryFolder, RecoveryInventory};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

pub(super) struct SurvivingPacks {
    pub(super) inventory: RecoveryInventory,
    pub(super) queried: usize,
    pub(super) corrupt_candidates: bool,
}

struct SurvivingMedia {
    content: PublishedContentReference,
    folders: Vec<RecoveryFolder>,
    bytes: Vec<u8>,
    protection: ProtectionConfiguration,
}

impl RecoveryShardSource for SurvivingPacks {
    fn read_candidate(
        &mut self,
        shard: ShardIdentity,
        length: u64,
        digest: [u8; 32],
    ) -> Result<Option<BoundedBytes>, ContentReadError> {
        self.queried += 1;
        if self.corrupt_candidates {
            return BoundedBytes::copy_from(b"not a valid shard", 100)
                .map(Some)
                .map_err(|_| ContentReadError::Corrupt);
        }
        self.inventory
            .read_content_shard(shard, length, digest)
            .map_err(|_| ContentReadError::Unavailable)
    }
}

#[test]
fn offline_recovery_reconstructs_from_two_surviving_packs_without_original_journals() -> TestResult
{
    let root = tempdir()?;
    let volume = VolumeId::from_bytes([2; 16])?;
    let SurvivingMedia {
        content,
        folders,
        bytes,
        ..
    } = prepare_surviving_media(root.path(), volume)?;
    let mut source = SurvivingPacks {
        inventory: capture_surviving_media(root.path(), folders)?,
        queried: 0,
        corrupt_candidates: false,
    };
    assert_eq!(source.inventory.summary()?.packs, 2);
    let catalog =
        DurableContentCatalog::open(&root.path().join("restored-history"), UnixMicros::new(100))?;
    let layout = catalog.committed_layout_transfer(content)?;
    assert!(layout.header().chunk_count > 1);
    let keys = VolumeContentKeyring::new(volume, VolumeKeyEncryptionKey::from_bytes(1, [8; 32])?);
    let key = keys.unwrap_content_key(
        volume,
        content.manifest.manifest_id,
        layout.header().wrapped_key,
    )?;
    let operation = RequestContext {
        contract_version: ContractVersion::V1_0,
        operation_id: OperationId::from_bytes([90; 16])?,
        deadline: UnixMicros::new(1000),
        expected_revision: None,
    };
    let mut output = Vec::new();
    let result = layout.recover_to(
        operation,
        key,
        &ReedSolomonCoding::new(),
        &mut source,
        &mut output,
    )?;
    assert_eq!(output, bytes);
    assert_eq!(result.logical_length, u64::try_from(bytes.len())?);
    assert_eq!(result.content_digest, *blake3::hash(&bytes).as_bytes());
    assert_eq!(result.chunks, layout.header().chunk_count);
    assert!(source.queried <= usize::try_from(result.chunks)? * 4);
    assert!(!root.path().join("filesystem").exists());
    assert!(!root.path().join("storage-state-2").exists());

    check_recovery_failures(&layout, &keys, operation, &mut source, root.path())?;
    Ok(())
}

/// The restarted index must work even after every original storage path disappears.
fn capture_surviving_media(
    root: &std::path::Path,
    folders: Vec<RecoveryFolder>,
) -> TestResult<RecoveryInventory> {
    let work = root.join("inventory");
    let scope = [35; 32];
    let mut inventory = RecoveryInventory::create(&work, scope, 16 * 1024 * 1024)?;
    for folder in &folders {
        for sequence in folder.pack_sequences()? {
            inventory.capture_pack(folder, sequence?)?;
        }
    }
    drop(inventory);
    drop(folders);
    for index in 2..4 {
        fs::rename(
            root.join(format!("storage-{index}")),
            root.join(format!("unavailable-target-{index}")),
        )?;
    }
    RecoveryInventory::open(&work, scope).map_err(Into::into)
}

/// Normal publication and a closed catalogue copy precede losing the original journals/targets.
fn prepare_surviving_media(root: &std::path::Path, volume: VolumeId) -> TestResult<SurvivingMedia> {
    let mesh = MeshId::from_bytes([1; 16])?;
    let fixture = protection_fixture(root, mesh)?;
    let protection = fixture.protection.clone();
    let state = root.join("filesystem");
    let mut publisher = protected_publisher(
        &state,
        fixture.router.clone(),
        volume,
        fixture.protection.clone(),
        mesh,
        8,
    )?;
    let mut bytes = fixture_bytes();
    bytes.extend_from_within(..);
    bytes.extend_from_slice(b"partial last chunk");
    let mut request = publication_request(volume, 10)?;
    request.logical_length = u64::try_from(bytes.len())?;
    let content = publish(&mut publisher, request, &bytes)?;
    let markers = fixture
        .control
        .lock()?
        .providers
        .values()
        .map(FolderShardStore::target_marker)
        .collect::<Vec<_>>();
    drop(publisher);
    drop(fixture);
    let restored = root.join("restored-history");
    fs::create_dir(&restored)?;
    fs::copy(
        state.join("filesystem-content.sqlite3"),
        restored.join("filesystem-content.sqlite3"),
    )?;
    fs::rename(&state, root.join("unavailable-filesystem"))?;
    for index in 0..4 {
        fs::rename(
            root.join(format!("storage-state-{index}")),
            root.join(format!("unavailable-journal-{index}")),
        )?;
    }
    // Losing two whole targets leaves only the other two coded slices, not original plaintext.
    for index in 0..2 {
        fs::rename(
            root.join(format!("storage-{index}")),
            root.join(format!("unavailable-target-{index}")),
        )?;
    }
    let folders = (2..4)
        .map(|index| {
            RecoveryFolder::open(
                &root.join(format!("storage-{index}")),
                markers[index].fingerprint(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(SurvivingMedia {
        content,
        folders,
        bytes,
        protection,
    })
}

#[test]
fn offline_restoration_writes_normal_providers_and_reads_without_salvage_after_restart()
-> TestResult {
    let root = tempdir()?;
    let mesh = MeshId::from_bytes([1; 16])?;
    let volume = VolumeId::from_bytes([2; 16])?;
    let SurvivingMedia {
        content,
        folders,
        bytes,
        protection,
    } = prepare_surviving_media(root.path(), volume)?;
    let mut source = SurvivingPacks {
        inventory: capture_surviving_media(root.path(), folders)?,
        queried: 0,
        corrupt_candidates: false,
    };
    let mut providers = BTreeMap::new();
    for index in 0_u8..4 {
        let id = TargetId::from_bytes([100 + index; 16])?;
        providers.insert(id, open_provider(root.path(), mesh, id, index + 4)?);
    }
    let mut router = TestRouter::new(providers);
    let state = root.path().join("restored-history");
    let mut catalog = DurableContentCatalog::open(&state, UnixMicros::new(100))?;
    let chunks = catalog
        .committed_layout_transfer(content)?
        .header()
        .chunk_count;
    let first = catalog.committed_protected_stripe(content, 0)?;
    rejected_or_interrupted_restore(&first, &mut source, &mut router)?;
    source.queried = 0;
    for index in 0..chunks {
        restore_one_stripe(&mut catalog, content, index, &mut source, &mut router)?;
    }
    // Each batch reconstructs once for all four destinations; retry repeats one batch read.
    assert!(source.queried <= usize::try_from(chunks)? * 8);
    drop(catalog);
    drop(source);
    fs::rename(
        root.path().join("inventory"),
        root.path().join("unavailable-inventory"),
    )?;
    let markers = router
        .lock()?
        .providers
        .values()
        .map(FolderShardStore::target_marker)
        .collect::<Vec<_>>();
    drop(router);
    let reopened = reopen_restored_providers(root.path(), mesh, &markers)?;
    let mut reader = protected_publisher(&state, reopened, volume, protection.clone(), mesh, 8)?;
    assert_exact_read(&mut reader, content, &bytes, 200)?;
    // Read through the ordinary client path with two replacement targets also unavailable.
    let reader_router = reader.into_router();
    reader_router.set_offline(markers[0].target_id())?;
    reader_router.set_offline(markers[1].target_id())?;
    let mut reader = protected_publisher(&state, reader_router, volume, protection, mesh, 8)?;
    assert_exact_read(&mut reader, content, &bytes, 201)?;
    Ok(())
}

fn requests_for(stripe: &CommittedProtectedStripe) -> TestResult<Vec<ShardRepairRequest>> {
    stripe
        .receipts
        .as_slice()
        .iter()
        .map(|receipt| {
            let index = u8::try_from(receipt.shard.shard_index)?;
            let operation = 100 + u8::try_from(receipt.shard.stripe_index)? * 4 + index;
            Ok(ShardRepairRequest {
                replacement_operation_id: OperationId::from_bytes([operation; 16])?,
                source_receipt: *receipt,
                replacement_target_id: TargetId::from_bytes([100 + index; 16])?,
                replacement_target_generation: 1,
                replacement_shard_generation: receipt.shard.generation,
                authorization_revision: Revision::new(2),
                deadline: UnixMicros::new(1000),
                observed_at: UnixMicros::new(100),
            })
        })
        .collect()
}

fn restore_one_stripe(
    catalog: &mut DurableContentCatalog,
    content: PublishedContentReference,
    index: u64,
    source: &mut SurvivingPacks,
    router: &mut TestRouter,
) -> TestResult {
    let stripe = catalog.committed_protected_stripe(content, index)?;
    let requests = requests_for(&stripe)?;
    let receipts = meshspan_filesystem::restore_recovery_stripe(
        &requests,
        &stripe,
        &ReedSolomonCoding::new(),
        source,
        router,
    )?;
    assert_eq!(
        meshspan_filesystem::restore_recovery_stripe(
            &requests,
            &stripe,
            &ReedSolomonCoding::new(),
            source,
            router
        )?,
        receipts
    );
    for (request, receipt) in requests.iter().zip(receipts.as_slice()) {
        assert_eq!(receipt.shard, request.source_receipt.shard);
        assert_eq!(receipt.digest, request.source_receipt.digest);
        assert_eq!(receipt.length, request.source_receipt.length);
        let candidate = catalog
            .shard_repair_candidate(
                request.source_receipt.target_id,
                request.source_receipt.target_generation,
                request.source_receipt.shard,
            )?
            .ok_or("missing original route")?;
        // An isolated candidate, not a claim that cluster recovery admission exists.
        let mut wrong = *receipt;
        wrong.length += 1;
        assert!(
            catalog
                .prepare_recovery_shard_route(content, candidate, wrong, Revision::new(2))
                .is_err()
        );
        catalog.prepare_recovery_shard_route(content, candidate, *receipt, Revision::new(2))?;
        catalog.prepare_recovery_shard_route(content, candidate, *receipt, Revision::new(2))?;
    }
    Ok(())
}

fn rejected_or_interrupted_restore(
    stripe: &CommittedProtectedStripe,
    source: &mut SurvivingPacks,
    router: &mut TestRouter,
) -> TestResult {
    let requests = requests_for(stripe)?;
    let duplicate = vec![requests[0], requests[0]];
    assert!(matches!(
        meshspan_filesystem::restore_recovery_stripe(
            &duplicate,
            stripe,
            &ReedSolomonCoding::new(),
            source,
            router
        ),
        Err(ContractError::InvalidInput)
    ));
    assert_eq!(source.queried, 0);
    source.corrupt_candidates = true;
    assert!(matches!(
        meshspan_filesystem::restore_recovery_stripe(
            &requests,
            stripe,
            &ReedSolomonCoding::new(),
            source,
            router
        ),
        Err(ContractError::Unavailable)
    ));
    source.corrupt_candidates = false;
    router.set_offline(requests[2].replacement_target_id)?;
    assert!(matches!(
        meshspan_filesystem::restore_recovery_stripe(
            &requests,
            stripe,
            &ReedSolomonCoding::new(),
            source,
            router
        ),
        Err(ContractError::Unavailable)
    ));
    assert!(
        router
            .lock()?
            .providers
            .get(&requests[0].replacement_target_id)
            .ok_or("missing target")?
            .inventory_exact(requests[0].source_receipt.shard)?
            .is_some()
    );
    assert!(
        router
            .lock()?
            .providers
            .get(&requests[2].replacement_target_id)
            .ok_or("missing target")?
            .inventory_exact(requests[2].source_receipt.shard)?
            .is_none()
    );
    router.set_all_online()?;
    Ok(())
}

fn reopen_restored_providers(
    root: &std::path::Path,
    mesh: MeshId,
    markers: &[meshspan_storage::TargetMarker],
) -> TestResult<TestRouter> {
    let mut providers = BTreeMap::new();
    for (index, marker) in markers.iter().enumerate() {
        let folder = RegisteredFolder::reopen(
            &root.join(format!("storage-{}", index + 4)),
            FolderRegistration {
                mesh_id: mesh,
                target_id: marker.target_id(),
                generation: 1,
                usage_limit: UsageLimit::DEFAULT,
            },
            marker.fingerprint(),
        )?;
        providers.insert(
            marker.target_id(),
            FolderShardStore::open(
                folder,
                &root.join(format!("storage-state-{}", index + 4)),
                CapacityPolicy {
                    usage_limit: UsageLimit::DEFAULT,
                    repair_reserve_bytes: 0,
                    revision: Revision::new(1),
                },
                StoragePermitVerifier::new(
                    mesh,
                    1,
                    Revision::new(1),
                    StoragePermitMacKey::from_bytes(PERMIT_KEY)?,
                )?,
                UnixMicros::new(101),
                &mut FixedRandom,
            )?,
        );
    }
    Ok(TestRouter::new(providers))
}

fn check_recovery_failures(
    layout: &meshspan_filesystem::CommittedContentLayoutTransfer<'_>,
    keys: &VolumeContentKeyring,
    context: RequestContext,
    source: &mut SurvivingPacks,
    root: &std::path::Path,
) -> TestResult {
    let key = || {
        keys.unwrap_content_key(
            layout.volume_id(),
            layout.header().manifest.manifest_id,
            layout.header().wrapped_key,
        )
    };
    let mut output = Vec::new();
    assert!(matches!(
        layout.recover_to(
            context,
            ContentEncryptionKey::from_bytes([99; 32])?,
            &ReedSolomonCoding::new(),
            source,
            &mut output
        ),
        Err(ContentReadError::Corrupt)
    ));
    assert!(output.is_empty());
    source.corrupt_candidates = true;
    assert!(matches!(
        layout.recover_to(
            context,
            key()?,
            &ReedSolomonCoding::new(),
            source,
            &mut output
        ),
        Err(ContentReadError::Unavailable)
    ));
    assert!(output.is_empty());
    source.corrupt_candidates = false;
    let mut failing_output = FailingOutput;
    assert!(matches!(
        layout.recover_to(
            context,
            key()?,
            &ReedSolomonCoding::new(),
            source,
            &mut failing_output
        ),
        Err(ContentReadError::Io(_))
    ));
    fs::rename(
        root.join("inventory/pack-0000000000000002"),
        root.join("unavailable-recovery-copy"),
    )?;
    assert!(matches!(
        layout.recover_to(
            context,
            key()?,
            &ReedSolomonCoding::new(),
            source,
            &mut output
        ),
        Err(ContentReadError::Unavailable)
    ));
    assert!(output.is_empty());
    Ok(())
}

struct FailingOutput;
impl Write for FailingOutput {
    fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
        Err(std::io::Error::other("injected destination failure"))
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}
