// SPDX-License-Identifier: GPL-2.0-only

use std::{cell::RefCell, collections::BTreeMap, io::Write, path::Path, rc::Rc};

use meshspan_domain::{
    AssuranceLevel, AuthenticationService, BranchId, ContentManifestId, FileVersionId, HandleId,
    NamespaceCommitId, NodeId, ObjectId, ObjectRevisionId, OperationId, PrincipalId, Revision,
    UnixMicros, VolumeId,
};
use meshspan_filesystem::{
    AdapterCloseFileRequest, AdapterCreateFileRequest, AuthorisedFilesystemService,
    BoundFilesystemAdapter, CompletedStage, ContentPublicationError, ContentPublicationRequest,
    ContentReadError, ContentReadRequest, CreateDisposition, DurableContentPublisher,
    DurableContentReader, FilePublication, FilesystemAccessAuthority, FilesystemAccessContext,
    FilesystemAdapterPolicy, FilesystemAuthorityGrant, FilesystemAuthorityRequest,
    FilesystemCommitService, FilesystemFileAdapter, HandleAccess, HandleShare, ManifestPublication,
    NamespaceHistoryLimits, NamespaceLimits, NamespacePath, NamespacePublicationPath,
    NamespaceReconciliationApplication, NamespaceReplayDisposition, PublicationDisposition,
    ReconciliationFrontier, ReconciliationLimits, RootFilePublication, VersionPublicationStore,
};
use tempfile::{TempDir, tempdir};

use crate::FilesystemConvergenceService;

#[test]
fn semantic_isolated_writes_restart_exchange_and_converge_automatically()
-> Result<(), Box<dyn std::error::Error>> {
    let fixture = IsolatedServiceFixture::create()?;
    let home_write = fixture.create_conflicting_file(NodeSide::Home)?;
    let office_write = fixture.create_conflicting_file(NodeSide::Office)?;
    let mut home_store = fixture.open_home(20)?;
    let mut office_store = fixture.open_office(20)?;
    let frontier = ReconciliationFrontier {
        converged_head: Some(fixture.base.namespace_commit_id),
        eligible_heads: vec![home_write.commit_id, office_write.commit_id],
    };
    let history_limits = NamespaceHistoryLimits::DEFAULT;
    let reconciliation_limits = ReconciliationLimits::DEFAULT;
    let home_bundle =
        FilesystemConvergenceService::new(&mut home_store, history_limits, reconciliation_limits)
            .export_history(
            fixture.base.file.volume_id,
            &[home_write.commit_id],
            &[fixture.base.namespace_commit_id],
        )?;
    let office_bundle =
        FilesystemConvergenceService::new(&mut office_store, history_limits, reconciliation_limits)
            .export_history(
                fixture.base.file.volume_id,
                &[office_write.commit_id],
                &[fixture.base.namespace_commit_id],
            )?;
    let application = merge_application(fixture.base.file.created_by)?;
    let (home_receipt, office_receipt) = {
        let mut home = FilesystemConvergenceService::new(
            &mut home_store,
            history_limits,
            reconciliation_limits,
        );
        let mut office = FilesystemConvergenceService::new(
            &mut office_store,
            history_limits,
            reconciliation_limits,
        );
        let home_prepared = home.import_and_prepare(&office_bundle, &frontier)?;
        let office_prepared = office.import_and_prepare(&home_bundle, &frontier)?;
        assert_eq!(home_prepared.prepared, office_prepared.prepared);
        assert_preserves_both_versions(
            &home_prepared.prepared,
            home_write.version_id,
            office_write.version_id,
        );
        (
            home.apply(application, &home_prepared.prepared)?,
            office.apply(application, &office_prepared.prepared)?,
        )
    };
    assert_eq!(home_receipt, office_receipt);
    drop(home_store);
    drop(office_store);
    fixture.assert_restarted_receipts(application.operation_id, home_receipt)?;
    Ok(())
}

#[derive(Clone, Copy)]
enum NodeSide {
    Home,
    Office,
}

#[derive(Clone, Copy)]
struct AcknowledgedWrite {
    commit_id: NamespaceCommitId,
    version_id: FileVersionId,
}

struct IsolatedServiceFixture {
    home: TempDir,
    office: TempDir,
    base: RootFilePublication,
    principal_id: PrincipalId,
}

impl IsolatedServiceFixture {
    fn create() -> Result<Self, Box<dyn std::error::Error>> {
        let home = tempdir()?;
        let office = tempdir()?;
        let base = base_publication()?;
        seed_node(home.path(), &base, BranchId::from_bytes([21; 16])?)?;
        seed_node(office.path(), &base, BranchId::from_bytes([22; 16])?)?;
        Ok(Self {
            home,
            office,
            principal_id: base.file.created_by,
            base,
        })
    }

    fn create_conflicting_file(
        &self,
        side: NodeSide,
    ) -> Result<AcknowledgedWrite, Box<dyn std::error::Error>> {
        let (state, branch_id, gateway_id, operation, handle) = match side {
            NodeSide::Home => (self.home.path(), [21; 16], [31; 16], [41; 16], [42; 16]),
            NodeSide::Office => (self.office.path(), [22; 16], [32; 16], [51; 16], [52; 16]),
        };
        let branch_id = BranchId::from_bytes(branch_id)?;
        let gateway_id = NodeId::from_bytes(gateway_id)?;
        let content = EmptyContentPublisher::default();
        let filesystem = FilesystemCommitService::open(state, UnixMicros::new(2), content)?;
        let authorised = AuthorisedFilesystemService::new(filesystem, AllowAll(self.principal_id));
        let mut adapter = BoundFilesystemAdapter::new(
            authorised,
            branch_id,
            FilesystemAdapterPolicy::new(true, 1, 1)?,
        );
        let request = AdapterCreateFileRequest {
            operation_id: OperationId::from_bytes(operation)?,
            handle_id: HandleId::from_bytes(handle)?,
            volume_id: self.base.file.volume_id,
            path: NamespacePath::from_components(["Shared report"], NamespaceLimits::PORTABLE)?,
            create_disposition: CreateDisposition::CreateNew,
            desired_access: HandleAccess::new(true, true, false)?,
            share_access: HandleShare::new(true, true, false),
            delete_on_close: false,
            maximum_stage_bytes: Some(1_024),
            lease_expires_at: UnixMicros::new(100),
            content_deadline: UnixMicros::new(90),
            observed_at: UnixMicros::new(10),
        };
        let access = access_context(gateway_id, request.observed_at);
        let receipt = adapter.create_file(access, &request)?;
        let creation = receipt
            .creation
            .ok_or("missing semantic creation receipt")?;
        assert_eq!(creation.disposition, PublicationDisposition::Applied);
        adapter.close_file(
            access_context(gateway_id, UnixMicros::new(11)),
            AdapterCloseFileRequest {
                operation_id: OperationId::from_bytes(match side {
                    NodeSide::Home => [43; 16],
                    NodeSide::Office => [53; 16],
                })?,
                handle_id: request.handle_id,
                handle_fence: 1,
                flush: None,
                observed_at: UnixMicros::new(11),
            },
        )?;
        Ok(AcknowledgedWrite {
            commit_id: creation.namespace_commit_id,
            version_id: creation.file_version_id,
        })
    }

    fn open_home(
        &self,
        at: i64,
    ) -> Result<VersionPublicationStore, meshspan_filesystem::PublicationError> {
        VersionPublicationStore::open(self.home.path(), UnixMicros::new(at))
    }

    fn open_office(
        &self,
        at: i64,
    ) -> Result<VersionPublicationStore, meshspan_filesystem::PublicationError> {
        VersionPublicationStore::open(self.office.path(), UnixMicros::new(at))
    }

    fn assert_restarted_receipts(
        &self,
        operation_id: OperationId,
        expected: meshspan_filesystem::NamespaceReconciliationReceipt,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let home = self.open_home(30)?;
        let office = self.open_office(30)?;
        for store in [&home, &office] {
            let receipt = store
                .resolve_namespace_reconciliation(operation_id)?
                .ok_or("missing reconciliation receipt after restart")?;
            assert_eq!(receipt.operation_id, expected.operation_id);
            assert_eq!(receipt.result_digest, expected.result_digest);
            assert_eq!(receipt.disposition, PublicationDisposition::Replayed);
        }
        Ok(())
    }
}

fn seed_node(
    state: &Path,
    base: &RootFilePublication,
    branch_id: BranchId,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut store = VersionPublicationStore::open(state, UnixMicros::new(1))?;
    store.publish_root_file(base)?;
    let first =
        store.ensure_namespace_branch(branch_id, base.file.volume_id, base.namespace_commit_id)?;
    assert_eq!(first.namespace_commit_id, base.namespace_commit_id);
    assert_eq!(
        store.ensure_namespace_branch(branch_id, base.file.volume_id, base.namespace_commit_id)?,
        first
    );
    Ok(())
}

fn assert_preserves_both_versions(
    prepared: &meshspan_filesystem::PreparedNamespaceReconciliation,
    home: FileVersionId,
    office: FileVersionId,
) {
    use std::collections::BTreeSet;

    let actions = prepared.replay_plan().actions();
    assert_eq!(actions.len(), 2);
    let source_versions = actions
        .iter()
        .filter_map(|action| match action.mutation {
            meshspan_filesystem::BranchMutation::File { version_id } => Some(version_id),
            _ => None,
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(source_versions, BTreeSet::from([home, office]));
    assert_eq!(
        actions
            .iter()
            .filter(|action| action.disposition == NamespaceReplayDisposition::Applied)
            .count(),
        1
    );
    assert_eq!(
        actions
            .iter()
            .filter(|action| action.disposition == NamespaceReplayDisposition::Recovered)
            .count(),
        1
    );
}

fn merge_application(
    principal_id: PrincipalId,
) -> Result<NamespaceReconciliationApplication, Box<dyn std::error::Error>> {
    Ok(NamespaceReconciliationApplication {
        operation_id: OperationId::from_bytes([61; 16])?,
        namespace_commit_id: NamespaceCommitId::from_bytes([62; 16])?,
        created_by: principal_id,
        retain_superseded_history: true,
        retention_policy_sequence: 1,
        created_at: UnixMicros::new(60),
    })
}

fn access_context(gateway_node_id: NodeId, now: UnixMicros) -> FilesystemAccessContext {
    FilesystemAccessContext {
        authentication_service: AuthenticationService::Https,
        credential_digest: [90; 32],
        required_assurance: AssuranceLevel::SingleFactor,
        gateway_node_id,
        gateway_incarnation: 1,
        now,
    }
}

#[derive(Clone, Copy)]
struct AllowAll(PrincipalId);

impl FilesystemAccessAuthority for AllowAll {
    type Error = std::convert::Infallible;

    fn authorise(
        &self,
        request: FilesystemAuthorityRequest,
    ) -> Result<FilesystemAuthorityGrant, Self::Error> {
        Ok(FilesystemAuthorityGrant {
            principal_id: self.0,
            gateway_node_id: request.context.gateway_node_id,
            gateway_incarnation: request.context.gateway_incarnation,
            volume_id: request.volume_id,
            object_id: request.object_id,
            requested_rights: request.requested_rights,
            identity_revision: Revision::new(1),
            namespace_revision: Revision::new(1),
            object_revision: Revision::new(1),
            gateway_revision: Revision::new(1),
            expires_at: UnixMicros::new(1_000),
            evidence_digest: [91; 32],
        })
    }
}

type StoredManifests =
    Rc<RefCell<BTreeMap<OperationId, (ContentPublicationRequest, ManifestPublication)>>>;

#[derive(Clone, Default)]
struct EmptyContentPublisher {
    stored: StoredManifests,
}

impl DurableContentPublisher for EmptyContentPublisher {
    type Sink = Vec<u8>;

    fn resolve(
        &mut self,
        request: ContentPublicationRequest,
    ) -> Result<Option<ManifestPublication>, ContentPublicationError> {
        let stored = self.stored.borrow();
        match stored.get(&request.operation_id) {
            Some((prior, manifest)) if prior.same_intent(request) => Ok(Some(*manifest)),
            Some(_) => Err(ContentPublicationError::Conflict),
            None => Ok(None),
        }
    }

    fn begin(
        &mut self,
        request: ContentPublicationRequest,
    ) -> Result<Self::Sink, ContentPublicationError> {
        if self.stored.borrow().contains_key(&request.operation_id) {
            Err(ContentPublicationError::Conflict)
        } else {
            Ok(Vec::new())
        }
    }

    fn finish(
        &mut self,
        request: ContentPublicationRequest,
        sink: Self::Sink,
        completed: CompletedStage,
    ) -> Result<ManifestPublication, ContentPublicationError> {
        let empty_digest: [u8; 32] = blake3::hash(&[]).into();
        if !sink.is_empty()
            || completed.logical_length != 0
            || completed.content_digest != empty_digest
        {
            return Err(ContentPublicationError::Corrupt);
        }
        let mut digest = blake3::Hasher::new();
        digest.update(b"meshspan.test.empty-content.v1\0");
        digest.update(&request.manifest_id.as_bytes());
        let manifest = ManifestPublication {
            manifest_id: request.manifest_id,
            format_version: request.format_version,
            logical_length: 0,
            content_digest: completed.content_digest,
            root_digest: digest.finalize().into(),
        };
        let mut stored = self.stored.borrow_mut();
        match stored.get(&request.operation_id) {
            Some((prior, existing)) if prior.same_intent(request) && *existing == manifest => {
                Ok(*existing)
            }
            Some(_) => Err(ContentPublicationError::Conflict),
            None => {
                stored.insert(request.operation_id, (request, manifest));
                Ok(manifest)
            }
        }
    }
}

impl DurableContentReader for EmptyContentPublisher {
    fn stream_range(
        &mut self,
        _request: ContentReadRequest,
        _destination: &mut dyn Write,
    ) -> Result<(), ContentReadError> {
        Err(ContentReadError::Unavailable)
    }
}

fn base_publication() -> Result<RootFilePublication, Box<dyn std::error::Error>> {
    Ok(RootFilePublication {
        file: FilePublication {
            operation_id: OperationId::from_bytes([1; 16])?,
            branch_id: BranchId::from_bytes([11; 16])?,
            volume_id: VolumeId::from_bytes([12; 16])?,
            object_id: ObjectId::from_bytes([13; 16])?,
            expected_current_version_id: None,
            version_id: FileVersionId::from_bytes([14; 16])?,
            parent_version_id: None,
            retain_superseded_history: true,
            retention_policy_sequence: 1,
            manifest: ManifestPublication {
                manifest_id: ContentManifestId::from_bytes([15; 16])?,
                format_version: 1,
                logical_length: 0,
                content_digest: blake3::hash(&[]).into(),
                root_digest: [17; 32],
            },
            created_by: PrincipalId::from_bytes([18; 16])?,
            created_at: UnixMicros::new(1),
        },
        root_object_id: ObjectId::from_bytes([2; 16])?,
        expected_namespace_commit_id: None,
        expected_file_object_revision_id: None,
        file_object_revision_id: ObjectRevisionId::from_bytes([3; 16])?,
        root_object_revision_id: ObjectRevisionId::from_bytes([4; 16])?,
        namespace_commit_id: NamespaceCommitId::from_bytes([5; 16])?,
        path: NamespacePublicationPath::new(
            NamespacePath::from_components(["Seed"], NamespaceLimits::PORTABLE)?,
            Vec::new(),
        )?,
        entry_generation: 1,
    })
}
