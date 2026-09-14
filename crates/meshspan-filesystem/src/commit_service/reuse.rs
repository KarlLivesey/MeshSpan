// SPDX-License-Identifier: GPL-2.0-only

//! Co-ordinates upload verification, content selection and the namespace's cleanup fence.

use super::{
    CompletedStage, ContentPublicationError, DurableContentPublisher, FilesystemCommitError,
    FilesystemCommitService, ManifestPublication, PublicationError, RootFileCommitRequest,
    root_publication, validate_manifest,
};

impl<P: DurableContentPublisher> FilesystemCommitService<P> {
    pub(super) fn finish_root_content(
        &mut self,
        request: &RootFileCommitRequest,
        intent: super::ContentPublicationRequest,
        sink: P::Sink,
        completed: CompletedStage,
    ) -> Result<ManifestPublication, FilesystemCommitError> {
        if let Some(selected) = self
            .publications
            .selected_content_reuse(intent.operation_id)?
        {
            self.publications
                .reserve_content_reuse(root_publication(request, selected).file)?;
            let reuse = self
                .content
                .verify_reuse(intent, selected, completed)?
                .ok_or(ContentPublicationError::Unavailable)?;
            return self
                .content
                .finish_reuse(intent, sink, reuse)
                .map_err(Into::into);
        }
        // Discovery is bounded per foreground attempt. Incompatible layouts do not block saves.
        let mut after = None;
        if intent.format_version == 2 && completed.logical_length != 0 {
            for _ in 0..4 {
                let candidates = self.publications.content_reuse_candidates(
                    intent.volume_id,
                    completed,
                    after,
                    32,
                )?;
                for candidate in &candidates {
                    let Some(reuse) = self.content.verify_reuse(intent, *candidate, completed)?
                    else {
                        continue;
                    };
                    match self
                        .publications
                        .reserve_content_reuse(root_publication(request, *candidate).file)
                    {
                        Ok(()) => {
                            return self
                                .content
                                .finish_reuse(intent, sink, reuse)
                                .map_err(Into::into);
                        }
                        Err(PublicationError::CleanupFenced) => {}
                        Err(error) => return Err(error.into()),
                    }
                }
                if candidates.len() < 32 {
                    break;
                }
                after = candidates.last().map(|manifest| manifest.manifest_id);
            }
        }
        self.content
            .finish(intent, sink, completed)
            .map_err(Into::into)
    }

    pub(super) fn validate_root_manifest(
        &mut self,
        request: &RootFileCommitRequest,
        manifest: ManifestPublication,
        completed: Option<CompletedStage>,
    ) -> Result<(), FilesystemCommitError> {
        let mut intent = request.content_publication_request();
        if manifest.manifest_id != intent.manifest_id {
            if self
                .publications
                .selected_content_reuse(intent.operation_id)?
                != Some(manifest)
            {
                return Err(ContentPublicationError::Corrupt.into());
            }
            self.publications
                .reserve_content_reuse(root_publication(request, manifest).file)?;
            intent.manifest_id = manifest.manifest_id;
        }
        validate_manifest(intent, manifest, completed)
    }
}
