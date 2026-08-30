// SPDX-License-Identifier: GPL-2.0-only

//! Immutable owner-side admission decisions for imported federated namespace history.

use meshspan_domain::{
    FederatedMutationAcknowledgement, FederatedMutationAdmission, NamespaceCommitId,
    QuarantineReason, UnixMicros,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

use super::history_import::NamespaceHistoryMutationDecision;
use crate::PublicationError;

const ADMITTED: i64 = 1;
const QUARANTINED: i64 = 2;

pub(super) fn persist(
    transaction: &Transaction<'_>,
    decision: NamespaceHistoryMutationDecision,
    acknowledgement: &FederatedMutationAcknowledgement,
) -> Result<(), PublicationError> {
    if let Some(existing) = load(transaction, decision.commit_id())? {
        return if existing == decision {
            Ok(())
        } else {
            Err(PublicationError::OperationConflict)
        };
    }
    let (kind, reason) = admission_columns(decision.admission());
    let digest = decision_digest(decision, acknowledgement);
    transaction.execute(
        "INSERT INTO federated_namespace_mutation_admissions(
            namespace_commit_id, admission_kind, quarantine_reason, classified_at,
            decision_digest
         ) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![
            decision.commit_id().as_bytes().as_slice(),
            kind,
            reason,
            decision.classified_at().get(),
            digest.as_slice(),
        ],
    )?;
    Ok(())
}

pub(super) fn load(
    connection: &Connection,
    commit_id: NamespaceCommitId,
) -> Result<Option<NamespaceHistoryMutationDecision>, PublicationError> {
    let stored: Option<(i64, Option<i64>, i64, Vec<u8>)> = connection
        .query_row(
            "SELECT admission_kind, quarantine_reason, classified_at, decision_digest
             FROM federated_namespace_mutation_admissions WHERE namespace_commit_id = ?1",
            [commit_id.as_bytes().as_slice()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((kind, reason, classified_at, stored_digest)) = stored else {
        return Ok(None);
    };
    let decision = NamespaceHistoryMutationDecision::new(
        commit_id,
        decode_admission(kind, reason)?,
        UnixMicros::new(classified_at),
    );
    let acknowledgement =
        super::federated_mutation::load(connection, commit_id)?.ok_or(PublicationError::Corrupt)?;
    if stored_digest.as_slice() != decision_digest(decision, &acknowledgement) {
        return Err(PublicationError::Corrupt);
    }
    Ok(Some(decision))
}

pub(in crate::publication) fn is_quarantined(
    connection: &Connection,
    commit_id: NamespaceCommitId,
) -> Result<bool, PublicationError> {
    Ok(load(connection, commit_id)?.is_some_and(|decision| {
        matches!(
            decision.admission(),
            FederatedMutationAdmission::Quarantined(_)
        )
    }))
}

pub(super) fn decision_set_digest(
    decisions: &[NamespaceHistoryMutationDecision],
) -> Result<[u8; 32], PublicationError> {
    let mut ordered = decisions.to_vec();
    ordered.sort_by_key(|decision| decision.commit_id());
    if ordered
        .windows(2)
        .any(|pair| pair[0].commit_id() == pair[1].commit_id())
    {
        return Err(PublicationError::InvalidInput);
    }
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.federated-mutation-decision-set.v1\0");
    digest.update(
        &u32::try_from(ordered.len())
            .map_err(|_| PublicationError::InvalidInput)?
            .to_be_bytes(),
    );
    for decision in ordered {
        append_decision(&mut digest, decision);
    }
    Ok(digest.finalize().into())
}

fn decision_digest(
    decision: NamespaceHistoryMutationDecision,
    acknowledgement: &FederatedMutationAcknowledgement,
) -> [u8; 32] {
    let mut digest = blake3::Hasher::new();
    digest.update(b"meshspan.filesystem.federated-mutation-decision.v1\0");
    append_decision(&mut digest, decision);
    digest.update(&acknowledgement.signing_payload());
    digest.update(&acknowledgement.signature);
    digest.finalize().into()
}

fn append_decision(digest: &mut blake3::Hasher, decision: NamespaceHistoryMutationDecision) {
    digest.update(&decision.commit_id().as_bytes());
    let (kind, reason) = admission_columns(decision.admission());
    digest.update(&[u8::try_from(kind).unwrap_or(u8::MAX)]);
    digest.update(&[reason
        .and_then(|value| u8::try_from(value).ok())
        .unwrap_or(0)]);
    digest.update(&decision.classified_at().get().to_be_bytes());
}

const fn admission_columns(admission: FederatedMutationAdmission) -> (i64, Option<i64>) {
    match admission {
        FederatedMutationAdmission::Admitted => (ADMITTED, None),
        FederatedMutationAdmission::Quarantined(reason) => (QUARANTINED, Some(reason_code(reason))),
    }
}

const fn reason_code(reason: QuarantineReason) -> i64 {
    match reason {
        QuarantineReason::PrincipalInactive => 1,
        QuarantineReason::BeforeValidity => 2,
        QuarantineReason::Expired => 3,
        QuarantineReason::Revoked => 4,
        QuarantineReason::OutsideRights => 5,
        QuarantineReason::OutsideStorageLimit => 6,
    }
}

const fn decode_admission(
    kind: i64,
    reason: Option<i64>,
) -> Result<FederatedMutationAdmission, PublicationError> {
    match (kind, reason) {
        (ADMITTED, None) => Ok(FederatedMutationAdmission::Admitted),
        (QUARANTINED, Some(1)) => Ok(FederatedMutationAdmission::Quarantined(
            QuarantineReason::PrincipalInactive,
        )),
        (QUARANTINED, Some(2)) => Ok(FederatedMutationAdmission::Quarantined(
            QuarantineReason::BeforeValidity,
        )),
        (QUARANTINED, Some(3)) => Ok(FederatedMutationAdmission::Quarantined(
            QuarantineReason::Expired,
        )),
        (QUARANTINED, Some(4)) => Ok(FederatedMutationAdmission::Quarantined(
            QuarantineReason::Revoked,
        )),
        (QUARANTINED, Some(5)) => Ok(FederatedMutationAdmission::Quarantined(
            QuarantineReason::OutsideRights,
        )),
        (QUARANTINED, Some(6)) => Ok(FederatedMutationAdmission::Quarantined(
            QuarantineReason::OutsideStorageLimit,
        )),
        _ => Err(PublicationError::Corrupt),
    }
}
