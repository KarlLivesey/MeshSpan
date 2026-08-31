// SPDX-License-Identifier: GPL-2.0-only

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use meshspan_api_contract::{CreatePasskeyChallengeRequest, SessionAuthentication};
use meshspan_domain::{
    AuthenticationMethodId, DurationMicros, EntropyError, NodeId, OperationId, PrincipalId,
    RandomSource, Revision, UnixMicros,
};
use meshspan_metadata::{LocalDatabase, PasskeyVerificationMaterial};
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

use crate::{
    PasskeyCeremonyKey, PasskeyChallengeConfiguration, PasskeyChallengeService,
    PasskeySessionError, PasskeySessionService,
};

const CREATE_OPERATION: &str = "00000000-0000-4000-8000-000000000071";
const COMPLETE_OPERATION: [u8; 16] = [8; 16];
const RELYING_PARTY: &str = "files.example.test";
const ORIGIN: &str = "https://files.example.test";
const CREDENTIAL_ID: &[u8] = b"credential-one";

#[test]
fn exact_assertion_completes_and_replays_after_restart() -> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("local.sqlite3");
    let node_id = NodeId::from_bytes([1; 16])?;
    let response = create_challenge(&file_path, node_id)?;
    let principal_id = PrincipalId::from_bytes([6; 16])?;
    let authentication = assertion(
        response.challenge_id.as_str(),
        &response.challenge,
        principal_id,
        7,
    )?;
    let material = verification_material(principal_id, 6)?;
    let operation_id = OperationId::from_bytes(COMPLETE_OPERATION)?;

    let database = LocalDatabase::open(&file_path, node_id, UnixMicros::new(2_000_000))?;
    let mut service =
        PasskeySessionService::new(database, PasskeyCeremonyKey::from_bytes([9; 32])?);
    let prepared = service.prepare(&authentication, operation_id, UnixMicros::new(2_000_000))?;
    assert_eq!(prepared.credential_id(), CREDENTIAL_ID);
    assert_eq!(prepared.recorded_result_digest(), None);
    let verified = prepared.verify(&material)?;
    assert_eq!(verified.principal_id, principal_id);
    assert_eq!(verified.signature_counter, 7);
    assert!(!verified.backup_state);
    service.complete(&prepared, [7; 32], UnixMicros::new(3_000_000))?;
    drop(service);

    let database = LocalDatabase::open(&file_path, node_id, UnixMicros::new(4_000_000))?;
    let mut replay = PasskeySessionService::new(database, PasskeyCeremonyKey::from_bytes([9; 32])?);
    let prepared = replay.prepare(&authentication, operation_id, UnixMicros::new(4_000_000))?;
    assert_eq!(prepared.recorded_result_digest(), Some([7; 32]));
    assert_eq!(prepared.verify(&material)?.signature_counter, 7);
    replay.complete(&prepared, [7; 32], UnixMicros::new(4_000_000))?;
    Ok(())
}

#[test]
fn substitution_expiry_and_wrong_protection_key_fail_closed()
-> Result<(), Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let file_path = directory.path().join("local.sqlite3");
    let node_id = NodeId::from_bytes([2; 16])?;
    let response = create_challenge(&file_path, node_id)?;
    let principal_id = PrincipalId::from_bytes([6; 16])?;
    let authentication = assertion(
        response.challenge_id.as_str(),
        &response.challenge,
        principal_id,
        7,
    )?;
    let operation_id = OperationId::from_bytes(COMPLETE_OPERATION)?;

    let database = LocalDatabase::open(&file_path, node_id, UnixMicros::new(2_000_000))?;
    let mut wrong_key =
        PasskeySessionService::new(database, PasskeyCeremonyKey::from_bytes([8; 32])?);
    assert!(matches!(
        wrong_key.prepare(&authentication, operation_id, UnixMicros::new(2_000_000)),
        Err(PasskeySessionError::Failed)
    ));
    drop(wrong_key);

    let database = LocalDatabase::open(&file_path, node_id, UnixMicros::new(2_000_000))?;
    let mut exact_key =
        PasskeySessionService::new(database, PasskeyCeremonyKey::from_bytes([9; 32])?);
    let changed = assertion(
        response.challenge_id.as_str(),
        &response.challenge,
        principal_id,
        8,
    )?;
    assert!(matches!(
        exact_key.prepare(&changed, operation_id, UnixMicros::new(2_000_000)),
        Err(PasskeySessionError::Conflict)
    ));

    let other_directory = tempdir()?;
    let other_path = other_directory.path().join("local.sqlite3");
    let other_node = NodeId::from_bytes([3; 16])?;
    let expired = create_challenge(&other_path, other_node)?;
    let expired_assertion = assertion(
        expired.challenge_id.as_str(),
        &expired.challenge,
        principal_id,
        7,
    )?;
    let database = LocalDatabase::open(&other_path, other_node, UnixMicros::new(200_000_000))?;
    let mut expired_service =
        PasskeySessionService::new(database, PasskeyCeremonyKey::from_bytes([9; 32])?);
    assert!(matches!(
        expired_service.prepare(
            &expired_assertion,
            operation_id,
            UnixMicros::new(200_000_000)
        ),
        Err(PasskeySessionError::Rejected)
    ));
    Ok(())
}

#[test]
fn assertion_requires_exact_origin_user_counter_and_key() -> Result<(), Box<dyn std::error::Error>>
{
    let directory = tempdir()?;
    let file_path = directory.path().join("local.sqlite3");
    let node_id = NodeId::from_bytes([4; 16])?;
    let response = create_challenge(&file_path, node_id)?;
    let principal_id = PrincipalId::from_bytes([6; 16])?;
    let authentication = assertion(
        response.challenge_id.as_str(),
        &response.challenge,
        principal_id,
        7,
    )?;
    let database = LocalDatabase::open(&file_path, node_id, UnixMicros::new(2_000_000))?;
    let mut service =
        PasskeySessionService::new(database, PasskeyCeremonyKey::from_bytes([9; 32])?);
    let prepared = service.prepare(
        &authentication,
        OperationId::from_bytes(COMPLETE_OPERATION)?,
        UnixMicros::new(2_000_000),
    )?;

    let mut wrong_principal = verification_material(PrincipalId::from_bytes([7; 16])?, 6)?;
    assert_eq!(
        prepared.verify(&wrong_principal),
        Err(PasskeySessionError::Rejected)
    );
    wrong_principal.principal_id = principal_id;
    wrong_principal.signature_counter = 7;
    assert_eq!(
        prepared.verify(&wrong_principal),
        Err(PasskeySessionError::Rejected)
    );
    wrong_principal.signature_counter = 6;
    wrong_principal.public_key[1] ^= 1;
    assert_eq!(
        prepared.verify(&wrong_principal),
        Err(PasskeySessionError::Rejected)
    );
    Ok(())
}

fn create_challenge(
    file_path: &std::path::Path,
    node_id: NodeId,
) -> Result<meshspan_api_contract::CreatePasskeyChallengeResponse, Box<dyn std::error::Error>> {
    let database = LocalDatabase::open(file_path, node_id, UnixMicros::new(1))?;
    let mut service = PasskeyChallengeService::new(
        database,
        CountingRandom::default(),
        PasskeyCeremonyKey::from_bytes([9; 32])?,
        PasskeyChallengeConfiguration::new(
            RELYING_PARTY.to_owned(),
            vec![ORIGIN.to_owned()],
            DurationMicros::new(120_000_000),
        )?,
    );
    let request: CreatePasskeyChallengeRequest =
        serde_json::from_value(serde_json::json!({ "operation_id": CREATE_OPERATION }))?;
    Ok(service.create(&request, UnixMicros::new(1_000_000))?)
}

fn assertion(
    challenge_id: &str,
    challenge: &str,
    principal_id: PrincipalId,
    sign_count: u32,
) -> Result<SessionAuthentication, Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_slice(&[0x42; 32])?;
    let client_data = format!(
        "{{\"type\":\"webauthn.get\",\"challenge\":\"{challenge}\",\"origin\":\"{ORIGIN}\",\"crossOrigin\":false}}"
    );
    let mut authenticator_data = Vec::from(Sha256::digest(RELYING_PARTY.as_bytes()).as_slice());
    authenticator_data.push(0x05);
    authenticator_data.extend_from_slice(&sign_count.to_be_bytes());
    let mut signed = authenticator_data.clone();
    signed.extend_from_slice(&Sha256::digest(client_data.as_bytes()));
    let signature: Signature = signing_key.sign(&signed);
    Ok(SessionAuthentication::Passkey {
        challenge_id: challenge_id.to_owned(),
        credential_id: encode_base64url(CREDENTIAL_ID),
        client_data_json: encode_base64url(client_data.as_bytes()),
        authenticator_data: encode_base64url(&authenticator_data),
        signature: encode_base64url(signature.to_der().as_bytes()),
        user_handle: Some(encode_base64url(&principal_id.as_bytes())),
    })
}

fn verification_material(
    principal_id: PrincipalId,
    signature_counter: u64,
) -> Result<PasskeyVerificationMaterial, Box<dyn std::error::Error>> {
    let signing_key = SigningKey::from_slice(&[0x42; 32])?;
    Ok(PasskeyVerificationMaterial {
        principal_id,
        method_id: AuthenticationMethodId::from_bytes([5; 16])?,
        credential_generation: 3,
        revision: Revision::new(4),
        credential_id: CREDENTIAL_ID.to_vec(),
        public_key_algorithm: -7,
        public_key: signing_key
            .verifying_key()
            .to_sec1_point(false)
            .as_bytes()
            .to_vec(),
        signature_counter,
        backup_eligible: false,
        backup_state: false,
    })
}

fn encode_base64url(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut encoded = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for block in bytes.chunks(3) {
        let bits = u32::from(block[0]) << 16
            | u32::from(*block.get(1).unwrap_or(&0)) << 8
            | u32::from(*block.get(2).unwrap_or(&0));
        encoded.push(char::from(ALPHABET[((bits >> 18) & 63) as usize]));
        encoded.push(char::from(ALPHABET[((bits >> 12) & 63) as usize]));
        if block.len() > 1 {
            encoded.push(char::from(ALPHABET[((bits >> 6) & 63) as usize]));
        }
        if block.len() > 2 {
            encoded.push(char::from(ALPHABET[(bits & 63) as usize]));
        }
    }
    encoded
}

#[derive(Default)]
struct CountingRandom {
    calls: Arc<AtomicUsize>,
}

impl RandomSource for CountingRandom {
    fn fill_bytes(&mut self, destination: &mut [u8]) -> Result<(), EntropyError> {
        let value = u8::try_from(self.calls.fetch_add(1, Ordering::SeqCst) + 1)
            .map_err(|_| EntropyError)?;
        destination.fill(value);
        Ok(())
    }
}
