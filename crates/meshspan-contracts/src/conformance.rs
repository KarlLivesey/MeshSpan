// SPDX-License-Identifier: GPL-2.0-only

//! Reusable exact-input/output contract harness.

use std::fmt::Debug;

use thiserror::Error;

use crate::{ContractError, ContractKind, ImplementationDescriptor};

const MAX_CASES: usize = 4_096;
const MAX_CASE_NAME_BYTES: usize = 160;

/// One exact behaviour vector shared by every implementation of a contract.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ConformanceCase<Input, Output, Failure = ContractError> {
    /// Stable human-readable vector name.
    pub name: &'static str,
    /// Complete validated input supplied to a fresh implementation.
    pub input: Input,
    /// Exact expected output or stable failure.
    pub expected: Result<Output, Failure>,
}

/// Nature of one implementation's conformance failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CaseFailureKind {
    /// The implementation disagreed with the exact expected result.
    UnexpectedResult,
    /// Two fresh instances produced different results for identical input.
    NonDeterministic,
}

/// Bounded report identifying one failed vector without copying hostile values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConformanceFailure {
    /// Stable case name from the checked harness.
    pub case_name: &'static str,
    /// Exact class of failure.
    pub kind: CaseFailureKind,
}

/// Rejection of an invalid harness or implementation descriptor.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum HarnessError {
    /// The suite is empty, excessive or has an invalid case name.
    #[error("conformance suite definition is invalid")]
    InvalidSuite,
    /// The implementation descriptor is malformed or belongs to another contract.
    #[error("implementation descriptor is invalid for this contract")]
    InvalidDescriptor,
}

/// Runs exact vectors twice against fresh implementations to detect mismatch and nondeterminism.
///
/// # Errors
///
/// Rejects an empty, excessive or ambiguously named suite before executing implementation code.
pub fn run_conformance_cases<Input, Output, Failure, Factory, Handler>(
    cases: &[ConformanceCase<Input, Output, Failure>],
    mut factory: Factory,
) -> Result<Vec<ConformanceFailure>, HarnessError>
where
    Input: Clone,
    Output: Debug + Eq,
    Failure: Debug + Eq,
    Factory: FnMut() -> Handler,
    Handler: FnMut(Input) -> Result<Output, Failure>,
{
    validate_cases(cases)?;
    let mut failures = Vec::new();
    for case in cases {
        let first = factory()(case.input.clone());
        let second = factory()(case.input.clone());
        if first != second {
            failures.push(ConformanceFailure {
                case_name: case.name,
                kind: CaseFailureKind::NonDeterministic,
            });
        } else if first != case.expected {
            failures.push(ConformanceFailure {
                case_name: case.name,
                kind: CaseFailureKind::UnexpectedResult,
            });
        }
    }
    Ok(failures)
}

/// Validates common descriptor invariants before a contract-specific suite runs.
///
/// # Errors
///
/// Rejects the wrong contract, invalid identifier, absent versions or zero resource limits.
pub fn verify_descriptor(
    descriptor: ImplementationDescriptor,
    expected_contract: ContractKind,
) -> Result<(), HarnessError> {
    let identifier_is_valid = !descriptor.implementation_id.is_empty()
        && descriptor.implementation_id.len() <= 80
        && descriptor
            .implementation_id
            .bytes()
            .enumerate()
            .all(|(index, byte)| match byte {
                b'a'..=b'z' | b'0'..=b'9' => true,
                b'-' if index > 0 => true,
                _ => false,
            });
    if descriptor.contract != expected_contract
        || !identifier_is_valid
        || descriptor.versions.is_empty()
        || descriptor.limits.validate().is_err()
    {
        return Err(HarnessError::InvalidDescriptor);
    }
    Ok(())
}

fn validate_cases<Input, Output, Failure>(
    cases: &[ConformanceCase<Input, Output, Failure>],
) -> Result<(), HarnessError> {
    let suite_is_valid = !cases.is_empty()
        && cases.len() <= MAX_CASES
        && cases.iter().all(|case| {
            !case.name.is_empty()
                && case.name.len() <= MAX_CASE_NAME_BYTES
                && !case.name.chars().any(char::is_control)
        });
    if suite_is_valid {
        Ok(())
    } else {
        Err(HarnessError::InvalidSuite)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        CaseFailureKind, ConformanceCase, ConformanceFailure, HarnessError, run_conformance_cases,
        verify_descriptor,
    };
    use crate::{ContractKind, ContractLimits, ContractVersion, ImplementationDescriptor};

    #[test]
    fn harness_accepts_exact_deterministic_vectors() {
        let cases = [ConformanceCase {
            name: "doubles a bounded value",
            input: 4_u8,
            expected: Ok::<u8, ()>(8),
        }];
        assert_eq!(
            run_conformance_cases(&cases, || |value| Ok(value * 2)),
            Ok(Vec::new())
        );
    }

    #[test]
    fn harness_reports_mismatch_without_copying_values() {
        let cases = [ConformanceCase {
            name: "rejects zero",
            input: 0_u8,
            expected: Err::<u8, _>("invalid"),
        }];
        assert_eq!(
            run_conformance_cases(&cases, || |value| Ok::<u8, &str>(value)),
            Ok(vec![ConformanceFailure {
                case_name: "rejects zero",
                kind: CaseFailureKind::UnexpectedResult,
            }])
        );
    }

    #[test]
    fn descriptor_rejects_wrong_contract_and_unbounded_zero_limits() {
        let descriptor = ImplementationDescriptor {
            implementation_id: "folder-storage",
            contract: ContractKind::StorageProvider,
            versions: &[ContractVersion::V1_0],
            limits: ContractLimits {
                maximum_control_bytes: 1_024,
                maximum_items: 100,
                maximum_concurrency: 4,
            },
        };
        assert_eq!(
            verify_descriptor(descriptor, ContractKind::StorageProvider),
            Ok(())
        );
        assert_eq!(
            verify_descriptor(descriptor, ContractKind::ConsensusEngine),
            Err(HarnessError::InvalidDescriptor)
        );
        assert_eq!(
            verify_descriptor(
                ImplementationDescriptor {
                    limits: ContractLimits {
                        maximum_concurrency: 0,
                        ..descriptor.limits
                    },
                    ..descriptor
                },
                ContractKind::StorageProvider
            ),
            Err(HarnessError::InvalidDescriptor)
        );
    }
}
