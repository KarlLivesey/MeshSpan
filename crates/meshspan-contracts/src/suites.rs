// SPDX-License-Identifier: GPL-2.0-only

//! Typed entry points for every replaceable-boundary conformance suite.

use std::fmt::Debug;

use crate::{
    AccessConnector, AdministrationClient, AuthenticationHandler, BackupProvider,
    CertificateChallenge, CodingScheme, ComponentLifecycle, ConformanceCase, ConformanceFailure,
    ConsensusEngine, ContractKind, HarnessError, MetadataRepository, ObservabilitySink,
    PlacementPolicy, StorageProvider, run_conformance_cases, verify_descriptor,
};

fn run_component_cases<Input, Output, Failure, Component, Factory, Handler>(
    cases: &[ConformanceCase<Input, Output, Failure>],
    mut factory: Factory,
    handler: Handler,
    kind: ContractKind,
) -> Result<Vec<ConformanceFailure>, HarnessError>
where
    Input: Clone,
    Output: Debug + Eq,
    Failure: Debug + Eq,
    Component: ComponentLifecycle,
    Factory: FnMut() -> Component,
    Handler: Clone + Fn(&mut Component, Input) -> Result<Output, Failure>,
{
    verify_descriptor(factory().describe(), kind)?;
    run_conformance_cases(cases, || {
        let mut component = factory();
        let execute = handler.clone();
        move |input| execute(&mut component, input)
    })
}

macro_rules! typed_suite {
    ($name:ident, $bound:path, $kind:expr, $doc:literal) => {
        #[doc = $doc]
        ///
        /// # Errors
        ///
        /// Rejects an invalid descriptor/suite or returns exact deterministic case failures.
        pub fn $name<Input, Output, Failure, Component, Factory, Handler>(
            cases: &[ConformanceCase<Input, Output, Failure>],
            factory: Factory,
            handler: Handler,
        ) -> Result<Vec<ConformanceFailure>, HarnessError>
        where
            Input: Clone,
            Output: Debug + Eq,
            Failure: Debug + Eq,
            Component: $bound,
            Factory: FnMut() -> Component,
            Handler: Clone + Fn(&mut Component, Input) -> Result<Output, Failure>,
        {
            run_component_cases(cases, factory, handler, $kind)
        }
    };
}

/// Runs exact vectors against fresh storage-provider implementations.
///
/// # Errors
///
/// Rejects an invalid descriptor/suite or returns exact deterministic case failures.
pub fn run_storage_provider_suite<Input, Output, Failure, Component, Factory, Handler>(
    cases: &[ConformanceCase<Input, Output, Failure>],
    mut factory: Factory,
    handler: Handler,
) -> Result<Vec<ConformanceFailure>, HarnessError>
where
    Input: Clone,
    Output: Debug + Eq,
    Failure: Debug + Eq,
    Component: StorageProvider,
    Factory: FnMut() -> Component,
    Handler: Clone + Fn(&mut Component, Input) -> Result<Output, Failure>,
{
    verify_descriptor(factory().describe(), ContractKind::StorageProvider)?;
    run_conformance_cases(cases, || {
        let mut component = factory();
        let execute = handler.clone();
        move |input| execute(&mut component, input)
    })
}
typed_suite!(
    run_backup_provider_suite,
    BackupProvider,
    ContractKind::BackupProvider,
    "Runs exact vectors against fresh encrypted-backup-provider implementations."
);
typed_suite!(
    run_access_connector_suite,
    AccessConnector,
    ContractKind::AccessConnector,
    "Runs exact vectors against fresh public access-connector implementations."
);
typed_suite!(
    run_administration_client_suite,
    AdministrationClient,
    ContractKind::AdministrationClient,
    "Runs exact vectors against fresh administration-client implementations."
);
typed_suite!(
    run_metadata_repository_suite,
    MetadataRepository,
    ContractKind::MetadataRepository,
    "Runs exact vectors against fresh metadata-repository implementations."
);
typed_suite!(
    run_consensus_engine_suite,
    ConsensusEngine,
    ContractKind::ConsensusEngine,
    "Runs exact vectors against fresh consensus-engine implementations."
);
typed_suite!(
    run_coding_scheme_suite,
    CodingScheme,
    ContractKind::CodingScheme,
    "Runs exact vectors against fresh coding-scheme implementations."
);
typed_suite!(
    run_placement_policy_suite,
    PlacementPolicy,
    ContractKind::PlacementPolicy,
    "Runs exact vectors against fresh placement-policy implementations."
);
typed_suite!(
    run_authentication_handler_suite,
    AuthenticationHandler,
    ContractKind::AuthenticationHandler,
    "Runs exact vectors against fresh authentication-handler implementations."
);
typed_suite!(
    run_certificate_challenge_suite,
    CertificateChallenge,
    ContractKind::CertificateChallenge,
    "Runs exact vectors against fresh certificate-challenge implementations."
);
typed_suite!(
    run_observability_sink_suite,
    ObservabilitySink,
    ContractKind::ObservabilitySink,
    "Runs exact vectors against fresh observability-sink implementations."
);
