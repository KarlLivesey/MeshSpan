// SPDX-License-Identifier: GPL-2.0-only

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use meshspan_api_contract::{
    AcknowledgementConsistency, AcknowledgementPolicySummary, AssignVolumePlacementPolicyRequest,
    AssignVolumePlacementPolicyResponse, AssignVolumeProtectionPolicyRequest,
    AssignVolumeProtectionPolicyResponse, AvailabilityCellSummary,
    CreateAcknowledgementPolicyRequest, CreateAcknowledgementPolicyResponse,
    CreateAvailabilityCellRequest, CreateAvailabilityCellResponse, CreateFaultGroupRequest,
    CreateFaultGroupResponse, CreateLocalityPolicyRequest, CreateLocalityPolicyResponse,
    CreateLocalityRequirement, CreateProtectionPolicyRequest, CreateProtectionPolicyResponse,
    CreateProtectionScenario, FaultGroupSummary, ListAcknowledgementPoliciesResponse,
    ListAvailabilityCellsResponse, ListFaultGroupMembershipsResponse, ListFaultGroupsResponse,
    ListLocalityPoliciesResponse, ListProtectionPoliciesResponse, ListTopologyNodesResponse,
    ListTopologyQuery, ListTopologyTargetsResponse, LocalityPolicySummary,
    LocalityRequirementSummary, ProtectionFailureTerm, ProtectionFailureTermSummary,
    ProtectionPolicySummary, ProtectionScenarioSummary, SetAvailabilityCellMembershipResponse,
    SetFaultGroupMembershipRequest, SetFaultGroupMembershipResponse, StrongFallback,
};
use meshspan_domain::{PrincipalId, UnixMicros};
use tower::ServiceExt;

use crate::{
    BrowserRequestProtection, IdentityAdministrator, TopologyAdministrationController,
    TopologyAdministrationError, topology_administration_api_router,
};

#[tokio::test]
async fn topology_mutation_authenticates_before_reading_an_invalid_body()
-> Result<(), Box<dyn std::error::Error>> {
    let mutated = Arc::new(AtomicBool::new(false));
    let router = topology_administration_api_router(FakeController {
        mutated: Arc::clone(&mutated),
    })?;
    let response = router
        .oneshot(
            Request::post("/api/latest/admin/topology/fault-groups")
                .header("content-type", "application/json")
                .body(Body::from("{"))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    assert!(!mutated.load(Ordering::SeqCst));
    Ok(())
}

#[tokio::test]
async fn authenticated_topology_routes_list_and_create_real_contract_shapes()
-> Result<(), Box<dyn std::error::Error>> {
    let mutated = Arc::new(AtomicBool::new(false));
    let router = topology_administration_api_router(FakeController {
        mutated: Arc::clone(&mutated),
    })?;
    let listed = router
        .clone()
        .oneshot(
            Request::get("/api/latest/admin/topology/nodes?limit=1")
                .header("x-test-auth", "accepted")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(listed.status(), StatusCode::OK);

    let request = serde_json::to_vec(&CreateFaultGroupRequest {
        operation_id: serde_json::from_str("\"123e4567-e89b-42d3-a456-426614174000\"")?,
        class_name: serde_json::from_str("\"Power source\"")?,
        group_name: serde_json::from_str("\"UPS A\"")?,
    })?;
    let created = router
        .clone()
        .oneshot(
            Request::post("/api/latest/admin/topology/fault-groups")
                .header("content-type", "application/json")
                .header("x-test-auth", "accepted")
                .body(Body::from(request))?,
        )
        .await?;
    assert_eq!(created.status(), StatusCode::CREATED);

    let policy_request = serde_json::to_vec(&CreateProtectionPolicyRequest {
        operation_id: serde_json::from_str("\"223e4567-e89b-42d3-a456-426614174000\"")?,
        name: serde_json::from_str("\"Two machines and three devices\"")?,
        scenarios: vec![CreateProtectionScenario {
            name: serde_json::from_str("\"Combined loss\"")?,
            terms: vec![ProtectionFailureTerm {
                class_id: "6d657368-7370-816e-ad6d-616368696e65".to_owned(),
                failure_count: 2,
            }],
        }],
    })?;
    let protected = router
        .clone()
        .oneshot(
            Request::post("/api/latest/admin/protection-policies")
                .header("content-type", "application/json")
                .header("x-test-auth", "accepted")
                .body(Body::from(policy_request))?,
        )
        .await?;
    assert_eq!(protected.status(), StatusCode::CREATED);

    let cell_request = serde_json::to_vec(&CreateAvailabilityCellRequest {
        operation_id: serde_json::from_str("\"323e4567-e89b-42d3-a456-426614174000\"")?,
        name: serde_json::from_str("\"Building A\"")?,
        parent_cell_id: None,
    })?;
    let cell = router
        .clone()
        .oneshot(
            Request::post("/api/latest/admin/topology/availability-cells")
                .header("content-type", "application/json")
                .header("x-test-auth", "accepted")
                .body(Body::from(cell_request))?,
        )
        .await?;
    assert_eq!(cell.status(), StatusCode::CREATED);

    assert!(mutated.load(Ordering::SeqCst));
    Ok(())
}

#[tokio::test]
async fn authenticated_placement_policy_routes_accept_real_contract_shapes()
-> Result<(), Box<dyn std::error::Error>> {
    let mutated = Arc::new(AtomicBool::new(false));
    let router = topology_administration_api_router(FakeController {
        mutated: Arc::clone(&mutated),
    })?;
    let locality_request = serde_json::to_vec(&CreateLocalityPolicyRequest {
        operation_id: serde_json::from_str("\"423e4567-e89b-42d3-a456-426614174000\"")?,
        name: serde_json::from_str("\"Complete in Building A\"")?,
        maximum_lag_micros: Some(1_000_000),
        requirements: vec![CreateLocalityRequirement {
            cell_id: "623e4567-e89b-42d3-a456-426614174000".to_owned(),
            local_protection_policy_id: None,
        }],
    })?;
    let locality = router
        .clone()
        .oneshot(
            Request::post("/api/latest/admin/locality-policies")
                .header("content-type", "application/json")
                .header("x-test-auth", "accepted")
                .body(Body::from(locality_request))?,
        )
        .await?;
    assert_eq!(locality.status(), StatusCode::CREATED);

    let acknowledgement_request = serde_json::to_vec(&CreateAcknowledgementPolicyRequest {
        operation_id: serde_json::from_str("\"523e4567-e89b-42d3-a456-426614174000\"")?,
        name: serde_json::from_str("\"Local durable write\"")?,
        consistency: AcknowledgementConsistency::Eventual,
        minimum_durable_targets: 1,
        minimum_distinct_nodes: 1,
        strong_wait_micros: None,
        fallback: StrongFallback::RemainPending,
        required_scenario_ids: Vec::new(),
        cells: Vec::new(),
    })?;
    let acknowledgement = router
        .clone()
        .oneshot(
            Request::post("/api/latest/admin/acknowledgement-policies")
                .header("content-type", "application/json")
                .header("x-test-auth", "accepted")
                .body(Body::from(acknowledgement_request))?,
        )
        .await?;
    assert_eq!(acknowledgement.status(), StatusCode::CREATED);

    let listed_acknowledgement = router
        .oneshot(
            Request::get("/api/latest/admin/acknowledgement-policies?limit=1")
                .header("x-test-auth", "accepted")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(listed_acknowledgement.status(), StatusCode::OK);
    assert!(mutated.load(Ordering::SeqCst));
    Ok(())
}

struct FakeController {
    mutated: Arc<AtomicBool>,
}

impl TopologyAdministrationController for FakeController {
    fn authenticate(
        &self,
        headers: &HeaderMap,
        _protection: BrowserRequestProtection,
        now: UnixMicros,
    ) -> Result<IdentityAdministrator, TopologyAdministrationError> {
        if headers
            .get("x-test-auth")
            .and_then(|value| value.to_str().ok())
            != Some("accepted")
        {
            return Err(TopologyAdministrationError::Unauthenticated);
        }
        Ok(IdentityAdministrator {
            principal_id: PrincipalId::from_bytes([7; 16])
                .map_err(|_| TopologyAdministrationError::Failed)?,
            now,
        })
    }

    fn list_nodes(
        &self,
        _administrator: IdentityAdministrator,
        _query: ListTopologyQuery,
    ) -> Result<ListTopologyNodesResponse, TopologyAdministrationError> {
        Ok(ListTopologyNodesResponse {
            nodes: Vec::new(),
            next_page_url: None,
        })
    }

    fn list_targets(
        &self,
        _administrator: IdentityAdministrator,
        _query: ListTopologyQuery,
    ) -> Result<ListTopologyTargetsResponse, TopologyAdministrationError> {
        Ok(ListTopologyTargetsResponse {
            targets: Vec::new(),
            next_page_url: None,
        })
    }

    fn list_fault_groups(
        &self,
        _administrator: IdentityAdministrator,
        _query: ListTopologyQuery,
    ) -> Result<ListFaultGroupsResponse, TopologyAdministrationError> {
        Ok(ListFaultGroupsResponse {
            groups: Vec::new(),
            next_page_url: None,
        })
    }

    fn list_fault_group_memberships(
        &self,
        _administrator: IdentityAdministrator,
        _query: ListTopologyQuery,
    ) -> Result<ListFaultGroupMembershipsResponse, TopologyAdministrationError> {
        Ok(ListFaultGroupMembershipsResponse {
            memberships: Vec::new(),
            next_page_url: None,
        })
    }

    fn list_protection_policies(
        &self,
        _administrator: IdentityAdministrator,
        _query: ListTopologyQuery,
    ) -> Result<ListProtectionPoliciesResponse, TopologyAdministrationError> {
        Ok(ListProtectionPoliciesResponse {
            policies: Vec::new(),
            next_page_url: None,
        })
    }

    fn list_availability_cells(
        &self,
        _administrator: IdentityAdministrator,
        _query: ListTopologyQuery,
    ) -> Result<ListAvailabilityCellsResponse, TopologyAdministrationError> {
        Ok(ListAvailabilityCellsResponse {
            cells: Vec::new(),
            next_page_url: None,
        })
    }

    fn list_locality_policies(
        &self,
        _administrator: IdentityAdministrator,
        _query: ListTopologyQuery,
    ) -> Result<ListLocalityPoliciesResponse, TopologyAdministrationError> {
        Ok(ListLocalityPoliciesResponse {
            policies: Vec::new(),
            next_page_url: None,
        })
    }

    fn list_acknowledgement_policies(
        &self,
        _administrator: IdentityAdministrator,
        _query: ListTopologyQuery,
    ) -> Result<ListAcknowledgementPoliciesResponse, TopologyAdministrationError> {
        Ok(ListAcknowledgementPoliciesResponse {
            policies: Vec::new(),
            next_page_url: None,
        })
    }

    fn create_fault_group(
        &mut self,
        _administrator: IdentityAdministrator,
        request: CreateFaultGroupRequest,
    ) -> Result<CreateFaultGroupResponse, TopologyAdministrationError> {
        self.mutated.store(true, Ordering::SeqCst);
        Ok(CreateFaultGroupResponse {
            operation_id: request.operation_id,
            group: group(),
        })
    }

    fn set_fault_group_membership(
        &mut self,
        _administrator: IdentityAdministrator,
        group_id: &str,
        host_id: &str,
        request: SetFaultGroupMembershipRequest,
    ) -> Result<SetFaultGroupMembershipResponse, TopologyAdministrationError> {
        Ok(SetFaultGroupMembershipResponse {
            operation_id: request.operation_id,
            host_id: host_id.to_owned(),
            group_id: group_id.to_owned(),
            present: request.present,
            revision: 2,
        })
    }

    fn create_protection_policy(
        &mut self,
        _administrator: IdentityAdministrator,
        request: CreateProtectionPolicyRequest,
    ) -> Result<CreateProtectionPolicyResponse, TopologyAdministrationError> {
        self.mutated.store(true, Ordering::SeqCst);
        Ok(CreateProtectionPolicyResponse {
            operation_id: request.operation_id,
            policy: policy(),
        })
    }

    fn assign_volume_protection_policy(
        &mut self,
        _administrator: IdentityAdministrator,
        volume_id: &str,
        policy_id: &str,
        request: AssignVolumeProtectionPolicyRequest,
    ) -> Result<AssignVolumeProtectionPolicyResponse, TopologyAdministrationError> {
        Ok(AssignVolumeProtectionPolicyResponse {
            operation_id: request.operation_id,
            volume_id: volume_id.to_owned(),
            policy_id: policy_id.to_owned(),
            revision: 3,
        })
    }

    fn create_locality_policy(
        &mut self,
        _administrator: IdentityAdministrator,
        request: CreateLocalityPolicyRequest,
    ) -> Result<CreateLocalityPolicyResponse, TopologyAdministrationError> {
        self.mutated.store(true, Ordering::SeqCst);
        let requirements = request
            .requirements
            .iter()
            .map(|requirement| LocalityRequirementSummary {
                requirement_id: "923e4567-e89b-42d3-a456-426614174000".to_owned(),
                cell_id: requirement.cell_id.clone(),
                local_protection_policy_id: requirement.local_protection_policy_id.clone(),
            })
            .collect();
        Ok(CreateLocalityPolicyResponse {
            operation_id: request.operation_id,
            policy: LocalityPolicySummary {
                policy_id: "723e4567-e89b-42d3-a456-426614174000".to_owned(),
                name: request.name.as_str().to_owned(),
                maximum_lag_micros: request.maximum_lag_micros,
                requirements,
                revision: 5,
            },
        })
    }

    fn assign_volume_locality_policy(
        &mut self,
        _administrator: IdentityAdministrator,
        volume_id: &str,
        policy_id: &str,
        request: AssignVolumePlacementPolicyRequest,
    ) -> Result<AssignVolumePlacementPolicyResponse, TopologyAdministrationError> {
        Ok(placement_assignment(volume_id, policy_id, request, 6))
    }

    fn create_acknowledgement_policy(
        &mut self,
        _administrator: IdentityAdministrator,
        request: CreateAcknowledgementPolicyRequest,
    ) -> Result<CreateAcknowledgementPolicyResponse, TopologyAdministrationError> {
        self.mutated.store(true, Ordering::SeqCst);
        Ok(CreateAcknowledgementPolicyResponse {
            operation_id: request.operation_id,
            policy: AcknowledgementPolicySummary {
                policy_id: "823e4567-e89b-42d3-a456-426614174000".to_owned(),
                name: request.name.as_str().to_owned(),
                consistency: AcknowledgementConsistency::Eventual,
                minimum_durable_targets: 1,
                minimum_distinct_nodes: 1,
                strong_wait_micros: None,
                fallback: StrongFallback::RemainPending,
                required_scenario_ids: Vec::new(),
                cells: Vec::new(),
                revision: 7,
            },
        })
    }

    fn assign_volume_acknowledgement_policy(
        &mut self,
        _administrator: IdentityAdministrator,
        volume_id: &str,
        policy_id: &str,
        request: AssignVolumePlacementPolicyRequest,
    ) -> Result<AssignVolumePlacementPolicyResponse, TopologyAdministrationError> {
        Ok(placement_assignment(volume_id, policy_id, request, 8))
    }

    fn create_availability_cell(
        &mut self,
        _administrator: IdentityAdministrator,
        request: CreateAvailabilityCellRequest,
    ) -> Result<CreateAvailabilityCellResponse, TopologyAdministrationError> {
        Ok(CreateAvailabilityCellResponse {
            operation_id: request.operation_id,
            cell: AvailabilityCellSummary {
                cell_id: "623e4567-e89b-42d3-a456-426614174000".to_owned(),
                name: request.name.as_str().to_owned(),
                parent_cell_id: request.parent_cell_id,
                revision: 4,
            },
        })
    }

    fn set_host_availability_cell_membership(
        &mut self,
        _administrator: IdentityAdministrator,
        cell_id: &str,
        host_id: &str,
        request: SetFaultGroupMembershipRequest,
    ) -> Result<SetAvailabilityCellMembershipResponse, TopologyAdministrationError> {
        Ok(cell_membership(cell_id, host_id, request))
    }

    fn set_target_availability_cell_membership(
        &mut self,
        _administrator: IdentityAdministrator,
        cell_id: &str,
        target_id: &str,
        request: SetFaultGroupMembershipRequest,
    ) -> Result<SetAvailabilityCellMembershipResponse, TopologyAdministrationError> {
        Ok(cell_membership(cell_id, target_id, request))
    }
}

fn placement_assignment(
    volume_id: &str,
    policy_id: &str,
    request: AssignVolumePlacementPolicyRequest,
    revision: u64,
) -> AssignVolumePlacementPolicyResponse {
    AssignVolumePlacementPolicyResponse {
        operation_id: request.operation_id,
        volume_id: volume_id.to_owned(),
        policy_id: policy_id.to_owned(),
        revision,
    }
}

fn group() -> FaultGroupSummary {
    FaultGroupSummary {
        class_id: "223e4567-e89b-42d3-a456-426614174000".to_owned(),
        class_name: "Power source".to_owned(),
        group_id: "323e4567-e89b-42d3-a456-426614174000".to_owned(),
        group_name: "UPS A".to_owned(),
        revision: 2,
    }
}

fn policy() -> ProtectionPolicySummary {
    ProtectionPolicySummary {
        policy_id: "423e4567-e89b-42d3-a456-426614174000".to_owned(),
        name: "Two machines and three devices".to_owned(),
        scenarios: vec![ProtectionScenarioSummary {
            scenario_id: "523e4567-e89b-42d3-a456-426614174000".to_owned(),
            name: "Combined loss".to_owned(),
            terms: vec![ProtectionFailureTermSummary {
                class_id: "6d657368-7370-816e-ad6d-616368696e65".to_owned(),
                class_name: "Machine".to_owned(),
                failure_count: 2,
            }],
        }],
        revision: 3,
    }
}

fn cell_membership(
    cell_id: &str,
    member_id: &str,
    request: SetFaultGroupMembershipRequest,
) -> SetAvailabilityCellMembershipResponse {
    SetAvailabilityCellMembershipResponse {
        operation_id: request.operation_id,
        cell_id: cell_id.to_owned(),
        member_id: member_id.to_owned(),
        present: request.present,
        revision: 5,
    }
}
