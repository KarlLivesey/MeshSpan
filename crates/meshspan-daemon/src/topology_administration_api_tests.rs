// SPDX-License-Identifier: GPL-2.0-only

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use axum::body::Body;
use axum::http::{HeaderMap, Request, StatusCode};
use meshspan_api_contract::{
    AssignVolumeProtectionPolicyRequest, AssignVolumeProtectionPolicyResponse,
    CreateFaultGroupRequest, CreateFaultGroupResponse, CreateProtectionPolicyRequest,
    CreateProtectionPolicyResponse, CreateProtectionScenario, FaultGroupSummary,
    ListFaultGroupMembershipsResponse, ListFaultGroupsResponse, ListProtectionPoliciesResponse,
    ListTopologyNodesResponse, ListTopologyQuery, ListTopologyTargetsResponse,
    ProtectionFailureTerm, ProtectionFailureTermSummary, ProtectionPolicySummary,
    ProtectionScenarioSummary, SetFaultGroupMembershipRequest, SetFaultGroupMembershipResponse,
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
        .oneshot(
            Request::post("/api/latest/admin/protection-policies")
                .header("content-type", "application/json")
                .header("x-test-auth", "accepted")
                .body(Body::from(policy_request))?,
        )
        .await?;
    assert_eq!(protected.status(), StatusCode::CREATED);
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
