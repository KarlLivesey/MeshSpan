// SPDX-License-Identifier: GPL-2.0-only

//! Deterministic topology identities, strict cursors and public projections.

use std::fmt::Write;

use meshspan_api_contract::{
    CreateFaultGroupRequest, FaultGroupMembershipSummary, FaultGroupSummary,
    ListFaultGroupMembershipsResponse, ListFaultGroupsResponse, ListTopologyNodesResponse,
    ListTopologyQuery, ListTopologyTargetsResponse, OperationId as ApiOperationId,
    SetFaultGroupMembershipRequest, StorageFolderUsageLimit, TopologyCursor, TopologyNodeRoles,
    TopologyNodeState, TopologyNodeSummary, TopologyTargetState, TopologyTargetSummary,
};
use meshspan_domain::{
    AuditEventId, FaultGroupClassId, FaultGroupId, HostId, OperationId, uuid_v8,
};
use meshspan_metadata::{
    AuthoritativeCommand, CommandContext, CreateFaultGroup, FaultGroupCursor,
    FaultGroupMembershipCursor, FaultGroupMembershipRecord, FaultGroupRecord, Page, RecordName,
    SetHostFaultGroupMembership, StorageUsageLimit, TopologyNodeCursor, TopologyNodeRecord,
    TopologyTargetCursor, TopologyTargetRecord,
};
use sha2::{Digest, Sha256};

use super::{IdentityAdministrator, TopologyAdministrationError};
use crate::create_mesh_setup::{format_uuid, parse_uuid};

const CLASS_ID_DOMAIN: &[u8] = b"meshspan.topology.fault-class-id.v1\0";
const GROUP_ID_DOMAIN: &[u8] = b"meshspan.topology.fault-group-id.v1\0";
const AUDIT_ID_DOMAIN: &[u8] = b"meshspan.topology.audit-id.v1\0";

pub(super) fn create_command(
    request: &CreateFaultGroupRequest,
) -> Result<(OperationId, FaultGroupId, AuthoritativeCommand), TopologyAdministrationError> {
    let operation_id = domain_operation(&request.operation_id)?;
    let class_name = RecordName::new(request.class_name.as_str())
        .map_err(|_| TopologyAdministrationError::InvalidInput)?;
    if class_name.canonical().len() > 128 {
        return Err(TopologyAdministrationError::InvalidInput);
    }
    let group_name = RecordName::new(request.group_name.as_str())
        .map_err(|_| TopologyAdministrationError::InvalidInput)?;
    let class_id = FaultGroupClassId::from_bytes(derived_uuid(
        CLASS_ID_DOMAIN,
        class_name.canonical().as_bytes(),
    )?)
    .map_err(|_| TopologyAdministrationError::Failed)?;
    let group_id =
        FaultGroupId::from_bytes(derived_uuid(GROUP_ID_DOMAIN, &operation_id.as_bytes())?)
            .map_err(|_| TopologyAdministrationError::Failed)?;
    Ok((
        operation_id,
        group_id,
        AuthoritativeCommand::CreateFaultGroup(CreateFaultGroup {
            class_id,
            class_name,
            group_id,
            group_name,
        }),
    ))
}

pub(super) fn membership_command(
    group_id: &str,
    host_id: &str,
    request: &SetFaultGroupMembershipRequest,
) -> Result<(OperationId, FaultGroupId, HostId, AuthoritativeCommand), TopologyAdministrationError>
{
    let operation_id = domain_operation(&request.operation_id)?;
    let group_id = FaultGroupId::from_bytes(
        parse_uuid(group_id).map_err(|_| TopologyAdministrationError::InvalidInput)?,
    )
    .map_err(|_| TopologyAdministrationError::InvalidInput)?;
    let host_id = HostId::from_bytes(
        parse_uuid(host_id).map_err(|_| TopologyAdministrationError::InvalidInput)?,
    )
    .map_err(|_| TopologyAdministrationError::InvalidInput)?;
    Ok((
        operation_id,
        group_id,
        host_id,
        AuthoritativeCommand::SetHostFaultGroupMembership(SetHostFaultGroupMembership {
            group_id,
            host_id,
            present: request.present,
        }),
    ))
}

pub(super) fn command_context(
    administrator: IdentityAdministrator,
    operation_id: OperationId,
) -> Result<CommandContext, TopologyAdministrationError> {
    let audit_event_id =
        AuditEventId::from_bytes(derived_uuid(AUDIT_ID_DOMAIN, &operation_id.as_bytes())?)
            .map_err(|_| TopologyAdministrationError::Failed)?;
    Ok(CommandContext {
        operation_id,
        actor_principal_id: administrator.principal_id,
        audit_event_id,
        occurred_at: administrator.now,
        expected_revision: None,
    })
}

pub(super) fn node_response(
    query: &ListTopologyQuery,
    page: Page<TopologyNodeRecord, TopologyNodeCursor>,
) -> Result<ListTopologyNodesResponse, TopologyAdministrationError> {
    Ok(ListTopologyNodesResponse {
        nodes: page
            .items
            .into_iter()
            .map(node_summary)
            .collect::<Result<_, _>>()?,
        next_page_url: page
            .next
            .as_ref()
            .map(encode_node_cursor)
            .transpose()?
            .map(|cursor| page_url("nodes", &cursor, query.limit))
            .transpose()?,
    })
}

pub(super) fn target_response(
    query: &ListTopologyQuery,
    page: Page<TopologyTargetRecord, TopologyTargetCursor>,
) -> Result<ListTopologyTargetsResponse, TopologyAdministrationError> {
    Ok(ListTopologyTargetsResponse {
        targets: page
            .items
            .into_iter()
            .map(target_summary)
            .collect::<Result<_, _>>()?,
        next_page_url: page
            .next
            .as_ref()
            .map(encode_target_cursor)
            .transpose()?
            .map(|cursor| page_url("targets", &cursor, query.limit))
            .transpose()?,
    })
}

pub(super) fn group_response(
    query: &ListTopologyQuery,
    page: Page<FaultGroupRecord, FaultGroupCursor>,
) -> Result<ListFaultGroupsResponse, TopologyAdministrationError> {
    Ok(ListFaultGroupsResponse {
        groups: page.items.into_iter().map(group_summary).collect(),
        next_page_url: page
            .next
            .as_ref()
            .map(encode_group_cursor)
            .transpose()?
            .map(|cursor| page_url("fault-groups", &cursor, query.limit))
            .transpose()?,
    })
}

pub(super) fn membership_response(
    query: &ListTopologyQuery,
    page: Page<FaultGroupMembershipRecord, FaultGroupMembershipCursor>,
) -> Result<ListFaultGroupMembershipsResponse, TopologyAdministrationError> {
    Ok(ListFaultGroupMembershipsResponse {
        memberships: page.items.into_iter().map(membership_summary).collect(),
        next_page_url: page
            .next
            .as_ref()
            .map(encode_membership_cursor)
            .transpose()?
            .map(|cursor| page_url("fault-group-memberships", &cursor, query.limit))
            .transpose()?,
    })
}

pub(super) fn group_summary(record: FaultGroupRecord) -> FaultGroupSummary {
    FaultGroupSummary {
        class_id: format_uuid(record.class_id.as_bytes()),
        class_name: record.class_display_name,
        group_id: format_uuid(record.group_id.as_bytes()),
        group_name: record.group_display_name,
        revision: record.revision.get(),
    }
}

pub(super) fn decode_node_cursor(
    cursor: &TopologyCursor,
) -> Result<TopologyNodeCursor, TopologyAdministrationError> {
    let fields = cursor_fields(cursor, "n", 2)?;
    let node_id = meshspan_domain::NodeId::from_bytes(parse_cursor_uuid(fields[0])?)
        .map_err(|_| TopologyAdministrationError::InvalidInput)?;
    Ok(TopologyNodeCursor::new(decode_text(fields[1])?, node_id))
}

pub(super) fn decode_target_cursor(
    cursor: &TopologyCursor,
) -> Result<TopologyTargetCursor, TopologyAdministrationError> {
    let fields = cursor_fields(cursor, "t", 2)?;
    let target_id = meshspan_domain::TargetId::from_bytes(parse_cursor_uuid(fields[0])?)
        .map_err(|_| TopologyAdministrationError::InvalidInput)?;
    Ok(TopologyTargetCursor::new(
        decode_text(fields[1])?,
        target_id,
    ))
}

pub(super) fn decode_group_cursor(
    cursor: &TopologyCursor,
) -> Result<FaultGroupCursor, TopologyAdministrationError> {
    let fields = cursor_fields(cursor, "g", 3)?;
    let group_id = FaultGroupId::from_bytes(parse_cursor_uuid(fields[0])?)
        .map_err(|_| TopologyAdministrationError::InvalidInput)?;
    Ok(FaultGroupCursor::new(
        decode_text(fields[1])?,
        decode_text(fields[2])?,
        group_id,
    ))
}

pub(super) fn decode_membership_cursor(
    cursor: &TopologyCursor,
) -> Result<FaultGroupMembershipCursor, TopologyAdministrationError> {
    let fields = cursor_fields(cursor, "m", 2)?;
    let host_id = HostId::from_bytes(parse_cursor_uuid(fields[0])?)
        .map_err(|_| TopologyAdministrationError::InvalidInput)?;
    let group_id = FaultGroupId::from_bytes(parse_cursor_uuid(fields[1])?)
        .map_err(|_| TopologyAdministrationError::InvalidInput)?;
    Ok(FaultGroupMembershipCursor::new(host_id, group_id))
}

fn node_summary(
    record: TopologyNodeRecord,
) -> Result<TopologyNodeSummary, TopologyAdministrationError> {
    Ok(TopologyNodeSummary {
        node_id: format_uuid(record.node_id.as_bytes()),
        host_id: format_uuid(record.host_id.as_bytes()),
        display_name: record.display_name,
        state: match record.state {
            1 => TopologyNodeState::Joining,
            2 => TopologyNodeState::Active,
            3 => TopologyNodeState::Draining,
            4 => TopologyNodeState::Retired,
            _ => return Err(TopologyAdministrationError::Failed),
        },
        incarnation: record.incarnation.to_string(),
        roles: TopologyNodeRoles {
            storage: record.roles & 1 != 0,
            gateway: record.roles & 2 != 0,
            metadata_eligible: record.roles & 4 != 0,
        },
        private_endpoint: record.private_endpoint,
        revision: record.revision.get(),
    })
}

fn target_summary(
    record: TopologyTargetRecord,
) -> Result<TopologyTargetSummary, TopologyAdministrationError> {
    Ok(TopologyTargetSummary {
        target_id: format_uuid(record.target_id.as_bytes()),
        node_id: format_uuid(record.node_id.as_bytes()),
        host_id: format_uuid(record.host_id.as_bytes()),
        display_name: record.display_name,
        state: match record.state {
            1 => TopologyTargetState::Active,
            2 => TopologyTargetState::Configuring,
            3 => TopologyTargetState::Draining,
            4 => TopologyTargetState::Unavailable,
            5 => TopologyTargetState::Retired,
            _ => return Err(TopologyAdministrationError::Failed),
        },
        generation: record.generation.to_string(),
        usage_limit: match record.usage_limit {
            StorageUsageLimit::Percent(percent) => StorageFolderUsageLimit::Percent { percent },
            StorageUsageLimit::Bytes(bytes) => StorageFolderUsageLimit::Bytes {
                bytes: bytes.to_string(),
            },
        },
        revision: record.revision.get(),
    })
}

fn membership_summary(record: FaultGroupMembershipRecord) -> FaultGroupMembershipSummary {
    FaultGroupMembershipSummary {
        host_id: format_uuid(record.host_id.as_bytes()),
        group_id: format_uuid(record.group_id.as_bytes()),
        revision: record.revision.get(),
    }
}

fn domain_operation(value: &ApiOperationId) -> Result<OperationId, TopologyAdministrationError> {
    OperationId::from_bytes(
        parse_uuid(value.as_str()).map_err(|_| TopologyAdministrationError::InvalidInput)?,
    )
    .map_err(|_| TopologyAdministrationError::InvalidInput)
}

fn derived_uuid(domain: &[u8], value: &[u8]) -> Result<[u8; 16], TopologyAdministrationError> {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(value);
    digest.finalize()[..16]
        .try_into()
        .map(uuid_v8)
        .map_err(|_| TopologyAdministrationError::Failed)
}

fn encode_node_cursor(
    cursor: &TopologyNodeCursor,
) -> Result<TopologyCursor, TopologyAdministrationError> {
    encoded_cursor("n", cursor.node_id().as_bytes(), &[cursor.canonical_name()])
}

fn encode_target_cursor(
    cursor: &TopologyTargetCursor,
) -> Result<TopologyCursor, TopologyAdministrationError> {
    encoded_cursor(
        "t",
        cursor.target_id().as_bytes(),
        &[cursor.canonical_name()],
    )
}

fn encode_group_cursor(
    cursor: &FaultGroupCursor,
) -> Result<TopologyCursor, TopologyAdministrationError> {
    encoded_cursor(
        "g",
        cursor.group_id().as_bytes(),
        &[cursor.class_name(), cursor.group_name()],
    )
}

fn encode_membership_cursor(
    cursor: &FaultGroupMembershipCursor,
) -> Result<TopologyCursor, TopologyAdministrationError> {
    let encoded = format!(
        "v1.m.{}.{}",
        format_uuid(cursor.host_id().as_bytes()),
        format_uuid(cursor.group_id().as_bytes())
    );
    TopologyCursor::from_encoded(encoded).ok_or(TopologyAdministrationError::Failed)
}

fn encoded_cursor(
    kind: &str,
    identifier: [u8; 16],
    names: &[&str],
) -> Result<TopologyCursor, TopologyAdministrationError> {
    let mut encoded = format!("v1.{kind}.{}", format_uuid(identifier));
    for name in names {
        encoded.push('.');
        append_hex(&mut encoded, name.as_bytes());
    }
    TopologyCursor::from_encoded(encoded).ok_or(TopologyAdministrationError::Failed)
}

fn cursor_fields<'a>(
    cursor: &'a TopologyCursor,
    kind: &str,
    count: usize,
) -> Result<Vec<&'a str>, TopologyAdministrationError> {
    let mut values = cursor.as_str().split('.');
    if values.next() != Some("v1") || values.next() != Some(kind) {
        return Err(TopologyAdministrationError::InvalidInput);
    }
    let fields = values.collect::<Vec<_>>();
    if fields.len() == count {
        Ok(fields)
    } else {
        Err(TopologyAdministrationError::InvalidInput)
    }
}

fn parse_cursor_uuid(value: &str) -> Result<[u8; 16], TopologyAdministrationError> {
    parse_uuid(value).map_err(|_| TopologyAdministrationError::InvalidInput)
}

fn append_hex(output: &mut String, value: &[u8]) {
    for byte in value {
        let _ = write!(output, "{byte:02x}");
    }
}

fn decode_text(value: &str) -> Result<String, TopologyAdministrationError> {
    let (pairs, remainder) = value.as_bytes().as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(TopologyAdministrationError::InvalidInput);
    }
    let bytes = pairs
        .iter()
        .map(|pair| {
            let text =
                std::str::from_utf8(pair).map_err(|_| TopologyAdministrationError::InvalidInput)?;
            u8::from_str_radix(text, 16).map_err(|_| TopologyAdministrationError::InvalidInput)
        })
        .collect::<Result<Vec<_>, _>>()?;
    String::from_utf8(bytes).map_err(|_| TopologyAdministrationError::InvalidInput)
}

fn page_url(
    resource: &str,
    cursor: &TopologyCursor,
    limit: Option<u16>,
) -> Result<String, TopologyAdministrationError> {
    let mut url = format!(
        "/api/latest/admin/topology/{resource}?cursor={}",
        cursor.as_str()
    );
    if let Some(limit) = limit {
        write!(url, "&limit={limit}").map_err(|_| TopologyAdministrationError::Failed)?;
    }
    Ok(url)
}
