// SPDX-License-Identifier: Apache-2.0
//! Real Organization authoring through shared codecs and durable original-create receipts.

mod types;
pub use types::*;

use reqwest::Method;
use std::collections::BTreeSet;

use scoplen_api::{
    group_policy::{
        GroupCreateRequest, GroupFields, GroupPage, GroupReplaceRequest, GroupResource,
        GroupSource, MAX_GROUP_POLICY_BYTES, PolicyCreateRequest, PolicyFields, PolicyPage,
        PolicyReplaceRequest, PolicyResource, SimpleRule, SimpleRuleInput, SimpleRuleSelector,
        SimpleRuleSubject,
    },
    inventory::{
        InventoryCreateRequest, InventoryFields, InventoryPage, InventoryReplaceRequest,
        InventoryResource, MAX_INVENTORY_PAGE_BYTES, MAX_INVENTORY_RESOURCE_BYTES,
    },
};

use super::*;
use crate::store::team_authoring::TeamAuthoringRecord;

impl TeamAuthoringCollection {
    fn operation(self, action: usize) -> DeviceAccessOperation {
        use DeviceAccessOperation as Op;
        (match self {
            Self::Host => [
                Op::InventoryHostList,
                Op::InventoryHostRead,
                Op::InventoryHostCreate,
                Op::InventoryHostReplace,
                Op::InventoryHostDelete,
            ],
            Self::Login => [
                Op::InventoryAccessProfileList,
                Op::InventoryAccessProfileRead,
                Op::InventoryAccessProfileCreate,
                Op::InventoryAccessProfileReplace,
                Op::InventoryAccessProfileDelete,
            ],
            Self::Route => [
                Op::InventoryRouteList,
                Op::InventoryRouteRead,
                Op::InventoryRouteCreate,
                Op::InventoryRouteReplace,
                Op::InventoryRouteDelete,
            ],
            Self::HostGroup => [
                Op::InventoryHostGroupList,
                Op::InventoryHostGroupRead,
                Op::InventoryHostGroupCreate,
                Op::InventoryHostGroupReplace,
                Op::InventoryHostGroupDelete,
            ],
            Self::TrustRecord => [
                Op::InventoryTrustRecordList,
                Op::InventoryTrustRecordRead,
                Op::InventoryTrustRecordCreate,
                Op::InventoryTrustRecordReplace,
                Op::InventoryTrustRecordDelete,
            ],
            Self::Snippet => [
                Op::InventorySnippetList,
                Op::InventorySnippetRead,
                Op::InventorySnippetCreate,
                Op::InventorySnippetReplace,
                Op::InventorySnippetDelete,
            ],
            Self::GatewayNetwork => [
                Op::InventoryGatewayNetworkList,
                Op::InventoryGatewayNetworkRead,
                Op::InventoryGatewayNetworkCreate,
                Op::InventoryGatewayNetworkReplace,
                Op::InventoryGatewayNetworkDelete,
            ],
            Self::Group => [
                Op::OrganizationGroupList,
                Op::OrganizationGroupRead,
                Op::OrganizationGroupCreate,
                Op::OrganizationGroupReplace,
                Op::OrganizationGroupDelete,
            ],
            Self::Policy => [
                Op::OrganizationPolicyList,
                Op::OrganizationPolicyRead,
                Op::OrganizationPolicyCreate,
                Op::OrganizationPolicyReplace,
                Op::OrganizationPolicyDelete,
            ],
        })[action]
    }

    fn from_segment(value: &str) -> Result<Self, TeamError> {
        match value {
            "hosts" => Ok(Self::Host),
            "access-profiles" => Ok(Self::Login),
            "routes" => Ok(Self::Route),
            "host-groups" => Ok(Self::HostGroup),
            "trust-records" => Ok(Self::TrustRecord),
            "snippets" => Ok(Self::Snippet),
            "gateway-networks" => Ok(Self::GatewayNetwork),
            "groups" => Ok(Self::Group),
            "policies" => Ok(Self::Policy),
            _ => Err(TeamFailure::InvalidTeamResponse.into()),
        }
    }

    fn resource_limit(self) -> usize {
        if self.inventory().is_some() {
            MAX_INVENTORY_RESOURCE_BYTES
        } else {
            MAX_GROUP_POLICY_BYTES
        }
    }
}

impl PersonalServer {
    /// Fetch one live administration page, independently of the complete synchronized view.
    pub async fn team_authoring_page(
        &self,
        store: Arc<Store>,
        organization_id: &str,
        collection: TeamAuthoringCollection,
        cursor: Option<&str>,
    ) -> Result<TeamAuthoringPageView, TeamError> {
        let organization = parse_id(organization_id)?;
        let query = OrganizationListQuery {
            cursor: cursor.map(parse_id).transpose()?,
            ..Default::default()
        };
        query.validate().map_err(invalid)?;
        let base = format!("/api/v1/orgs/{organization}/{}", collection.segment());
        let mut path = format!("{base}?limit={}", query.limit);
        if let Some(cursor) = query.cursor {
            path.push_str(&format!("&cursor={cursor}"));
        }
        let session = self.team_session(&store, collection.operation(0)).await?;
        let proof = session.proof("GET", &base)?;
        let response = self
            .transport
            .as_ref()
            .map_err(|error| *error)?
            .team_get(
                &session.identity.origin,
                &path,
                session.token()?,
                &proof,
                MAX_INVENTORY_PAGE_BYTES,
            )
            .await?;
        session.current(&store)?;
        require_authoring_success(&store, &session, &response, 200)?;
        let (items, next_cursor) = if let Some(kind) = collection.inventory() {
            let page = InventoryPage::from_http_json(
                kind,
                response.body.as_bytes(),
                response.cache_control.as_deref(),
                response.pragma.as_deref(),
            )
            .map_err(invalid)?;
            page.validate_for_request(kind, query).map_err(invalid)?;
            (
                page.items
                    .into_iter()
                    .map(|item| inventory_view(&session.identity, organization, collection, item))
                    .collect::<Result<Vec<_>, _>>()?,
                page.next_cursor,
            )
        } else if collection == TeamAuthoringCollection::Group {
            let page = GroupPage::from_http_json(
                response.body.as_bytes(),
                response.cache_control.as_deref(),
                response.pragma.as_deref(),
            )
            .map_err(invalid)?;
            page.validate_for_query(query).map_err(invalid)?;
            (
                page.items
                    .into_iter()
                    .map(|item| group_view(&session.identity, organization, item))
                    .collect(),
                page.next_cursor,
            )
        } else {
            let page = PolicyPage::from_http_json(
                response.body.as_bytes(),
                response.cache_control.as_deref(),
                response.pragma.as_deref(),
            )
            .map_err(invalid)?;
            page.validate_for_query(query).map_err(invalid)?;
            let mut items = Vec::new();
            for item in page.items {
                item.validate_for_request(organization, item.id).map_err(invalid)?;
                items.push(policy_view(&session.identity, organization, item));
            }
            (items, page.next_cursor)
        };
        Ok(TeamAuthoringPageView {
            origin: session.identity.origin,
            account_id: session.identity.account_id.to_string(),
            organization_id: organization.to_string(),
            collection,
            items,
            next_cursor: next_cursor.map(|id| id.to_string()),
        })
    }

    /// Capture this resource's actual fields and strong ETag before an explicit edit or delete.
    pub async fn team_authoring_resource(
        &self,
        store: Arc<Store>,
        organization_id: &str,
        collection: TeamAuthoringCollection,
        resource_id: &str,
    ) -> Result<TeamAuthoringResourceView, TeamError> {
        let organization = parse_id(organization_id)?;
        let id = parse_id(resource_id)?;
        let path = format!("/api/v1/orgs/{organization}/{}/{id}", collection.segment());
        let session = self.team_session(&store, collection.operation(1)).await?;
        let proof = session.proof("GET", &path)?;
        let response = self
            .transport
            .as_ref()
            .map_err(|error| *error)?
            .team_get(
                &session.identity.origin,
                &path,
                session.token()?,
                &proof,
                collection.resource_limit(),
            )
            .await?;
        session.current(&store)?;
        require_authoring_success(&store, &session, &response, 200)?;
        resource_response(&session.identity, organization, collection, id, &response)
            .map(|(view, _)| view)
    }

    /// Read the exact original create locally; a retained receipt grants no current access.
    pub fn pending_team_authoring(
        &self,
        store: &Store,
        organization_id: &str,
    ) -> Result<Option<TeamAuthoringCreateView>, TeamError> {
        let identity = record(store)?;
        store
            .team_authoring_pending(&identity, parse_id(organization_id)?)
            .map_err(storage)?
            .map(|pending| pending_view(&identity, &pending, now_ms()?))
            .transpose()
    }

    /// Validate named form values with the shared codec and retain them before any POST.
    pub fn prepare_team_authoring(
        &self,
        store: &Store,
        organization_id: &str,
        data: TeamAuthoringData,
    ) -> Result<TeamAuthoringCreateView, TeamError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let identity = record(store)?;
        let organization = parse_id(organization_id)?;
        let resource = scoplen_model::new_uuid_v7().map_err(invalid)?;
        let pending = TeamAuthoringRecord {
            organization,
            operation: scoplen_model::new_uuid_v7().map_err(invalid)?,
            resource,
            collection: data.collection().segment().into(),
            payload: SecretVec::new(request_body(&data, Some(resource))?),
            phase: 0,
            first_attempt_ms: None,
            response: None,
        };
        let view = pending_view(&identity, &pending, now_ms()?)?;
        if !store.prepare_team_authoring(&identity, &pending).map_err(storage)? {
            return Err(TeamFailure::AuthoringPending.into());
        }
        Ok(view)
    }

    /// Send or explicitly confirm only the retained UUIDv7 key, object id and canonical body.
    pub async fn submit_team_authoring(
        &self,
        store: Arc<Store>,
        organization_id: &str,
        operation_id: &str,
    ) -> Result<TeamAuthoringCreateView, TeamError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let identity = record(&store)?;
        let pending = load_authoring(&store, &identity, organization_id, operation_id)?;
        let current = pending_view(&identity, &pending, now_ms()?)?;
        match current.phase {
            TeamAuthoringCreatePhase::Confirmed => return Ok(current),
            TeamAuthoringCreatePhase::Expired => return Err(TeamFailure::OperationExpired.into()),
            _ => {}
        }
        let collection = current.data.collection();
        let path = format!("/api/v1/orgs/{}/{}", pending.organization, collection.segment());
        let session = self.team_session(&store, collection.operation(2)).await?;
        let proof = session.proof("POST", &path)?;
        if !store
            .dispatch_team_authoring(&session.identity, &pending, &session.access, now_ms()?)
            .map_err(storage)?
        {
            return Err(PersonalServerError::Busy.into());
        }
        let sent = load_authoring(&store, &session.identity, organization_id, operation_id)?;
        let response = self
            .transport
            .as_ref()
            .map_err(|error| *error)?
            .team_exchange(
                &session.identity.origin,
                &path,
                Method::POST,
                Some(sent.payload.as_bytes()),
                session.token()?,
                &proof,
                Some(sent.operation),
                None,
                collection.resource_limit(),
            )
            .await;
        store
            .invalidate_team_assets(&session.identity, pending.organization, None)
            .map_err(storage)?;
        let response = match response {
            Ok(response) => response,
            Err(PersonalServerError::ConnectionBeforeRequest) if pending.phase == 0 => {
                finish_create(&store, &session, &sent, None)?;
                return Err(PersonalServerError::ConnectionBeforeRequest.into());
            }
            Err(_) => return Err(TeamFailure::AuthoringUnknown.into()),
        };
        session.current(&store).map_err(|_| TeamFailure::AuthoringUnknown)?;
        if response.status == 201 {
            let (resource, canonical) = resource_response(
                &session.identity,
                pending.organization,
                collection,
                pending.resource,
                &response,
            )
            .map_err(|_| TeamFailure::AuthoringUnknown)?;
            if resource.read_only
                || request_body(&resource.data, Some(pending.resource))? != sent.payload.as_bytes()
            {
                return Err(TeamFailure::AuthoringUnknown.into());
            }
            finish_create(&store, &session, &sent, Some(&canonical))?;
            return self
                .pending_team_authoring(&store, organization_id)?
                .ok_or_else(|| TeamFailure::OperationMissing.into());
        }
        let problem = problem(&response).map_err(|_| TeamFailure::AuthoringUnknown)?;
        let error = authoring_problem(&problem)?;
        // A later refusal cannot settle an earlier request whose response was lost.
        if pending.phase == 0
            && !problem.changed
            && problem.code.as_str() != "organization.conflict"
        {
            finish_create(&store, &session, &sent, None)?;
        }
        if problem.status == 401 {
            store
                .invalidate_personal_session(&session.identity, &session.access)
                .map_err(storage)?;
        }
        Err(error)
    }

    /// Clear prepared/confirmed state, or archive expired uncertainty after explicit review.
    pub fn discard_team_authoring(
        &self,
        store: &Store,
        organization_id: &str,
        operation_id: &str,
    ) -> Result<(), TeamError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        let identity = record(store)?;
        let pending = load_authoring(store, &identity, organization_id, operation_id)?;
        if pending_view(&identity, &pending, now_ms()?)?.phase == TeamAuthoringCreatePhase::Unknown
        {
            return Err(TeamFailure::AuthoringUnknown.into());
        }
        if !store.discard_team_authoring(&identity, &pending, now_ms()?).map_err(storage)? {
            return Err(PersonalServerError::Busy.into());
        }
        Ok(())
    }

    /// Replace one resource using exactly the fields and ETag captured by the visible form.
    pub async fn update_team_authoring(
        &self,
        store: Arc<Store>,
        organization_id: &str,
        resource_id: &str,
        etag: &str,
        data: TeamAuthoringData,
    ) -> Result<TeamAuthoringResourceView, TeamError> {
        let body = request_body(&data, None)?;
        let collection = data.collection();
        let (session, organization, id, response) = self
            .mutate_authoring(&store, organization_id, resource_id, collection, etag, Some(&body))
            .await?;
        resource_response(&session.identity, organization, collection, id, &response)
            .map(|(view, _)| view)
            .map_err(|_| TeamFailure::AuthoringUnknown.into())
    }

    /// Delete only the explicitly reviewed resource at its original ETag.
    pub async fn delete_team_authoring(
        &self,
        store: Arc<Store>,
        organization_id: &str,
        collection: TeamAuthoringCollection,
        resource_id: &str,
        etag: &str,
    ) -> Result<(), TeamError> {
        self.mutate_authoring(&store, organization_id, resource_id, collection, etag, None).await?;
        Ok(())
    }

    async fn mutate_authoring(
        &self,
        store: &Store,
        organization_id: &str,
        resource_id: &str,
        collection: TeamAuthoringCollection,
        etag: &str,
        body: Option<&[u8]>,
    ) -> Result<(TeamSession, Uuid, Uuid, Response), TeamError> {
        let _operation = self.operation.try_lock().map_err(|_| PersonalServerError::Busy)?;
        parse_organization_if_match(Some(etag)).map_err(|_| TeamFailure::AuthoringConflict)?;
        let organization = parse_id(organization_id)?;
        let id = parse_id(resource_id)?;
        let method = if body.is_some() { Method::PUT } else { Method::DELETE };
        let session = self
            .team_session(store, collection.operation(if body.is_some() { 3 } else { 4 }))
            .await?;
        let path = format!("/api/v1/orgs/{organization}/{}/{id}", collection.segment());
        let proof = session.proof(method.as_str(), &path)?;
        let result = self
            .transport
            .as_ref()
            .map_err(|error| *error)?
            .team_exchange(
                &session.identity.origin,
                &path,
                method,
                body,
                session.token()?,
                &proof,
                None,
                Some(etag),
                collection.resource_limit(),
            )
            .await;
        store.invalidate_team_assets(&session.identity, organization, None).map_err(storage)?;
        let response = match result {
            Ok(response) => response,
            Err(PersonalServerError::ConnectionBeforeRequest) => {
                return Err(PersonalServerError::ConnectionBeforeRequest.into());
            }
            Err(_) => return Err(TeamFailure::AuthoringUnknown.into()),
        };
        session.current(store).map_err(|_| TeamFailure::AuthoringUnknown)?;
        require_authoring_success(
            store,
            &session,
            &response,
            if body.is_some() { 200 } else { 204 },
        )?;
        Ok((session, organization, id, response))
    }

    /// Preview one ordinary rule with the shared pure generator; this creates no authorization.
    pub fn preview_team_simple_rule(
        &self,
        store: &Store,
        organization_id: &str,
        input: TeamSimpleRuleInput,
    ) -> Result<TeamSimpleRulePreview, TeamError> {
        let identity = record(store)?;
        let organization = parse_id(organization_id)?;
        let subject = match (input.membership_id.as_deref(), input.group_id.as_deref()) {
            (Some(id), None) => SimpleRuleSubject::Membership(parse_id(id)?),
            (None, Some(id)) => SimpleRuleSubject::Group(parse_id(id)?),
            _ => return Err(TeamFailure::InvalidAuthoringData.into()),
        };
        let mut selected = BTreeSet::new();
        for resource in &input.resources {
            let kind = resource.collection.inventory().ok_or(TeamFailure::InvalidAuthoringData)?;
            let id = parse_id(&resource.id)?;
            if !selected.insert((kind, id)) {
                return Err(TeamFailure::InvalidAuthoringData.into());
            }
        }
        let rule = match input.permission {
            TeamSimplePermission::View => SimpleRule::View {
                resources: selected
                    .iter()
                    .map(|(kind, id)| SimpleRuleSelector {
                        object_type: kind.object_type(),
                        id: *id,
                    })
                    .collect(),
            },
            TeamSimplePermission::Connect => {
                if selected.iter().any(|(kind, _)| {
                    !matches!(
                        kind,
                        scoplen_api::inventory::InventoryType::Host
                            | scoplen_api::inventory::InventoryType::HostGroup
                    )
                }) {
                    return Err(TeamFailure::InvalidAuthoringData.into());
                }
                SimpleRule::Connect {
                    hosts: selected
                        .iter()
                        .filter(|(kind, _)| *kind == scoplen_api::inventory::InventoryType::Host)
                        .map(|(_, id)| *id)
                        .collect(),
                    host_groups: selected
                        .iter()
                        .filter(|(kind, _)| {
                            *kind == scoplen_api::inventory::InventoryType::HostGroup
                        })
                        .map(|(_, id)| *id)
                        .collect(),
                    remote_user: input.remote_user.ok_or(TeamFailure::InvalidAuthoringData)?,
                }
            }
        };
        let source = SimpleRuleInput { organization, subject, rule }
            .generate()
            .map_err(|_| TeamFailure::InvalidAuthoringData)?;
        let mut dependencies = BTreeSet::new();
        if matches!(input.permission, TeamSimplePermission::View)
            && let Some(view) =
                store.team_assets_record(&identity, organization).map_err(storage)?
        {
            for object in view.objects {
                let Ok(kind) =
                    scoplen_api::inventory::InventoryType::from_object_type(object.object_type)
                else {
                    continue;
                };
                if !selected.contains(&(kind, object.id)) {
                    continue;
                }
                for reference in InventoryFields::from_object(&object)
                    .map_err(invalid)?
                    .references()
                    .map_err(invalid)?
                {
                    if !selected.contains(&(reference.kind, reference.id)) {
                        dependencies.insert((reference.kind, reference.id));
                    }
                }
            }
        }
        Ok(TeamSimpleRulePreview {
            source,
            dependencies: dependencies
                .into_iter()
                .map(|(kind, id)| {
                    Ok(TeamSimpleRuleResource {
                        collection: TeamAuthoringCollection::from_segment(kind.segment())?,
                        id: id.to_string(),
                    })
                })
                .collect::<Result<_, TeamError>>()?,
        })
    }
}

fn request_body(data: &TeamAuthoringData, id: Option<Uuid>) -> Result<Vec<u8>, TeamError> {
    if let Some(kind) = data.collection().inventory() {
        let fields = InventoryFields::from_json(
            kind,
            &data.fields_json().map_err(|_| TeamFailure::InvalidAuthoringData)?,
        )
        .map_err(|_| TeamFailure::InvalidAuthoringData)?;
        return match id {
            Some(id) => InventoryCreateRequest { id, fields }.to_json(),
            None => InventoryReplaceRequest { fields }.to_json(),
        }
        .map_err(|_| TeamFailure::InvalidAuthoringData.into());
    }
    match data {
        TeamAuthoringData::Group(value) => {
            let fields = GroupFields {
                name: value.name.clone(),
                members: value.members.iter().map(|id| parse_id(id)).collect::<Result<_, _>>()?,
            };
            match id {
                Some(id) => GroupCreateRequest { id, fields }.to_json(),
                None => GroupReplaceRequest { fields }.to_json(),
            }
        }
        TeamAuthoringData::Policy(value) => {
            let fields = PolicyFields {
                name: value.name.clone(),
                source: value.source.clone(),
                enabled: value.enabled,
            };
            match id {
                Some(id) => PolicyCreateRequest { id, fields }.to_json(),
                None => PolicyReplaceRequest { fields }.to_json(),
            }
        }
        _ => unreachable!("non-inventory data"),
    }
    .map_err(|_| TeamFailure::InvalidAuthoringData.into())
}

fn inventory_data(
    collection: TeamAuthoringCollection,
    fields: &InventoryFields,
) -> Result<(TeamAuthoringData, Option<TeamTrustAttribution>), TeamError> {
    let mut fields: serde_json::Value =
        serde_json::from_slice(&fields.to_json().map_err(invalid)?).map_err(invalid)?;
    let attribution = if collection == TeamAuthoringCollection::TrustRecord {
        let fields = fields.as_object_mut().ok_or(TeamFailure::InvalidTeamResponse)?;
        let attributed = fields.contains_key("accepted_at");
        let mut take = |key| -> Result<String, TeamError> {
            fields
                .remove(key)
                .and_then(|value| value.as_str().map(str::to_owned))
                .ok_or_else(|| TeamFailure::InvalidTeamResponse.into())
        };
        if attributed {
            Some(TeamTrustAttribution {
                accepted_at: take("accepted_at")?,
                accepted_by_device: take("accepted_by_device")?,
                accepted_by_account: take("accepted_by_account")?,
            })
        } else {
            None
        }
    } else {
        None
    };
    let data = serde_json::from_value(serde_json::json!({ "kind": collection, "fields": fields }))
        .map_err(invalid)?;
    Ok((data, attribution))
}

fn inventory_view(
    identity: &PersonalRecord,
    organization: Uuid,
    collection: TeamAuthoringCollection,
    resource: InventoryResource,
) -> Result<TeamAuthoringResourceView, TeamError> {
    let (data, trust_attribution) = inventory_data(collection, &resource.fields)?;
    Ok(TeamAuthoringResourceView {
        origin: identity.origin.clone(),
        account_id: identity.account_id.to_string(),
        organization_id: organization.to_string(),
        id: resource.id.to_string(),
        etag: resource.etag,
        created_at: resource.created_at,
        updated_at: resource.updated_at,
        data,
        read_only: false,
        trust_attribution,
    })
}

fn group_view(
    identity: &PersonalRecord,
    organization: Uuid,
    resource: GroupResource,
) -> TeamAuthoringResourceView {
    TeamAuthoringResourceView {
        origin: identity.origin.clone(),
        account_id: identity.account_id.to_string(),
        organization_id: organization.to_string(),
        id: resource.id.to_string(),
        etag: resource.etag,
        created_at: resource.created_at,
        updated_at: resource.updated_at,
        data: TeamAuthoringData::Group(TeamGroupFields {
            name: resource.fields.name,
            members: resource.fields.members.into_iter().map(|id| id.to_string()).collect(),
        }),
        read_only: resource.source == GroupSource::Idp,
        trust_attribution: None,
    }
}

fn policy_view(
    identity: &PersonalRecord,
    organization: Uuid,
    resource: PolicyResource,
) -> TeamAuthoringResourceView {
    TeamAuthoringResourceView {
        origin: identity.origin.clone(),
        account_id: identity.account_id.to_string(),
        organization_id: organization.to_string(),
        id: resource.id.to_string(),
        etag: resource.etag,
        created_at: resource.created_at,
        updated_at: resource.updated_at,
        data: TeamAuthoringData::Policy(TeamPolicyFields {
            name: resource.fields.name,
            source: resource.fields.source,
            enabled: resource.fields.enabled,
        }),
        read_only: false,
        trust_attribution: None,
    }
}

fn resource_response(
    identity: &PersonalRecord,
    organization: Uuid,
    collection: TeamAuthoringCollection,
    id: Uuid,
    response: &Response,
) -> Result<(TeamAuthoringResourceView, Vec<u8>), TeamError> {
    decode_resource(
        identity,
        organization,
        collection,
        id,
        response.body.as_bytes(),
        Some(response),
    )
}

fn decode_resource(
    identity: &PersonalRecord,
    organization: Uuid,
    collection: TeamAuthoringCollection,
    id: Uuid,
    body: &[u8],
    http: Option<&Response>,
) -> Result<(TeamAuthoringResourceView, Vec<u8>), TeamError> {
    if let Some(kind) = collection.inventory() {
        let resource = if let Some(response) = http {
            InventoryResource::from_http_json(
                kind,
                body,
                response.etag.as_deref(),
                response.cache_control.as_deref(),
                response.pragma.as_deref(),
            )
        } else {
            InventoryResource::from_json(kind, body)
        }
        .map_err(invalid)?;
        resource.validate_for_request(kind, id).map_err(invalid)?;
        let canonical = resource.to_json().map_err(invalid)?;
        Ok((inventory_view(identity, organization, collection, resource)?, canonical))
    } else if collection == TeamAuthoringCollection::Group {
        let resource = if let Some(response) = http {
            GroupResource::from_http_json(
                body,
                response.etag.as_deref(),
                response.cache_control.as_deref(),
                response.pragma.as_deref(),
            )
        } else {
            GroupResource::from_json(body)
        }
        .map_err(invalid)?;
        resource.validate_for_request(id).map_err(invalid)?;
        let canonical = resource.to_json().map_err(invalid)?;
        Ok((group_view(identity, organization, resource), canonical))
    } else {
        let resource = if let Some(response) = http {
            PolicyResource::from_http_json(
                body,
                response.etag.as_deref(),
                response.cache_control.as_deref(),
                response.pragma.as_deref(),
            )
        } else {
            PolicyResource::from_json(body)
        }
        .map_err(invalid)?;
        resource.validate_for_request(organization, id).map_err(invalid)?;
        let canonical = resource.to_json().map_err(invalid)?;
        Ok((policy_view(identity, organization, resource), canonical))
    }
}

fn load_authoring(
    store: &Store,
    identity: &PersonalRecord,
    organization_id: &str,
    operation_id: &str,
) -> Result<TeamAuthoringRecord, TeamError> {
    let pending = store
        .team_authoring_pending(identity, parse_id(organization_id)?)
        .map_err(storage)?
        .ok_or(TeamFailure::OperationMissing)?;
    if pending.operation != parse_id(operation_id)? {
        return Err(TeamFailure::OperationMismatch.into());
    }
    Ok(pending)
}

fn pending_view(
    identity: &PersonalRecord,
    pending: &TeamAuthoringRecord,
    current_ms: u64,
) -> Result<TeamAuthoringCreateView, TeamError> {
    let collection = TeamAuthoringCollection::from_segment(&pending.collection)?;
    let data = if let Some(kind) = collection.inventory() {
        let request =
            InventoryCreateRequest::from_json(kind, pending.payload.as_bytes()).map_err(invalid)?;
        if request.id != pending.resource {
            return Err(TeamFailure::InvalidTeamResponse.into());
        }
        inventory_data(collection, &request.fields)?.0
    } else if collection == TeamAuthoringCollection::Group {
        let request = GroupCreateRequest::from_json(pending.payload.as_bytes()).map_err(invalid)?;
        if request.id != pending.resource {
            return Err(TeamFailure::InvalidTeamResponse.into());
        }
        TeamAuthoringData::Group(TeamGroupFields {
            name: request.fields.name,
            members: request.fields.members.into_iter().map(|id| id.to_string()).collect(),
        })
    } else {
        let request =
            PolicyCreateRequest::from_json(pending.payload.as_bytes()).map_err(invalid)?;
        if request.id != pending.resource {
            return Err(TeamFailure::InvalidTeamResponse.into());
        }
        TeamAuthoringData::Policy(TeamPolicyFields {
            name: request.fields.name,
            source: request.fields.source,
            enabled: request.fields.enabled,
        })
    };
    let phase = if pending.phase == 2 {
        let response = pending.response.as_ref().ok_or(TeamFailure::InvalidTeamResponse)?;
        let (resource, _) = decode_resource(
            identity,
            pending.organization,
            collection,
            pending.resource,
            response.as_bytes(),
            None,
        )?;
        if request_body(&resource.data, Some(pending.resource))? != pending.payload.as_bytes() {
            return Err(TeamFailure::InvalidTeamResponse.into());
        }
        TeamAuthoringCreatePhase::Confirmed
    } else if pending
        .first_attempt_ms
        .is_some_and(|first| current_ms.saturating_sub(first) >= 86_400_000)
    {
        TeamAuthoringCreatePhase::Expired
    } else if pending.phase == 0 {
        TeamAuthoringCreatePhase::Prepared
    } else {
        TeamAuthoringCreatePhase::Unknown
    };
    Ok(TeamAuthoringCreateView {
        origin: identity.origin.clone(),
        account_id: identity.account_id.to_string(),
        organization_id: pending.organization.to_string(),
        operation_id: pending.operation.to_string(),
        resource_id: pending.resource.to_string(),
        phase,
        data,
    })
}

fn finish_create(
    store: &Store,
    session: &TeamSession,
    sent: &TeamAuthoringRecord,
    response: Option<&[u8]>,
) -> Result<(), TeamError> {
    if !store
        .finish_team_authoring(&session.identity, sent, &session.access, response, now_ms()?)
        .map_err(storage)?
    {
        return Err(TeamFailure::AuthoringUnknown.into());
    }
    Ok(())
}

fn require_authoring_success(
    store: &Store,
    session: &TeamSession,
    response: &Response,
    expected: u16,
) -> Result<(), TeamError> {
    if response.status == expected {
        return Ok(());
    }
    let problem = problem(response)?;
    let error = authoring_problem(&problem)?;
    if problem.status == 401 {
        store.invalidate_personal_session(&session.identity, &session.access).map_err(storage)?;
    }
    Err(error)
}

fn authoring_problem(problem: &ProblemDetails) -> Result<TeamError, TeamError> {
    Ok(match (problem.status, problem.code.as_str(), problem.changed, problem.retryable) {
        (401, "auth.authentication_required", false, false) => {
            PersonalServerError::AuthenticationRequired.into()
        }
        (403, "policy.denied", false, false) => PersonalServerError::PermissionDenied.into(),
        (400 | 413 | 415, "organization.invalid_request", false, false) => {
            TeamFailure::InvalidAuthoringData.into()
        }
        (404, "organization.not_found", false, false) => TeamFailure::TeamNotFound.into(),
        (409, "organization.conflict", false, false)
        | (412, "organization.precondition_failed", false, false)
        | (428, "organization.precondition_required", false, false) => {
            TeamFailure::AuthoringConflict.into()
        }
        (503, "organization.commit_outcome_unknown", true, _) => {
            TeamFailure::AuthoringUnknown.into()
        }
        (503, "organization.storage_unavailable", false, true) | (429, _, false, true) => {
            TeamFailure::ServiceUnavailable.into()
        }
        _ => return Err(TeamFailure::InvalidTeamResponse.into()),
    })
}
