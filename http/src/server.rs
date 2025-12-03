use std::sync::Arc;

use crate::{
    auth::{
        AuthDatabase, admin_handlers, apikey_handlers, login_handler,
        middleware::{
            ApiKeyAuthNew, audit_log_middleware, check_permission,
            read_only_middleware,
        },
        models::{AuthContext, ErrorResponse},
        system_handlers,
    },
    error::Error,
};
use ave_bridge::{
    ApproveInfo, EventInfo, GovsData, PaginatorEvents, RegisterDataSubj,
    RequestData, RequestInfo, SignaturesInfo, SubjectInfo, TransferSubject,
};
use ave_bridge::{Bridge, BridgeSignedEventRequest};
use axum::{
    Extension, Json, Router,
    body::Body,
    extract::{Path, Query},
    http::{StatusCode, header},
    middleware,
    response::{IntoResponse, Response},
    routing::{delete, get, patch, post, put},
};
use bytes::Bytes;
use serde::Deserialize;
use tower::ServiceBuilder;
use utoipa::ToSchema;

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct SubjectQuery {
    active: Option<bool>,
    schema: Option<String>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct GovQuery {
    active: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct EventsQuery {
    quantity: Option<u64>,
    page: Option<u64>,
    reverse: Option<bool>,
}

#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct EventSnQuery {
    sn: u64,
}
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct EventFirstLastQuery {
    quantity: Option<u64>,
    success: Option<bool>,
    reverse: Option<bool>,
}

use crate::doc::ApiDoc;
use utoipa::OpenApi;
use utoipa_rapidoc::RapiDoc;
use axum::http::Method;

/// Send Event Request
///
/// Allows sending an event request for a subject to the Ave node.
/// These requests can be of any type of event (fact, creation, transfer, or end of life).
/// In case of external invocation, the requests can be signed.
///
/// # Parameters
///
/// * `Extension(bridge): Extension<Arc<Bridge>>` - The Bridge extension wrapped in an `Arc`.
/// * `Json(request): Json<BridgeSignedEventRequest>` - The signed event request in JSON format.
///
/// # Returns
///
/// * `Result<Json<RequestData>, Error>` - The response to the event request wrapped in a JSON object, or an error.
#[ utoipa::path(
    post,
    path = "/event-request",
    operation_id = "Send Event Request",
    tag = "Request",
    request_body(content = String, content_type = "application/json", description = "The signed event request"),
    responses(
        (status = 200, description = "Request Created Successfully", body = RequestData,
        example = json!(
            {
                "request_id":"JemKGBkBjpV5Q34zL-KItY9g-RuY4_QJIn0PpIjy0e_E",
                "subject_id":"Jd_vA5Dl1epomG7wyeHiqgKdOIBi28vNgHjRl6hy1N5w"
            }
        )),
        (status = 500, description = "Internal Server Error"),
    )
)]
async fn send_event_request(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Json(request): Json<BridgeSignedEventRequest>,
) -> Result<Json<RequestData>, Error> {
    match bridge.send_event_request(request).await {
        Ok(response) => Ok(Json(RequestData::from(response))),
        Err(e) => Err(Error::Ave(e.to_string())),
    }
}

/// Request State
///
/// Allows obtaining an event request by its identifier.
///
/// # Parameters
///
/// * `Extension(bridge): Extension<Arc<bridge>>` - The bridge extension wrapped in an `Arc`.
/// * `Path(request_id): Path<String>` - The identifier of the event request as a path parameter.
///
/// # Returns
///
/// * `Result<Json<RequestInfo>, Error>` - returns an Ok in a JSON or an error
#[utoipa::path(
    get,
    path = "/event-request/{request-id}",
    operation_id = "Request State",
    tag = "Request",
    params(
        ("request-id" = String, Path, description = "Event Request's unique id"),
    ),
    responses(
        (status = 200, description = "Request Data successfully retrieved", body = RequestInfo,
        example = json!(
            {
                "status": "Finish",
                "version": 0,
                "error": null
            }
        )),
        (status = 500, description = "Internal Server Error"),
    )
)]
async fn get_request_state(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Path(request_id): Path<String>,
) -> Result<Json<RequestInfo>, Error> {
    match bridge.get_request_state(request_id).await {
        Ok(response) => Ok(Json(RequestInfo::from(response))),
        Err(e) => Err(Error::Ave(e.to_string())),
    }
}

/// Approvals
///
/// Allows obtaining the list of requests for approvals received by the node.
///
/// # Parameters
///
/// * `Extension(bridge): Extension<Arc<bridge>>` - The bridge extension wrapped in an `Arc`.
/// * `Path(subject_id): Path<String>` - The identifier of the subject as a path parameter.
///
/// # Returns
///
/// * `Result<Json<ApproveInfo>, Error>` - returns an Ok in a JSON or an error
#[utoipa::path(
    get,
    path = "/approval-request/{subject_id}",
    operation_id = "One Approval Request Data",
    tag = "Approval",
    params(
        ("subject_id" = String, Path, description = "Subjects unique id"),
    ),
    responses(
        (status = 200, description = "Approval Data successfully retrieved", body = ApproveInfo),
        (status = 500, description = "Internal Server Error"),
    )
)]
async fn get_approval(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Path(subject_id): Path<String>,
) -> Result<Json<ApproveInfo>, Error> {
    match bridge.get_approval(subject_id).await {
        Ok(response) => Ok(Json(ApproveInfo::from(response))),
        Err(e) => Err(Error::Ave(e.to_string())),
    }
}

/// Approval
///
/// Allows issuing an affirmative or negative approval for a previously received request.
///
/// # Parameters
///
/// * `Extension(bridge): Extension<Arc<bridge>>` - The bridge extension wrapped in an `Arc`.
/// * `Path(subject_id): Path<String>` -The identifier of the subject as a path parameter.
/// * `Json(response): Json<String>` - The response (approval or rejection) in JSON format
///
/// # Returns
///
/// * `Result<Json<String>, Error>` - The approval request in JSON format or an error if the request fails.
#[ utoipa::path(
    patch,
    path = "/approval-request/{subject_id}",
    operation_id = "Set your Approval for a request",
    tag = "Approval",
    request_body(content = String, content_type = "application/json", description = "Vote of the user for an existing request"),
    params(
        ("subject_id" = String, Path, description = "Subjects unique id"),
    ),
    responses(
        (status = 200, description = "Request successfully voted", body = String,
        example = json!(
            "The approval request for subject Jd_vA5Dl1epomG7wyeHiqgKdOIBi28vNgHjRl6hy1N5w has changed to RespondedAccepted"
        )),
        (status = 500, description = "Internal Server Error"),
    )
)]
async fn patch_approval(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Path(subject_id): Path<String>,
    Json(response): Json<String>,
) -> Result<Json<String>, Error> {
    match bridge.patch_approve(subject_id, response).await {
        Ok(response) => Ok(Json(response)),
        Err(e) => Err(Error::Ave(e.to_string())),
    }
}

/// Authorization
///
/// Given a subject identifier and one or more witnesses, the witnesses authorize the subject to send them copy of the logs
///
/// # Parameters
///
/// * `Extension(bridge): Extension<Arc<bridge>>` - The bridge extension wrapped in an `Arc`.
/// * `Path(subject_id): Path<String>` - The identifier of the subject to be authorized as a path parameter.
/// * `Json(witnesses): Json<Vec<String>>` - The witnesses who will receive the copy of the logs in JSON format
///
/// # Returns
///
/// * `Result<Json<String>, Error>` - The result of the approval as a JSON object or an error if the request fails.
#[  utoipa::path(
    put,
    path = "/auth/{subject_id}",
    operation_id = "Authorization",
    tag = "Auth",
    request_body(content = String, content_type = "application/json", description = "witnesses"),
    params(
        ("subject_id" = String, Path, description = "Subjects unique id"),
    ),
    responses(
        (status = 200, description = "The result of the approval as a JSON object", body = String,
        example = json!(
            "Ok"
        )),
        (status = 500, description = "Internal Server Error"),
    )
)]
async fn put_auth(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Path(subject_id): Path<String>,
    Json(witnesses): Json<Vec<String>>,
) -> Result<Json<String>, Error> {
    match bridge.put_auth_subject(subject_id, witnesses).await {
        Ok(response) => Ok(Json(response)),
        Err(e) => Err(Error::Ave(e.to_string())),
    }
}

/// Authorized Subjects
///
/// Allows obtaining the list of subjects that have been authorized by the node
///
/// # Parameters
///
/// * `Extension(bridge): Extension<Arc<Bridge>>` - The bridge extension wrapped in an `Arc`.
///
/// # Returns
///
/// * `Result<Json<Vec<String>>, Error>` - A list of authorized subjects in JSON format or an error if the request fails.
#[ utoipa::path(
    get,
    path = "/auth",
    operation_id = "Authorized subjects",
    tag = "Auth",
    responses(
        (status = 200, description = "A list of authorized subjects in JSON ", body = [String],
        example = json!(
            [
                "J6blziscpjD0pJXsRh6_ooPtBsvwEZhx-xO4hT7WoKg0"
            ]
        )),
        (status = 500, description = "Internal Server Error", body = String),
    )
)]
async fn get_all_auth_subjects(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
) -> Result<Json<Vec<String>>, Error> {
    match bridge.get_all_auth_subjects().await {
        Ok(response) => Ok(Json(response)),
        Err(e) => Err(Error::Ave(e.to_string())),
    }
}

/// Witnesses Subject
///
/// Obtains a subject's witnesses
///
/// # Parameters
///
/// * `Extension(bridge): Extension<Arc<Bridge>>` - The bridge extension wrapped in an `Arc`.
/// * `Path(subject_id): Path<String>` - The identifier of the subject as a path parameter.
///
/// # Returns
///
/// * `Result<Json<Vec<String>>, Error>` - a list of witness nodes in Json format or an error
#[ utoipa::path(
    get,
    path = "/auth/{subject_id}",
    operation_id = "Witnesses Subject",
    tag = "Auth",
    params(
        ("subject_id" = String, Path, description = "Subjects unique id"),
    ),
    responses(
        (status = 200, description = "A list of witness nodes in Json", body = [String],
        example = json!(
            [
            "EehaWh_CuYvvvjr0dKUKRYMyCFJvDzumcLnUcUbIWwks"
            ]
        )),
        (status = 500, description = "Internal Server Error", body = String,  example = json!(
            "Api error: Can not get witnesses of subjects: Error: The subject has not been authorized"
        )),
    )
)]
async fn get_witnesses_subject(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Path(subject_id): Path<String>,
) -> Result<Json<Vec<String>>, Error> {
    match bridge.get_witnesses_subject(subject_id).await {
        Ok(response) => Ok(Json(response)),
        Err(e) => Err(Error::Ave(e.to_string())),
    }
}

/// Authorized Subjects
///
/// Deletes an authorized subject given its identifier
///
/// # Parameters
///
/// * `Extension(bridge): Extension<Arc<Bridge>>` - bridge extension wrapped in an `Arc`.
/// * `Path(subject_id): Path<String>` - The identifier of the subject as a path parameter.
///
/// # Returns
///
/// * `Result<Json<String>, Error>` - Ok in JSON format or an error if the request fails.
#[ utoipa::path(
    delete,
    path = "/auth/{subject_id}",
    operation_id = "Authorized Subjects",
    tag = "Auth",
    params(
        ("subject_id" = String, Path, description = "Subjects unique id"),
    ),
    responses(
        (status = 200, description = "Ok in JSON format", body = String,
        example = json!(
            "Ok"
        )),
        (status = 500, description = "Internal Server Error"),
    )
)]
async fn delete_auth_subject(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Path(subject_id): Path<String>,
) -> Result<Json<String>, Error> {
    match bridge.delete_auth_subject(subject_id).await {
        Ok(response) => Ok(Json(response)),
        Err(e) => Err(Error::Ave(e.to_string())),
    }
}

/// Update Subject
///
/// Updates an authorized subject given its identifier
///
/// # Parameters
///
/// * `Extension(bridge): Extension<Arc<Bridge>>` - bridge extension wrapped in an `Arc`.
/// * `Path(subject_id): Path<String>` - The identifier of the subject as a path parameter.
///
/// # Returns
///
/// * `Result<Json<String>, Error>` - A message in JSON format or an error if the request fails.
#[ utoipa::path(
    post,
    path = "/update/{subject_id}",
    operation_id = "Update Subject",
    tag = "Update",
    params(
        ("subject_id" = String, Path, description = "Subjects unique id"),
    ),
    responses(
        (status = 200, description = "Subject Data successfully retrieved", body = String,
        example = json!(
            "Update in progress"
        )),
        (status = 500, description = "Internal Server Error", body = String, example = json!(
            "Api error: Can not update subject: Error: The subject has not been authorized"
        )),
    )
)]
async fn update_subject(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Path(subject_id): Path<String>,
) -> Result<Json<String>, Error> {
    match bridge.update_subject(subject_id).await {
        Ok(response) => Ok(Json(response)),
        Err(e) => Err(Error::Ave(e.to_string())),
    }
}

/// Check Transfer
///
/// Check transfer event for subject given its identifier
///
/// # Parameters
///
/// * `Extension(bridge): Extension<Arc<Bridge>>` - bridge extension wrapped in an `Arc`.
/// * `Path(subject_id): Path<String>` - The identifier of the subject as a path parameter.
///
/// # Returns
///
/// * `Result<Json<String>, Error>` - A message in JSON format or an error if the request fails.
#[ utoipa::path(
    post,
    path = "/check-transfer/{subject_id}",
    operation_id = "Check transfer",
    tag = "Transfer",
    params(
        ("subject_id" = String, Path, description =  "Subject unique id"),
    ),
    responses(
        (status = 200, description = "Subject Data successfully retrieved", body = String),
        (status = 500, description = "Internal Server Error"),
    )
)]
async fn check_transfer(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Path(subject_id): Path<String>,
) -> Result<Json<String>, Error> {
    match bridge.check_transfer(subject_id).await {
        Ok(response) => Ok(Json(response)),
        Err(e) => Err(Error::Ave(e.to_string())),
    }
}

/// Update Manual Distribution
///
/// Throw to witnesses the last distribution of a subject
///
/// # Parameters
///
/// * `Extension(bridge): Extension<Arc<Bridge>>` - bridge extension wrapped in an `Arc`.
/// * `Path(subject_id): Path<String>` - The identifier of the subject as a path parameter.
///
/// # Returns
///
/// * `Result<Json<String>, Error>` - A message in JSON format or an error if the request fails.
#[ utoipa::path(
    post,
    path = "/manual-distribution/{subject_id}",
    operation_id = "Update Manual Distribution",
    tag = "Update",
    params(
        ("subject_id" = String, Path, description =  "Subject unique id"),
    ),
    responses(
        (status = 200, description = "Subject Data successfully retrieved", body = String,
        example = json!(
            "Manual update in progress"
        )
        ),
        (status = 500, description = "Internal Server Error"),
    )
)]
async fn manual_distribution(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Path(subject_id): Path<String>,
) -> Result<Json<String>, Error> {
    match bridge.manual_distribution(subject_id).await {
        Ok(response) => Ok(Json(response)),
        Err(e) => Err(Error::Ave(e.to_string())),
    }
}

/// All Governances
///
/// Gets all the governorships to which the node belongs
///
/// # Parameters
///
/// * `Extension(bridge): Extension<Arc<Bridge>>` - bridge extension wrapped in an `Arc`.
/// * `Query(parameters): Query<GovQuery>` - The query parameters for the request.
///
/// # Returns
///
/// * `Result<Json<Vec<GovsData>>, Error>` - A JSON with governance information or an error if the request fails.
#[ utoipa::path(
    get,
    path = "/register-governances",
    operation_id = "All Governances",
    tag = "Governance",
    params(
        ("parameters" = GovQuery, Query, description = "The query parameters for the request"),
    ),
    responses(
        (status = 200, description = "Gets all the governorships to which the node belongs", body = [GovsData],
        example = json!(
            [
                {
                    "governance_id": "JUH9HGYpqMgN3D3Wb43BCPKdb38K1ocDauupuvCN0plM",
                    "active": true
                },
                {
                    "governance_id": "Jl9LVUi8uVBmV9gitxEiiVeSWxEceZoOYT-Kx-t9DTVE",
                    "active": true
                }
            ]
        )),
        (status = 500, description = "Internal Server Error"),
    )
)]
async fn get_all_govs(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Query(parameters): Query<GovQuery>,
) -> Result<Json<Vec<GovsData>>, Error> {
    match bridge.get_all_govs(parameters.active).await {
        Ok(response) => Ok(Json(
            response.iter().map(|x| GovsData::from(x.clone())).collect(),
        )),
        Err(e) => Err(Error::Ave(e.to_string())),
    }
}

/// All Subjects
///
/// Allows obtaining the list of subjects known by the node with pagination.
/// It can also be used to obtain only the governances and all subjects belonging to a specific governance.
///
/// # Parameters
///
/// * `Extension(bridge): Extension<Arc<Bridge>>` - The bridge extension wrapped in an `Arc`.
/// * `Path(governance_id): Path<String>` - The identifier of the governance as a path parameter.
/// * `Query(parameters): Query<SubjectQuery>` - The query parameters for the request.
///
/// # Returns
///
/// * `Result<Json<Vec<RegisterData>>, Error>` - A list of subjects in JSON format or an error if the request fails.
#[  utoipa::path(
    get,
    path = "/register-subjects/{governance_id}",
    operation_id = "All Subjects",
    tag = "Subject",
    params(
        ("subject_id" = String, Path, description =  "Subject unique id"),
        ("parameters" = SubjectQuery, Query, description = "The query parameters for the request"),
    ),
    responses(
        (status = 200, description = "Subjects Data successfully retrieved", body = [RegisterDataSubj],
        example = json!(
            [
                {
                    "subject_id": "JukqvNApVZMlEBI5DrZlZWEUgZs9vdEC6MEmmAQpwmns",
                    "schema": "Test",
                    "active": true
                }
            ]
        )),
        (status = 500, description = "Internal Server Error"),
    )
)]
async fn get_all_subjects(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Path(governance_id): Path<String>,
    Query(parameters): Query<SubjectQuery>,
) -> Result<Json<Vec<RegisterDataSubj>>, Error> {
    match bridge
        .get_all_subjs(governance_id, parameters.active, parameters.schema)
        .await
    {
        Ok(response) => Ok(Json(
            response
                .iter()
                .map(|x| RegisterDataSubj::from(x.clone()))
                .collect(),
        )),
        Err(e) => Err(Error::Ave(e.to_string())),
    }
}

/// Subject Events
///
/// Allows obtaining specific events of a subject by its identifier.
///
/// # Parameters
///
/// * `Extension(bridge): Extension<Arc<Bridge>>` - The bridge extension wrapped in an `Arc`.
/// * `Path(subject_id): Path<String>` - The identifier of the subject as a path parameter.
/// * `Query(parameters): Query<EventsQuery>` - The pagination parameters for the request.
///
/// # Returns
///
/// * `Result<Json<PaginatorEvents>, Error>` - A list of events in JSON format or an error if the request fails.
#[ utoipa::path(
    get,
    path = "/events/{subject_id}",
    operation_id = "Subject Events",
    tag = "Event",
    params(
        ("subject_id" = String, Path, description =  "Subject unique id"),
        ("parameters" = EventsQuery, Query, description = "The query parameters for the request"),
    ),
    responses(
        (status = 200, description = "Allows obtaining specific events of a subject by its identifier.", body = [PaginatorEvents],
        example = json!(
            {
                "events": [
                    {
                        "patch": "[]",
                        "error": null,
                        "event_req": {
                            "Create": {
                                "governance_id": "",
                                "namespace": [],
                                "schema_id": "governance"
                            }
                        },
                        "sn": 0,
                        "subject_id": "Jd_vA5Dl1epomG7wyeHiqgKdOIBi28vNgHjRl6hy1N5w",
                        "succes": true
                    }
                ],
                "paginator": {
                    "next": null,
                    "pages": 1,
                    "prev": null
                }
            }
        )),
        (status = 500, description = "Internal Server Error"),
    )
)]
async fn get_events(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Path(subject_id): Path<String>,
    Query(parameters): Query<EventsQuery>,
) -> Result<Json<PaginatorEvents>, Error> {
    match bridge
        .get_events(
            subject_id,
            parameters.quantity,
            parameters.page,
            parameters.reverse,
        )
        .await
    {
        Ok(response) => Ok(Json(PaginatorEvents::from(response))),
        Err(e) => Err(Error::Ave(e.to_string())),
    }
}

/// Subject State
///
/// Allows obtaining specific state of a subject by its identifier.
///
/// # Parameters
///
/// * `Extension(bridge): Extension<Arc<Bridge>>` - bridge extension wrapped in an `Arc`.
/// * `Path(subject_id): Path<String>` - The identifier of the subject as a path parameter.
///
/// # Returns
///
/// * `Result<Json<SubjectInfo>, Error>` -the state of the subject in JSON format or an error if the request fails.
#[utoipa::path(
    get,
    path = "/state/{subject_id}",
    operation_id = "Subject State",
    tag = "State",
    params(
        ("subject_id" = String, Path, description =  "Subject unique id"),
    ),
    responses(
        (status = 200, description = "Allows obtaining specific state of a subject by its identifier.", body = [SubjectInfo],
        example = json!(
            {
                "active": true,
                "creator": "E2ZY7GjU14U3m-iAqvhQM6kiG62uqLdBMBwv4J-4tzwI",
                "genesis_gov_version": 0,
                "governance_id": "",
                "namespace": "",
                "owner": "E2ZY7GjU14U3m-iAqvhQM6kiG62uqLdBMBwv4J-4tzwI",
                "properties": {
                    "members": [
                        {
                            "id": "E2ZY7GjU14U3m-iAqvhQM6kiG62uqLdBMBwv4J-4tzwI",
                            "name": "Owner"
                        }
                    ],
                    "policies": [
                        {
                            "approve": {
                                "quorum": "MAJORITY"
                            },
                            "evaluate": {
                                "quorum": "MAJORITY"
                            },
                            "id": "governance",
                            "validate": {
                                "quorum": "MAJORITY"
                            }
                        }
                    ],
                    "roles": [
                        {
                            "namespace": "",
                            "role": "WITNESS",
                            "schema": {
                                "ID": "governance"
                            },
                            "who": "MEMBERS"
                        },
                        {
                            "namespace": "",
                            "role": "EVALUATOR",
                            "schema": "ALL",
                            "who": {
                                "NAME": "Owner"
                            }
                        },
                        {
                            "namespace": "",
                            "role": "ISSUER",
                            "schema": {
                                "ID": "governance"
                            },
                            "who": {
                                "NAME": "Owner"
                            }
                        },
                        {
                            "namespace": "",
                            "role": "APPROVER",
                            "schema": {
                                "ID": "governance"
                            },
                            "who": {
                                "NAME": "Owner"
                            }
                        },
                        {
                            "namespace": "",
                            "role": "VALIDATOR",
                            "schema": "ALL",
                            "who": {
                                "NAME": "Owner"
                            }
                        },
                        {
                            "namespace": "",
                            "role": "WITNESS",
                            "schema": "ALL",
                            "who": {
                                "NAME": "Owner"
                            }
                        }
                    ],
                    "schemas": [],
                    "version": 0
                },
                "schema_id": "governance",
                "sn": 0,
                "subject_id": "Jd_vA5Dl1epomG7wyeHiqgKdOIBi28vNgHjRl6hy1N5w"
            }
        )),
        (status = 500, description = "Internal Server Error"),
    )
)]
async fn get_state(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Path(subject_id): Path<String>,
) -> Result<Json<SubjectInfo>, Error> {
    match bridge.get_subject(subject_id).await {
        Ok(response) => Ok(Json(SubjectInfo::from(response))),
        Err(e) => Err(Error::Ave(e.to_string())),
    }
}

/// Subject Signatures
///
/// Allows obtaining signatures of the last event of subject.
///
/// # Parameters
///
/// * `Extension(bridge): Extension<Arc<Bridge>>` - The bridge extension wrapped in an `Arc`.
/// * `Path(subject_id): Path<String>` - The identifier of the subject as a path parameter.
///
/// # Returns
///
/// * `Result<Json<SignaturesInfo>, Error>` - the signature in JSON format or an error if the request fails.
#[ utoipa::path(
    get,
    path = "/signatures/{subject_id}",
    operation_id = "Subject Signatures",
    tag = "Signature",
    params(
        ("subject_id" = String, Path, description =  "Subject unique id"),
    ),
    responses(
        (status = 200, description = "the signature in JSON format", body = SignaturesInfo,
        example = json!(
            {
                "signatures_appr": null,
                "signatures_eval": null,
                "signatures_vali": [
                    {
                        "Signature": {
                            "content_hash": "JLZZ0vv3xwydlcUSIyS2r1J3f8Gz9R03i6ofLTwltheE",
                            "signer": "E2ZY7GjU14U3m-iAqvhQM6kiG62uqLdBMBwv4J-4tzwI",
                            "timestamp": 17346911,
                            "value": "SEySTR3fRiBzlps2Zc3r-Yb8HMiCV5kZJtAu7DYt4xczN8ogW5AZhVjhn6EOj3DmsNyBeFaGIHQrnVnPxA8vkBDA"
                        }
                    }
                ],
                "sn": 0,
                "subject_id": "Jd_vA5Dl1epomG7wyeHiqgKdOIBi28vNgHjRl6hy1N5w"
            }
        )),
        (status = 500, description = "Internal Server Error"),
    )
)]
async fn get_signatures(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Path(subject_id): Path<String>,
) -> Result<Json<SignaturesInfo>, Error> {
    match bridge.get_signatures(subject_id).await {
        Ok(response) => Ok(Json(SignaturesInfo::from(response))),
        Err(e) => Err(Error::Ave(e.to_string())),
    }
}

/// Controller-id
///
/// Gets the controller id of the node
///
/// # Parameters
///
/// * `Extension(bridge): Extension<Arc<Bridge>>` - The bridge extension wrapped in an `Arc`.
///
/// # Returns
///
/// * `Json<String>` - Returns the controller-id of the node in a Json

#[ utoipa::path(
    get,
    path = "/controller-id",
    operation_id = "Controller-id",
    tag = "Other",
    responses(
        (status = 200, description = "Gets the controller id of the node",  body = String,
        example = json!(
            "E2ZY7GjU14U3m-iAqvhQM6kiG62uqLdBMBwv4J-4tzwI"
        )),
        (status = 500, description = "Internal Server Error"),
    )
)]
async fn get_controller_id(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
) -> Json<String> {
    Json(bridge.controller_id())
}

/// Peer-id
///
/// Gets the peer id of the node
///
/// # Parameters
///
/// * `Extension(bridge): Extension<Arc<Bridge>>` - The bridge extension wrapped in an `Arc`.
///
/// # Returns
///
/// * `Json<String>` - Returns the peer id of the node in a Json
#[ utoipa::path(
    get,
    path = "/peer-id",
    operation_id = "Peer-id",
    tag = "Other",
    responses(
        (status = 200, description = "Gets the peer id of the node",  body = String,
        example = json!(
            "12D3KooWQTjWCGZa2f6ZVkwwcbEb4ghtS49AcssJSrATFBNxDpR7"
        )),
        (status = 500, description = "Internal Server Error"),
    )
)]
async fn get_peer_id(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
) -> Json<String> {
    Json(bridge.peer_id())
}

/// Config
///
/// Get the config of the node
///
/// # Parameters
///
/// * `Extension(bridge): Extension<Arc<Bridge>>` - The bridge extension wrapped in an `Arc`.
///
/// # Returns
///
/// * `Json<ConfigHttp>` - Returns the config of the node
#[utoipa::path(
    get,
    path = "/config",
    operation_id = "Config",
    tag = "Other",
    responses(
        (status = 200, description = "Obtain config of node", body = crate::config_types::ConfigHttp),
        (status = 500, description = "Internal Server Error"),
    )
)]
async fn get_config(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
) -> Json<crate::config_types::ConfigHttp> {
    Json(crate::config_types::ConfigHttp::from(bridge.config()))
}

/// keys
///
/// Gets private key of the node
///
/// # Parameters
///
/// * `Extension(bridge): Extension<Arc<Bridge>>` - The bridge extension wrapped in an `Arc`.
///
/// # Returns
///
/// * `Json<String>` - Returns the private key of the node in a Json
#[ utoipa::path(
    get,
    path = "/keys",
    operation_id = "Keys",
    tag = "Other",
    responses(
        (status = 200, description = "Gets the private key of the node",  body = String),
        (status = 500, description = "Internal Server Error"),
    )
)]
async fn get_keys(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
) -> impl IntoResponse {
    let keys_path = bridge.config().keys_path.join("node_private.der");

    // Lee el archivo como bytes
    let keys = match std::fs::read(&keys_path) {
        Ok(k) => k,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("Error reading keys: {}", e),
            )
                .into_response();
        }
    };

    // Devuelve el archivo DER encriptado directamente
    let body = Bytes::from(keys);
    let mut response = Response::new(Body::from(body));
    *response.status_mut() = StatusCode::OK;
    if let Ok(ct) = "application/pkcs8".parse() {
        response.headers_mut().insert(header::CONTENT_TYPE, ct);
    }
    if let Ok(disposition) = "attachment; filename=\"node_private.der\"".parse()
    {
        response
            .headers_mut()
            .insert(header::CONTENT_DISPOSITION, disposition);
    }
    response
}

/// Subject Events with SN
///
/// Allows obtaining specific events of a subject by its identifier and sn.
///
/// # Parameters
///
/// * `Extension(bridge): Extension<Arc<Bridge>>` - The bridge extension wrapped in an `Arc`.
/// * `Path(subject_id): Path<String>` - The identifier of the subject as a path parameter.
/// * `Query(parameters): Query<EventSnQuery>` - The query parameters for the request.
///
/// # Returns
///
/// * `Result<Json<EventInfo>, Error>` - A list of events in JSON format or an error if the request fails.
#[utoipa::path(
    get,
    path = "/event/{subject_id}",
    operation_id = "Subject Events with SN",
    tag = "Event",
    params(
        ("subject_id" = String, Path, description =  "Subject unique id"),
        ("parameters" = EventSnQuery, Query, description = "The query parameters for the request"),
    ),
    responses(
        (status = 200, description = "Allows obtaining specific events of a subject by its identifier and sn", body = [EventInfo],
        example = json!(
            {
                "events": [
                    {
                        "patch": "[]",
                        "error": null,
                        "event_req": {
                            "Create": {
                                "governance_id": "",
                                "namespace": [],
                                "schema_id": "governance"
                            }
                        },
                        "sn": 0,
                        "subject_id": "Jd_vA5Dl1epomG7wyeHiqgKdOIBi28vNgHjRl6hy1N5w",
                        "succes": true
                    }
                ],
                "paginator": {
                    "next": null,
                    "pages": 1,
                    "prev": null
                }
            }
        )),
        (status = 500, description = "Internal Server Error"),
    )
)]
async fn get_event_sn(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Path(subject_id): Path<String>,
    Query(parameters): Query<EventSnQuery>,
) -> Result<Json<EventInfo>, Error> {
    match bridge.get_event_sn(subject_id, parameters.sn).await {
        Ok(response) => Ok(Json(EventInfo::from(response))),
        Err(e) => Err(Error::Ave(e.to_string())),
    }
}

/// First or End Events
///
/// Given a subject id a specific number of events can be obtained, depending on the quantity, reverse and success parameters.
///
/// # Parameters
///
/// * `Extension(bridge): Extension<Arc<Bridge>>` - The bridge extension wrapped in an `Arc`.
/// * `Path(subject_id): Path<String>` - The identifier of the subject as a path parameter.
/// * `Query(parameters): Query<EventFirstLastQuery>` - The query parameters for the request.
///
/// # Returns
///
/// * `Result<Json<EventInfo>, Error>` - A list of events in JSON format or an error if the request fails.
#[utoipa::path(
    get,
    path = "/events-first-last/{subject_id}",
    operation_id = "First or End Events",
    tag = "Event",
    params(
        ("subject_id" = String, Path, description =  "Subject unique id"),
        ("parameters" = EventFirstLastQuery, Query, description = "The query parameters for the request"),
    ),
    responses(
        (status = 200, description = "Allows obtaining specific events of a subject by its identifier and sn", body = [EventInfo],
        example = json!(
            [
            {
                "subject_id": "JukqvNApVZMlEBI5DrZlZWEUgZs9vdEC6MEmmAQpwmns",
                "sn": 0,
                "patch": {
                    "custom_types": {},
                    "name": "",
                    "unit_process": [],
                    "version": 0
                },
                "error": null,
                "event_req": {
                    "Create": {
                        "governance_id": "JecW6BjX8cG-hG4uv2L7nok1G8ABO_4cHhJiDG9qcgF0",
                        "schema_id": "Test",
                        "namespace": []
                    }
                },
                "succes": true
            },
            ]
        )),
        (status = 500, description = "Internal Server Error"),
    )
)]
async fn get_first_or_end_events(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
    Path(subject_id): Path<String>,
    Query(parameters): Query<EventFirstLastQuery>,
) -> Result<Json<Vec<EventInfo>>, Error> {
    match bridge
        .get_first_or_end_events(
            subject_id,
            parameters.quantity,
            parameters.reverse,
            parameters.success,
        )
        .await
    {
        Ok(response) => Ok(Json(
            response
                .iter()
                .map(|x| EventInfo::from(x.clone()))
                .collect(),
        )),
        Err(e) => Err(Error::Ave(e.to_string())),
    }
}

/// Pending Transfers
///
/// # Returns
///
/// * `Result<Json<Vec<TransferSubject>>, Error>` - A list of pending transfers in JSON format or an error if the request fails.
#[utoipa::path(
get,
path = "/pending-transfers",
operation_id = "Pending Transfers",
tag = "Transfer",
responses(
    (status = 200, description = "Transfers pending to accept or reject", body = [TransferSubject],
    example = json!(
        [
            {
                "subject_id": "JWFHt_vWYF9mBGENP3AkAo3OEYMyId7M9n_sUubvBRVI",
                "new_owner": "E8oP5rRi2T5g_Hr7-zVhRbHJ32nvGeBJqrsF7S3uN89Q",
                "actual_owner": "EKHNpIpmzXI8fIzVUTsfUGMRsB_iGRDKZz4RrErcc4AU"
            }
        ]
    )),
    (status = 500, description = "Internal Server Error"),
)
)]
async fn get_pending_transfers(
    _auth: ApiKeyAuthNew,
    Extension(bridge): Extension<Arc<Bridge>>,
) -> Result<Json<Vec<TransferSubject>>, Error> {
    match bridge.get_pending_transfers().await {
        Ok(response) => Ok(Json(
            response
                .iter()
                .map(|x| TransferSubject::from(x.clone()))
                .collect(),
        )),
        Err(e) => Err(Error::Ave(e.to_string())),
    }
}

pub fn build_routes(
    doc: bool,
    bridge: Bridge,
    auth_db: Option<Arc<AuthDatabase>>,
) -> Router {
    let bridge = Arc::new(bridge);

    let main_routes = Router::new()
        .route("/signatures/{subject_id}", get(get_signatures))
        .route("/state/{subject_id}", get(get_state))
        .route("/events/{subject_id}", get(get_events))
        .route("/event/{subject_id}", get(get_event_sn))
        .route(
            "/events-first-last/{subject_id}",
            get(get_first_or_end_events),
        )
        .route("/register-subjects/{governance_id}", get(get_all_subjects))
        .route("/register-governances", get(get_all_govs))
        .route("/update/{subject_id}", post(update_subject))
        .route("/check-transfer/{subject_id}", post(check_transfer))
        .route(
            "/manual-distribution/{subject_id}",
            post(manual_distribution),
        )
        .route("/auth/{subject_id}", delete(delete_auth_subject))
        .route("/auth/{subject_id}", get(get_witnesses_subject))
        .route("/auth", get(get_all_auth_subjects))
        .route("/auth/{subject_id}", put(put_auth))
        .route("/approval-request/{subject_id}", patch(patch_approval))
        .route("/approval-request/{subject_id}", get(get_approval))
        .route("/event-request/{request_id}", get(get_request_state))
        .route("/event-request", post(send_event_request))
        .route("/controller-id", get(get_controller_id))
        .route("/peer-id", get(get_peer_id))
        .route("/config", get(get_config))
        .route("/keys", get(get_keys))
        .route("/pending-transfers", get(get_pending_transfers))
        .layer(ServiceBuilder::new().layer(Extension(bridge)));

    let doc_routes = if doc {
        Some(
            RapiDoc::with_openapi("/doc/api.json", ApiDoc::openapi())
                .path("/doc"),
        )
    } else {
        None
    };

    if let Some(db) = auth_db {
        let protected_routes = Router::new()
            .route(
                "/admin/users",
                get(admin_handlers::list_users)
                    .post(admin_handlers::create_user),
            )
            .route(
                "/admin/users/{user_id}",
                get(admin_handlers::get_user)
                    .put(admin_handlers::update_user)
                    .delete(admin_handlers::delete_user),
            )
            .route(
                "/admin/users/{user_id}/roles/{role_id}",
                post(admin_handlers::assign_role)
                    .delete(admin_handlers::remove_role),
            )
            .route(
                "/admin/users/{user_id}/permissions",
                get(admin_handlers::get_user_permissions)
                    .post(admin_handlers::set_user_permission)
                    .delete(admin_handlers::remove_user_permission),
            )
            .route(
                "/admin/roles",
                get(admin_handlers::list_roles)
                    .post(admin_handlers::create_role),
            )
            .route(
                "/admin/roles/{role_id}",
                get(admin_handlers::get_role)
                    .put(admin_handlers::update_role)
                    .delete(admin_handlers::delete_role),
            )
            .route(
                "/admin/roles/{role_id}/permissions",
                get(admin_handlers::get_role_permissions)
                    .post(admin_handlers::set_role_permission)
                    .delete(admin_handlers::remove_role_permission),
            )
            .route(
                "/admin/api-keys/user/{user_id}",
                post(apikey_handlers::create_api_key_for_user)
                    .get(apikey_handlers::list_user_api_keys_admin),
            )
            .route("/admin/api-keys", get(apikey_handlers::list_all_api_keys))
            .route(
                "/admin/api-keys/{key_id}",
                get(apikey_handlers::get_api_key)
                    .delete(apikey_handlers::revoke_api_key),
            )
            .route(
                "/admin/api-keys/{key_id}/rotate",
                post(apikey_handlers::rotate_api_key),
            )
            .route("/admin/resources", get(system_handlers::list_resources))
            .route("/admin/actions", get(system_handlers::list_actions))
            .route("/admin/audit-logs", get(system_handlers::query_audit_logs))
            .route(
                "/admin/audit-logs/stats",
                get(system_handlers::get_audit_stats),
            )
            .route(
                "/admin/rate-limits/stats",
                get(system_handlers::get_rate_limit_stats),
            )
            .route("/admin/config", get(system_handlers::list_system_config))
            .route(
                "/admin/config/{key}",
                put(system_handlers::update_system_config),
            )
            .route("/me", get(system_handlers::get_me))
            .route("/me/permissions", get(system_handlers::get_my_permissions))
            .route(
                "/me/permissions/detailed",
                get(system_handlers::get_my_permissions_detailed),
            )
            .route(
                "/me/api-keys",
                post(apikey_handlers::create_my_api_key)
                    .get(apikey_handlers::list_my_api_keys),
            )
            .route(
                "/me/api-keys/{key_id}",
                delete(apikey_handlers::revoke_my_api_key),
            )
            .layer(middleware::from_extractor::<ApiKeyAuthNew>());

        // Routes that require authentication & permission checks
        let authed = Router::new()
            .merge(main_routes.clone())
            .merge(protected_routes)
            .layer(Extension(db.clone()))
            .layer(middleware::from_extractor::<ApiKeyAuthNew>())
            .layer(middleware::from_fn(permission_layer))
            .layer(middleware::from_fn(read_only_layer))
            .layer(middleware::from_fn(audit_layer));

        // Login remains unauthenticated but needs DB extension
        let mut app = Router::new()
            .route("/login", post(login_handler::login))
            .layer(Extension(db.clone()))
            .merge(authed);

        if let Some(doc_routes) = doc_routes {
            app = app.merge(doc_routes);
        }

        app
    } else {
        let mut app = main_routes;
        if let Some(doc_routes) = doc_routes {
            app = app.merge(doc_routes);
        }
        app
    }
}

async fn read_only_layer(
    req: axum::http::Request<Body>,
    next: middleware::Next,
) -> Response {
    let db = req.extensions().get::<Arc<AuthDatabase>>().cloned();
    read_only_middleware(db, req, next).await
}

async fn audit_layer(
    req: axum::http::Request<Body>,
    next: middleware::Next,
) -> Response {
    let auth_ctx = req.extensions().get::<Arc<AuthContext>>().cloned();
    let db = req.extensions().get::<Arc<AuthDatabase>>().cloned();

    audit_log_middleware(auth_ctx, db, req, next).await
}

pub(crate) async fn permission_layer(
    req: axum::http::Request<Body>,
    next: middleware::Next,
) -> Response {
    // Skip docs
    if req.uri().path().starts_with("/doc") {
        return next.run(req).await;
    }

    let auth_ctx = match req.extensions().get::<Arc<AuthContext>>().cloned() {
        Some(ctx) => ctx,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse {
                    error: "Authentication required".to_string(),
                }),
            )
                .into_response();
        }
    };

    if let Some((resource, action)) =
        permission_for(req.method(), req.uri().path())
    {
        if let Err(resp) = check_permission(&auth_ctx, resource, action) {
            return resp.into_response();
        }
    }

    next.run(req).await
}

pub(crate) fn permission_for(
    method: &Method,
    path: &str,
) -> Option<(&'static str, &'static str)> {
    // Admin routes already perform explicit checks
    if path.starts_with("/admin/") || path == "/login" {
        return None;
    }

    match (method, path) {
        // Events / requests
        (&Method::POST, "/event-request") => Some(("events", "create")),
        (&Method::GET, p) if p.starts_with("/event-request/") => {
            Some(("events", "read"))
        }
        (&Method::GET, p) if p.starts_with("/events-first-last/") => {
            Some(("events", "list"))
        }
        (&Method::GET, p) if p.starts_with("/events/") => {
            Some(("events", "list"))
        }
        (&Method::GET, p) if p.starts_with("/event/") => {
            Some(("events", "read"))
        }

        // Approvals
        (&Method::GET, p) if p.starts_with("/approval-request/") => {
            Some(("approvals", "read"))
        }
        (&Method::PATCH, p) if p.starts_with("/approval-request/") => {
            Some(("approvals", "execute"))
        }

        // Subjects / auth
        (&Method::GET, "/auth") => Some(("auth", "list")),
        (&Method::GET, p) if p.starts_with("/auth/") => {
            Some(("auth", "read"))
        }
        (&Method::PUT, p) if p.starts_with("/auth/") => {
            Some(("auth", "create"))
        }
        (&Method::DELETE, p) if p.starts_with("/auth/") => {
            Some(("auth", "delete"))
        }

        // Updates / transfers
        (&Method::POST, p) if p.starts_with("/update/") => {
            Some(("subjects", "update"))
        }
        (&Method::POST, p) if p.starts_with("/check-transfer/") => {
            Some(("transfers", "execute"))
        }
        (&Method::POST, p) if p.starts_with("/manual-distribution/") => {
            Some(("transfers", "execute"))
        }

        // Ledger info
        (&Method::GET, p) if p.starts_with("/signatures/") => {
            Some(("signatures", "read"))
        }
        (&Method::GET, p) if p.starts_with("/state/") => {
            Some(("subjects", "read"))
        }
        (&Method::GET, p) if p.starts_with("/register-subjects/") => {
            Some(("subjects", "list"))
        }
        (&Method::GET, "/register-governances") => {
            Some(("governances", "list"))
        }
        (&Method::GET, p) if p.starts_with("/events/") => {
            Some(("events", "list"))
        }

        // System/info
        (&Method::GET, "/controller-id") => Some(("system", "read")),
        (&Method::GET, "/peer-id") => Some(("system", "read")),
        (&Method::GET, "/config") => Some(("system", "read")),
        (&Method::GET, "/keys") => Some(("system", "read")),
        (&Method::GET, "/pending-transfers") => Some(("transfers", "read")),

        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ave_bridge::auth::{
        ApiKeyConfig, AuthConfig, LockoutConfig, RateLimitConfig, SessionConfig,
    };
    use axum::{
        body::Body,
        http::{Request, StatusCode},
        middleware,
        routing::{delete, get, post},
        Router,
    };
    use std::path::PathBuf;
    use tower::ServiceExt;

    async fn ok_handler() -> StatusCode {
        StatusCode::OK
    }

    fn build_db() -> Arc<AuthDatabase> {
        let tmp = tempfile::tempdir().unwrap();
        let config = AuthConfig {
            enable: true,
            database_path: PathBuf::from(tmp.path()),
            superadmin: "admin".to_string(),
            api_key: ApiKeyConfig::default(),
            lockout: LockoutConfig::default(),
            rate_limit: RateLimitConfig::default(),
            session: SessionConfig::default(),
        };
        Arc::new(AuthDatabase::new(config, "AdminPass123!").unwrap())
    }

    fn auth_ctx_for_role(db: &AuthDatabase, role: &str) -> Arc<AuthContext> {
        let role = db.get_role_by_name(role).unwrap();
        let perms = db.get_role_permissions(role.id).unwrap();
        Arc::new(AuthContext {
            user_id: 1,
            username: role.name.clone(),
            is_superadmin: false,
            roles: vec![role.name],
            permissions: perms,
            api_key_id: 1,
            ip_address: None,
        })
    }

    async fn call(
        app: &Router,
        method: Method,
        path: &str,
        ctx: Arc<AuthContext>,
    ) -> StatusCode {
        let mut req = Request::builder()
            .method(method)
            .uri(path)
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(ctx);

        app.clone().oneshot(req).await.unwrap().status()
    }

    fn router() -> Router {
        Router::new()
            .route("/signatures/abc", get(ok_handler))
            .route("/event-request", post(ok_handler))
            .route("/event-request/123", get(ok_handler))
            .route("/manual-distribution/abc", post(ok_handler))
            .route("/auth/abc", delete(ok_handler))
            .layer(middleware::from_fn(permission_layer))
    }

    #[tokio::test]
    async fn read_role_allows_reads_but_not_writes() {
        let db = build_db();
        let ctx = auth_ctx_for_role(&db, "read");
        let app = router();

        let status =
            call(&app, Method::GET, "/signatures/abc", ctx.clone()).await;
        assert_eq!(status, StatusCode::OK);

        let status =
            call(&app, Method::POST, "/event-request", ctx.clone()).await;
        assert_eq!(status, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn write_role_allows_event_request_write() {
        let db = build_db();
        let ctx = auth_ctx_for_role(&db, "write");
        let app = router();

        let status = call(&app, Method::POST, "/event-request", ctx).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn sender_role_only_allows_send_event() {
        let db = build_db();
        let ctx = auth_ctx_for_role(&db, "sender");
        let app = router();

        let ok_status =
            call(&app, Method::POST, "/event-request", ctx.clone()).await;
        assert_eq!(ok_status, StatusCode::OK);

        let forbidden =
            call(&app, Method::GET, "/event-request/123", ctx).await;
        assert_eq!(forbidden, StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn owner_role_allows_full_business_access() {
        let db = build_db();
        let ctx = auth_ctx_for_role(&db, "owner");
        let app = router();

        let status =
            call(&app, Method::DELETE, "/auth/abc", ctx.clone()).await;
        assert_eq!(status, StatusCode::OK);

        let status =
            call(&app, Method::POST, "/manual-distribution/abc", ctx).await;
        assert_eq!(status, StatusCode::OK);
    }
}
