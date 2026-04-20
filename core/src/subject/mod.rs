//! # Subject module.
//!

use std::{
    collections::{BTreeSet, HashSet},
    ops::Deref,
};

use crate::{
    governance::{
        Governance,
        data::GovernanceData,
        model::Quorum,
        role_register::{RoleDataRegister, SearchRole},
    },
    model::{
        common::{
            check_quorum_signers, get_n_events, get_validation_roles_register,
        },
        event::{Ledger, LedgerSeal, Protocols, ValidationMetadata},
    },
    node::register::{Register, RegisterMessage},
    tracker::Tracker,
    validation::{
        request::{ActualProtocols, LastData, ValidationReq},
        response::ValidationRes,
    },
};

use error::SubjectError;

use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Event, PersistentActor,
};
use ave_common::{
    DataToSink, DataToSinkEvent, Namespace, SchemaType, ValueWrapper,
    identity::{
        DigestIdentifier, HashAlgorithm, PublicKey, Signed, hash_borsh,
    },
    request::EventRequest,
    response::{
        SinkEventsPage, SubjectDB, TrackerEventVisibilityDB,
        TrackerEventVisibilityRangeDB, TrackerStoredVisibilityDB,
        TrackerStoredVisibilityRangeDB, TrackerVisibilityModeDB,
        TrackerVisibilityStateDB,
    },
};

use async_trait::async_trait;
use borsh::{BorshDeserialize, BorshSerialize};
use json_patch::{Patch, patch};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sinkdata::{SinkData, SinkDataMessage};
use tracing::{debug, error};

pub mod error;
pub mod sinkdata;

impl Event for Ledger {}

#[derive(
    Clone, Debug, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub struct RequestSubjectData {
    pub subject_id: DigestIdentifier,
    pub governance_id: DigestIdentifier,
    pub namespace: Namespace,
    pub schema_id: SchemaType,
    pub sn: u64,
    pub gov_version: u64,
    pub signer: PublicKey,
}

pub struct VerifyNewLedgerEvent<'a> {
    pub new_ledger_event: &'a Ledger,
    pub subject_metadata: Metadata,
    pub actual_ledger_event_hash: DigestIdentifier,
    pub last_data: LastData,
    pub hash: &'a HashAlgorithm,
    pub full_view: bool,
    pub is_service: bool,
}

/// Subject metadata.
#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    Hash,
)]
pub struct Metadata {
    pub name: Option<String>,
    pub description: Option<String>,
    /// The identifier of the subject of the event.
    pub subject_id: DigestIdentifier,
    /// The identifier of the governance contract.
    pub governance_id: DigestIdentifier,
    pub genesis_gov_version: u64,
    pub prev_ledger_event_hash: DigestIdentifier,
    /// The identifier of the schema_id used to validate the event.
    pub schema_id: SchemaType,
    /// The namespace of the subject.
    pub namespace: Namespace,
    /// The current sequence number of the subject.
    pub sn: u64,
    /// The identifier of the public key of the creator owner.
    pub creator: PublicKey,
    /// The identifier of the public key of the subject owner.
    pub owner: PublicKey,
    pub new_owner: Option<PublicKey>,
    /// Indicates whether the subject is active or not.
    pub active: bool,
    /// The current status of the subject.
    pub properties: ValueWrapper,
}

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    BorshSerialize,
    BorshDeserialize,
    PartialEq,
    Eq,
    Hash,
)]
pub struct MetadataWithoutProperties {
    pub name: Option<String>,
    pub description: Option<String>,
    pub subject_id: DigestIdentifier,
    pub governance_id: DigestIdentifier,
    pub genesis_gov_version: u64,
    pub prev_ledger_event_hash: DigestIdentifier,
    pub schema_id: SchemaType,
    pub namespace: Namespace,
    pub sn: u64,
    pub creator: PublicKey,
    pub owner: PublicKey,
    pub new_owner: Option<PublicKey>,
    pub active: bool,
}

impl From<Metadata> for MetadataWithoutProperties {
    fn from(value: Metadata) -> Self {
        Self {
            name: value.name,
            description: value.description,
            subject_id: value.subject_id,
            governance_id: value.governance_id,
            genesis_gov_version: value.genesis_gov_version,
            prev_ledger_event_hash: value.prev_ledger_event_hash,
            schema_id: value.schema_id,
            namespace: value.namespace,
            sn: value.sn,
            creator: value.creator,
            owner: value.owner,
            new_owner: value.new_owner,
            active: value.active,
        }
    }
}

impl From<Governance> for Metadata {
    fn from(value: Governance) -> Self {
        Self {
            name: value.subject_metadata.name,
            description: value.subject_metadata.description,
            subject_id: value.subject_metadata.subject_id.clone(),
            governance_id: value.subject_metadata.subject_id,
            genesis_gov_version: 0,
            prev_ledger_event_hash: value
                .subject_metadata
                .prev_ledger_event_hash,
            schema_id: value.subject_metadata.schema_id,
            namespace: Namespace::new(),
            sn: value.subject_metadata.sn,
            creator: value.subject_metadata.creator,
            owner: value.subject_metadata.owner,
            new_owner: value.subject_metadata.new_owner,
            active: value.subject_metadata.active,
            properties: value.properties.to_value_wrapper(),
        }
    }
}

impl From<Tracker> for Metadata {
    fn from(value: Tracker) -> Self {
        Self {
            name: value.subject_metadata.name,
            description: value.subject_metadata.description,
            subject_id: value.subject_metadata.subject_id,
            governance_id: value.governance_id,
            genesis_gov_version: value.genesis_gov_version,
            prev_ledger_event_hash: value
                .subject_metadata
                .prev_ledger_event_hash,
            schema_id: value.subject_metadata.schema_id,
            namespace: value.namespace,
            sn: value.subject_metadata.sn,
            creator: value.subject_metadata.creator,
            owner: value.subject_metadata.owner,
            new_owner: value.subject_metadata.new_owner,
            active: value.subject_metadata.active,
            properties: value.properties,
        }
    }
}

impl From<Governance> for SubjectDB {
    fn from(value: Governance) -> Self {
        Self {
            name: value.subject_metadata.name,
            description: value.subject_metadata.description,
            subject_id: value.subject_metadata.subject_id.to_string(),
            governance_id: value.subject_metadata.subject_id.to_string(),
            genesis_gov_version: 0,
            prev_ledger_event_hash: if value
                .subject_metadata
                .prev_ledger_event_hash
                .is_empty()
            {
                None
            } else {
                Some(value.subject_metadata.prev_ledger_event_hash.to_string())
            },
            schema_id: value.subject_metadata.schema_id.to_string(),
            namespace: Namespace::new().to_string(),
            sn: value.subject_metadata.sn,
            creator: value.subject_metadata.creator.to_string(),
            owner: value.subject_metadata.owner.to_string(),
            new_owner: value
                .subject_metadata
                .new_owner
                .map(|owner| owner.to_string()),
            active: value.subject_metadata.active,
            tracker_visibility: None,
            properties: value.properties.to_value_wrapper().0,
        }
    }
}

impl From<crate::model::common::TrackerVisibilityMode>
    for TrackerVisibilityModeDB
{
    fn from(value: crate::model::common::TrackerVisibilityMode) -> Self {
        match value {
            crate::model::common::TrackerVisibilityMode::Full => Self::Full,
            crate::model::common::TrackerVisibilityMode::Opaque => Self::Opaque,
        }
    }
}

impl From<crate::model::common::TrackerStoredVisibility>
    for TrackerStoredVisibilityDB
{
    fn from(value: crate::model::common::TrackerStoredVisibility) -> Self {
        match value {
            crate::model::common::TrackerStoredVisibility::Full => Self::Full,
            crate::model::common::TrackerStoredVisibility::Only(viewpoints) => {
                Self::Only {
                    viewpoints: viewpoints.into_iter().collect(),
                }
            }
            crate::model::common::TrackerStoredVisibility::None => Self::None,
        }
    }
}

impl From<crate::model::common::TrackerStoredVisibilityRange>
    for TrackerStoredVisibilityRangeDB
{
    fn from(value: crate::model::common::TrackerStoredVisibilityRange) -> Self {
        Self {
            from_sn: value.from_sn,
            to_sn: value.to_sn,
            visibility: value.visibility.into(),
        }
    }
}

impl From<crate::model::common::TrackerEventVisibility>
    for TrackerEventVisibilityDB
{
    fn from(value: crate::model::common::TrackerEventVisibility) -> Self {
        match value {
            crate::model::common::TrackerEventVisibility::NonFact => {
                Self::NonFact
            }
            crate::model::common::TrackerEventVisibility::Fact(viewpoints) => {
                Self::Fact {
                    viewpoints: viewpoints.into_iter().collect(),
                }
            }
        }
    }
}

impl From<crate::model::common::TrackerEventVisibilityRange>
    for TrackerEventVisibilityRangeDB
{
    fn from(value: crate::model::common::TrackerEventVisibilityRange) -> Self {
        Self {
            from_sn: value.from_sn,
            to_sn: value.to_sn,
            visibility: value.visibility.into(),
        }
    }
}

impl From<crate::model::common::TrackerVisibilityState>
    for TrackerVisibilityStateDB
{
    fn from(value: crate::model::common::TrackerVisibilityState) -> Self {
        Self {
            mode: value.mode.into(),
            stored_ranges: value
                .stored_ranges
                .into_iter()
                .map(Into::into)
                .collect(),
            event_ranges: value
                .event_ranges
                .into_iter()
                .map(Into::into)
                .collect(),
        }
    }
}

#[derive(Clone)]
pub struct DataForSink {
    pub gov_id: Option<String>,
    pub subject_id: String,
    pub sn: u64,
    pub owner: String,
    pub namespace: String,
    pub schema_id: SchemaType,
    pub issuer: String,
    pub event_request_timestamp: u64,
    pub event_ledger_timestamp: u64,
    pub gov_version: u64,
    pub event_data_ledger: EventLedgerDataForSink,
}

#[derive(Clone, Debug)]
struct SinkReplayState {
    governance_id: Option<String>,
    subject_id: String,
    owner: String,
    new_owner: Option<String>,
    namespace: String,
    schema_id: SchemaType,
}

impl SinkReplayState {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            governance_id: if metadata.schema_id.is_gov() {
                None
            } else {
                Some(metadata.governance_id.to_string())
            },
            subject_id: metadata.subject_id.to_string(),
            owner: metadata.owner.to_string(),
            new_owner: metadata.new_owner.as_ref().map(ToString::to_string),
            namespace: metadata.namespace.to_string(),
            schema_id: metadata.schema_id.clone(),
        }
    }

    fn data_for_sink(
        &self,
        event: &Ledger,
        event_data_ledger: EventLedgerDataForSink,
    ) -> DataForSink {
        let (issuer, event_request_timestamp) =
            event.get_issuer_event_request_timestamp();

        DataForSink {
            gov_id: self.governance_id.clone(),
            subject_id: self.subject_id.clone(),
            sn: event.sn,
            owner: self.owner.clone(),
            namespace: self.namespace.clone(),
            schema_id: self.schema_id.clone(),
            issuer,
            event_request_timestamp,
            event_ledger_timestamp: event
                .ledger_seal_signature
                .timestamp
                .as_nanos(),
            gov_version: event.gov_version,
            event_data_ledger,
        }
    }

    fn build_replay_data_to_sink(
        &self,
        ledger: &Ledger,
        public_key: &str,
        sink_timestamp: u64,
    ) -> Result<DataToSink, ActorError> {
        let replay_parts = SinkReplayEventParts::from_ledger(ledger)?;
        let data = self.data_for_sink(ledger, replay_parts.event_data_ledger);

        Ok(build_data_to_sink(
            data,
            replay_parts.event_request,
            public_key,
            sink_timestamp,
        ))
    }

    fn apply_success(
        &mut self,
        protocols: &Protocols,
    ) -> Result<(), ActorError> {
        match protocols {
            Protocols::Create { .. }
            | Protocols::TrackerFactFull { .. }
            | Protocols::TrackerFactOpaque { .. }
            | Protocols::GovFact { .. }
            | Protocols::EOL { .. } => Ok(()),
            Protocols::Transfer { event_request, .. } => {
                let EventRequest::Transfer(transfer_request) =
                    event_request.content()
                else {
                    error!(
                        subject_id = %self.subject_id,
                        actual_request = ?event_request.content(),
                        "Unexpected event request type while replaying transfer event"
                    );
                    return Err(ActorError::Functional {
                        description:
                            "Replay transfer event must carry a Transfer request"
                                .to_owned(),
                    });
                };
                self.new_owner = Some(transfer_request.new_owner.to_string());
                Ok(())
            }
            Protocols::TrackerConfirm { .. } | Protocols::GovConfirm { .. } => {
                let Some(new_owner) = self.new_owner.take() else {
                    error!(
                        subject_id = %self.subject_id,
                        "Replay confirm event without pending new owner"
                    );
                    return Err(ActorError::Functional {
                        description:
                            "Replay confirm event without pending new owner"
                                .to_owned(),
                    });
                };
                self.owner = new_owner;
                Ok(())
            }
            Protocols::Reject { .. } => {
                self.new_owner = None;
                Ok(())
            }
        }
    }
}

struct SinkReplayEventParts {
    event_request: Option<EventRequest>,
    event_data_ledger: EventLedgerDataForSink,
}

impl SinkReplayEventParts {
    fn from_ledger(ledger: &Ledger) -> Result<Self, ActorError> {
        match &ledger.protocols {
            Protocols::Create { event_request, .. } => {
                let metadata = ledger.get_create_metadata().map_err(|e| {
                    ActorError::Functional {
                        description: e.to_string(),
                    }
                })?;

                Ok(Self {
                    event_request: Some(event_request.content().clone()),
                    event_data_ledger: EventLedgerDataForSink::Create {
                        state: metadata.properties.0,
                    },
                })
            }
            Protocols::TrackerFactFull { event_request, .. }
            | Protocols::GovFact { event_request, .. }
            | Protocols::Transfer { event_request, .. }
            | Protocols::TrackerConfirm { event_request, .. }
            | Protocols::GovConfirm { event_request, .. }
            | Protocols::Reject { event_request, .. }
            | Protocols::EOL { event_request, .. } => Ok(Self {
                event_request: Some(event_request.content().clone()),
                event_data_ledger: EventLedgerDataForSink::build(
                    &ledger.protocols,
                    &Value::Null,
                ),
            }),
            Protocols::TrackerFactOpaque { .. } => Ok(Self {
                event_request: None,
                event_data_ledger: EventLedgerDataForSink::build(
                    &ledger.protocols,
                    &Value::Null,
                ),
            }),
        }
    }
}

#[derive(Clone)]
pub enum EventLedgerDataForSink {
    Create {
        state: Value,
    },
    FactFull {
        patch: Option<Value>,
        success: bool,
        error: Option<String>,
    },
    FactOpaque {
        viewpoints: Vec<String>,
        success: bool,
    },
    Transfer {
        success: bool,
        error: Option<String>,
    },
    Confirm {
        patch: Option<Value>,
        success: bool,
        error: Option<String>,
    },
    Reject,
    Eol,
}

impl EventLedgerDataForSink {
    pub fn build(protocols: &Protocols, state: &Value) -> Self {
        match protocols {
            Protocols::Create { .. } => Self::Create {
                state: state.clone(),
            },
            Protocols::TrackerFactFull { evaluation, .. }
            | Protocols::GovFact { evaluation, .. } => {
                let success = protocols.is_success();
                let (patch, error) = match &evaluation.response {
                    crate::model::event::EvaluationResponse::Ok {
                        result,
                        ..
                    } if success => (Some(result.patch.0.clone()), None),
                    crate::model::event::EvaluationResponse::Ok { .. } => {
                        (None, None)
                    }
                    crate::model::event::EvaluationResponse::Error {
                        result,
                        ..
                    } => (None, Some(result.to_string())),
                };

                Self::FactFull {
                    patch,
                    success,
                    error,
                }
            }
            Protocols::TrackerFactOpaque { evaluation, .. } => {
                Self::FactOpaque {
                    viewpoints: evaluation.viewpoints.iter().cloned().collect(),
                    success: protocols.is_success(),
                }
            }
            Protocols::Transfer { evaluation, .. } => {
                let success = protocols.is_success();
                let error = match &evaluation.response {
                    crate::model::event::EvaluationResponse::Error {
                        result,
                        ..
                    } => Some(result.to_string()),
                    crate::model::event::EvaluationResponse::Ok { .. } => None,
                };
                Self::Transfer { success, error }
            }
            Protocols::Reject { .. } => Self::Reject,
            Protocols::EOL { .. } => Self::Eol,
            Protocols::TrackerConfirm { .. } => Self::Confirm {
                patch: None,
                success: true,
                error: None,
            },
            Protocols::GovConfirm { evaluation, .. } => {
                let success = protocols.is_success();
                let (patch, error) = match &evaluation.response {
                    crate::model::event::EvaluationResponse::Ok {
                        result,
                        ..
                    } if success => (Some(result.patch.0.clone()), None),
                    crate::model::event::EvaluationResponse::Ok { .. } => {
                        (None, None)
                    }
                    crate::model::event::EvaluationResponse::Error {
                        result,
                        ..
                    } => (None, Some(result.to_string())),
                };

                Self::Confirm {
                    patch,
                    success,
                    error,
                }
            }
        }
    }
}

fn data_to_sink_event(
    data: DataForSink,
    event: Option<EventRequest>,
) -> DataToSinkEvent {
    match (event, data.event_data_ledger) {
        (
            Some(EventRequest::Create(..)),
            EventLedgerDataForSink::Create { state },
        ) => DataToSinkEvent::Create {
            governance_id: data.gov_id,
            subject_id: data.subject_id,
            owner: data.owner,
            schema_id: data.schema_id,
            namespace: data.namespace.to_string(),
            sn: data.sn,
            gov_version: data.gov_version,
            state,
        },
        (
            Some(EventRequest::Fact(fact_request)),
            EventLedgerDataForSink::FactFull {
                patch,
                success,
                error,
            },
        ) => DataToSinkEvent::FactFull {
            governance_id: data.gov_id,
            subject_id: data.subject_id,
            issuer: data.issuer.to_string(),
            viewpoints: fact_request.viewpoints.iter().cloned().collect(),
            owner: data.owner,
            payload: success.then_some(fact_request.payload.0),
            schema_id: data.schema_id,
            sn: data.sn,
            gov_version: data.gov_version,
            patch,
            success,
            error,
        },
        (
            None,
            EventLedgerDataForSink::FactOpaque {
                viewpoints,
                success,
            },
        ) => DataToSinkEvent::FactOpaque {
            governance_id: data.gov_id,
            subject_id: data.subject_id,
            viewpoints,
            owner: data.owner,
            schema_id: data.schema_id,
            sn: data.sn,
            gov_version: data.gov_version,
            success,
        },
        (
            Some(EventRequest::Transfer(transfer_request)),
            EventLedgerDataForSink::Transfer { success, error },
        ) => DataToSinkEvent::Transfer {
            governance_id: data.gov_id,
            subject_id: data.subject_id,
            owner: data.owner,
            new_owner: transfer_request.new_owner.to_string(),
            schema_id: data.schema_id,
            sn: data.sn,
            gov_version: data.gov_version,
            success,
            error,
        },
        (
            Some(EventRequest::Confirm(confirm_request)),
            EventLedgerDataForSink::Confirm {
                patch,
                success,
                error,
            },
        ) => DataToSinkEvent::Confirm {
            governance_id: data.gov_id,
            subject_id: data.subject_id,
            schema_id: data.schema_id,
            sn: data.sn,
            gov_version: data.gov_version,
            patch,
            success,
            error,
            name_old_owner: confirm_request.name_old_owner,
        },
        (Some(EventRequest::Reject(..)), EventLedgerDataForSink::Reject) => {
            DataToSinkEvent::Reject {
                governance_id: data.gov_id,
                subject_id: data.subject_id,
                schema_id: data.schema_id,
                sn: data.sn,
                gov_version: data.gov_version,
            }
        }
        (Some(EventRequest::EOL(..)), EventLedgerDataForSink::Eol) => {
            DataToSinkEvent::Eol {
                governance_id: data.gov_id,
                subject_id: data.subject_id,
                schema_id: data.schema_id,
                sn: data.sn,
                gov_version: data.gov_version,
            }
        }
        _ => {
            unreachable!(
                "EventLedgerDataForSink is created according to protocols and protocols according to EventRequest"
            )
        }
    }
}

pub fn build_data_to_sink(
    data: DataForSink,
    event: Option<EventRequest>,
    public_key: &str,
    sink_timestamp: u64,
) -> DataToSink {
    DataToSink {
        payload: data_to_sink_event(data.clone(), event),
        public_key: public_key.to_owned(),
        event_request_timestamp: data.event_request_timestamp,
        event_ledger_timestamp: data.event_ledger_timestamp,
        sink_timestamp,
    }
}

pub fn replay_sink_events(
    ledgers: &[Ledger],
    public_key: &str,
    from_sn: u64,
    to_sn: Option<u64>,
    limit: u64,
    sink_timestamp: u64,
) -> Result<SinkEventsPage, ActorError> {
    if limit == 0 {
        return Err(ActorError::Functional {
            description: "Replay limit must be greater than zero".to_owned(),
        });
    }

    let mut replay_state: Option<SinkReplayState> = None;
    let mut events = Vec::new();
    let mut next_sn = None;
    let upper_bound = to_sn.unwrap_or(u64::MAX);

    for ledger in ledgers {
        if replay_state.is_none() {
            let metadata = ledger.get_create_metadata().map_err(|e| {
                ActorError::Functional {
                    description: e.to_string(),
                }
            })?;
            replay_state = Some(SinkReplayState::from_metadata(&metadata));
        }

        let Some(state) = replay_state.as_mut() else {
            unreachable!("replay state is initialized above");
        };

        let sn = ledger.sn;
        if sn > upper_bound {
            break;
        }

        let is_success = ledger.protocols.is_success();
        if sn >= from_sn {
            if events.len() as u64 >= limit {
                next_sn = Some(sn);
                break;
            }

            events.push(state.build_replay_data_to_sink(
                ledger,
                public_key,
                sink_timestamp,
            )?);
        }

        if is_success {
            state.apply_success(&ledger.protocols)?;
        }
    }

    Ok(SinkEventsPage {
        from_sn,
        to_sn,
        limit,
        next_sn,
        has_more: next_sn.is_some(),
        events,
    })
}

#[derive(
    Default,
    Debug,
    Serialize,
    Deserialize,
    Clone,
    BorshSerialize,
    BorshDeserialize,
)]
pub struct SubjectMetadata {
    /// The name of the subject.
    pub name: Option<String>,
    /// The description of the subject.
    pub description: Option<String>,
    /// The identifier of the subject.
    pub subject_id: DigestIdentifier,

    pub schema_id: SchemaType,
    /// The identifier of the public key of the subject owner.
    pub owner: PublicKey,
    /// The identifier of the public key of the new subject owner.
    pub new_owner: Option<PublicKey>,

    pub prev_ledger_event_hash: DigestIdentifier,
    /// The identifier of the public key of the subject creator.
    pub creator: PublicKey,
    /// Indicates whether the subject is active or not.
    pub active: bool,
    /// The current sequence number of the subject.
    pub sn: u64,
}

impl SubjectMetadata {
    pub fn new(data: &Metadata) -> Self {
        Self {
            name: data.name.clone(),
            description: data.description.clone(),
            subject_id: data.subject_id.clone(),
            owner: data.creator.clone(),
            schema_id: data.schema_id.clone(),
            new_owner: data.new_owner.clone(),
            prev_ledger_event_hash: data.prev_ledger_event_hash.clone(),
            creator: data.creator.clone(),
            active: data.active,
            sn: data.sn,
        }
    }
}

#[async_trait]
pub trait Subject
where
    <Self as Actor>::Event: BorshSerialize + BorshDeserialize,
    Self: PersistentActor,
{
    fn verify_new_ledger_event_args<'a>(
        new_ledger_event: &'a Ledger,
        subject_metadata: Metadata,
        actual_ledger_event_hash: DigestIdentifier,
        last_data: LastData,
        hash: &'a HashAlgorithm,
        full_view: bool,
        is_service: bool,
    ) -> VerifyNewLedgerEvent<'a> {
        VerifyNewLedgerEvent {
            new_ledger_event,
            subject_metadata,
            actual_ledger_event_hash,
            last_data,
            hash,
            full_view,
            is_service,
        }
    }

    fn hash_viewpoints(
        hash: &HashAlgorithm,
        viewpoints: &BTreeSet<String>,
    ) -> Result<DigestIdentifier, SubjectError> {
        hash_borsh(&*hash.hasher(), viewpoints).map_err(|e| {
            SubjectError::HashCreationFailed {
                details: e.to_string(),
            }
        })
    }

    fn request_viewpoints(event_request: &EventRequest) -> BTreeSet<String> {
        match event_request {
            EventRequest::Fact(fact_request) => fact_request.viewpoints.clone(),
            _ => BTreeSet::new(),
        }
    }

    fn apply_patch_verify(
        subject_properties: &mut ValueWrapper,
        json_patch: ValueWrapper,
    ) -> Result<(), SubjectError> {
        let json_patch = serde_json::from_value::<Patch>(json_patch.0)
            .map_err(|e| SubjectError::PatchConversionFailed {
                details: e.to_string(),
            })?;

        patch(&mut subject_properties.0, &json_patch).map_err(|e| {
            SubjectError::PatchApplicationFailed {
                details: e.to_string(),
            }
        })?;

        Ok(())
    }

    async fn verify_new_ledger_event(
        ctx: &mut ActorContext<Self>,
        args: VerifyNewLedgerEvent<'_>,
    ) -> Result<bool, SubjectError> {
        let VerifyNewLedgerEvent {
            new_ledger_event,
            subject_metadata,
            actual_ledger_event_hash,
            last_data,
            hash,
            full_view,
            is_service,
        } = args;

        if !subject_metadata.active {
            return Err(SubjectError::SubjectInactive);
        }

        if new_ledger_event.sn != subject_metadata.sn + 1 {
            return Err(SubjectError::InvalidSequenceNumber {
                expected: subject_metadata.sn + 1,
                actual: new_ledger_event.sn,
            });
        }

        let protocols_hash = new_ledger_event
            .protocols
            .hash_for_ledger(hash)
            .map_err(|e| SubjectError::HashCreationFailed {
            details: e.to_string(),
        })?;

        let ledger_seal = LedgerSeal {
            gov_version: new_ledger_event.gov_version,
            sn: new_ledger_event.sn,
            prev_ledger_event_hash: new_ledger_event
                .prev_ledger_event_hash
                .clone(),
            protocols_hash,
        };

        if new_ledger_event
            .ledger_seal_signature
            .verify(&ledger_seal)
            .is_err()
        {
            return Err(SubjectError::SignatureVerificationFailed {
                context: "new ledger event signature verification failed"
                    .to_string(),
            });
        }

        let signer = if let Some(new_owner) = &subject_metadata.new_owner {
            new_owner.clone()
        } else {
            subject_metadata.owner.clone()
        };

        if new_ledger_event.ledger_seal_signature.signer != signer {
            return Err(SubjectError::IncorrectSigner {
                expected: signer.to_string(),
                actual: new_ledger_event
                    .ledger_seal_signature
                    .signer
                    .to_string(),
            });
        }

        if actual_ledger_event_hash != new_ledger_event.prev_ledger_event_hash {
            return Err(SubjectError::PreviousHashMismatch);
        }

        let mut modified_subject_metadata = subject_metadata.clone();
        modified_subject_metadata.sn += 1;

        let (
            validation,
            new_actual_protocols,
            event_request,
            opaque_event_request_hash,
            opaque_viewpoints_hash,
        ) = match (
            &new_ledger_event.protocols,
            subject_metadata.schema_id.is_gov(),
        ) {
            (
                Protocols::TrackerFactFull {
                    event_request,
                    evaluation,
                    validation,
                },
                false,
            ) => {
                if let EventRequest::Fact(..) = event_request.content() {
                } else {
                    return Err(SubjectError::EventProtocolMismatch);
                }

                if modified_subject_metadata.new_owner.is_some() {
                    return Err(SubjectError::UnexpectedFactEvent);
                }

                if full_view
                    && let Some(eval) = evaluation.evaluator_response_ok()
                {
                    Self::apply_patch_verify(
                        &mut modified_subject_metadata.properties,
                        eval.patch,
                    )?;
                }
                (
                    validation,
                    ActualProtocols::Eval {
                        eval_data: evaluation.clone(),
                    },
                    Some(event_request),
                    None,
                    None,
                )
            }
            (
                Protocols::TrackerFactOpaque {
                    data,
                    event_request_hash,
                    evaluation,
                    validation,
                    ..
                },
                false,
            ) => {
                if is_service {
                    return Err(SubjectError::ServiceCannotAcceptTrackerOpaque);
                }

                if data.subject_id != subject_metadata.subject_id {
                    return Err(SubjectError::SubjectIdMismatch {
                        expected: subject_metadata.subject_id.to_string(),
                        actual: data.subject_id.to_string(),
                    });
                }

                (
                    validation,
                    ActualProtocols::None,
                    None,
                    Some(event_request_hash.clone()),
                    Some(Self::hash_viewpoints(hash, &evaluation.viewpoints)?),
                )
            }
            (
                Protocols::GovFact {
                    event_request,
                    evaluation,
                    approval,
                    validation,
                },
                true,
            ) => {
                if let EventRequest::Fact(fact_request) =
                    event_request.content()
                {
                    if !fact_request.viewpoints.is_empty() {
                        return Err(
                            SubjectError::GovernanceFactViewpointsNotAllowed,
                        );
                    }
                } else {
                    return Err(SubjectError::EventProtocolMismatch);
                }

                if modified_subject_metadata.new_owner.is_some() {
                    return Err(SubjectError::UnexpectedFactEvent);
                }

                let actual_protocols =
                    if let Some(eval) = evaluation.evaluator_response_ok() {
                        if let Some(appr) = approval {
                            if appr.approved {
                                Self::apply_patch_verify(
                                    &mut modified_subject_metadata.properties,
                                    eval.patch,
                                )?;
                            }

                            ActualProtocols::EvalApprove {
                                eval_data: evaluation.clone(),
                                approval_data: appr.clone(),
                            }
                        } else {
                            return Err(
                                SubjectError::MissingApprovalAfterEvaluation,
                            );
                        }
                    } else if approval.is_some() {
                        return Err(
                        SubjectError::UnexpectedApprovalAfterFailedEvaluation,
                    );
                    } else {
                        ActualProtocols::Eval {
                            eval_data: evaluation.clone(),
                        }
                    };

                (
                    validation,
                    actual_protocols,
                    Some(event_request),
                    None,
                    None,
                )
            }
            (
                Protocols::Transfer {
                    event_request,
                    evaluation,
                    validation,
                },
                ..,
            ) => {
                let EventRequest::Transfer(transfer) = event_request.content()
                else {
                    return Err(SubjectError::EventProtocolMismatch);
                };

                if modified_subject_metadata.new_owner.is_some() {
                    return Err(SubjectError::UnexpectedTransferEvent);
                }

                if let Some(eval) = evaluation.evaluator_response_ok() {
                    Self::apply_patch_verify(
                        &mut modified_subject_metadata.properties,
                        eval.patch,
                    )?;
                    modified_subject_metadata.new_owner =
                        Some(transfer.new_owner.clone());
                }

                (
                    validation,
                    ActualProtocols::Eval {
                        eval_data: evaluation.clone(),
                    },
                    Some(event_request),
                    None,
                    None,
                )
            }
            (
                Protocols::TrackerConfirm {
                    event_request,
                    validation,
                },
                false,
            ) => {
                if let EventRequest::Confirm(..) = event_request.content() {
                } else {
                    return Err(SubjectError::EventProtocolMismatch);
                }

                if let Some(new_owner) =
                    &modified_subject_metadata.new_owner.take()
                {
                    modified_subject_metadata.owner = new_owner.clone();
                } else {
                    return Err(SubjectError::ConfirmWithoutNewOwner);
                }

                (
                    validation,
                    ActualProtocols::None,
                    Some(event_request),
                    None,
                    None,
                )
            }
            (
                Protocols::GovConfirm {
                    event_request,
                    evaluation,
                    validation,
                },
                true,
            ) => {
                if let EventRequest::Confirm(..) = event_request.content() {
                } else {
                    return Err(SubjectError::EventProtocolMismatch);
                }

                if let Some(eval) = evaluation.evaluator_response_ok() {
                    Self::apply_patch_verify(
                        &mut modified_subject_metadata.properties,
                        eval.patch,
                    )?;

                    if let Some(new_owner) =
                        &modified_subject_metadata.new_owner.take()
                    {
                        modified_subject_metadata.owner = new_owner.clone();
                    } else {
                        return Err(SubjectError::ConfirmWithoutNewOwner);
                    }
                }

                (
                    validation,
                    ActualProtocols::Eval {
                        eval_data: evaluation.clone(),
                    },
                    Some(event_request),
                    None,
                    None,
                )
            }
            (
                Protocols::Reject {
                    event_request,
                    validation,
                },
                ..,
            ) => {
                if let EventRequest::Reject(..) = event_request.content() {
                } else {
                    return Err(SubjectError::EventProtocolMismatch);
                }

                if modified_subject_metadata.new_owner.take().is_none() {
                    return Err(SubjectError::RejectWithoutNewOwner);
                }

                (
                    validation,
                    ActualProtocols::None,
                    Some(event_request),
                    None,
                    None,
                )
            }
            (
                Protocols::EOL {
                    event_request,
                    validation,
                },
                ..,
            ) => {
                if let EventRequest::EOL(..) = event_request.content() {
                } else {
                    return Err(SubjectError::EventProtocolMismatch);
                }

                if modified_subject_metadata.new_owner.is_some() {
                    return Err(SubjectError::UnexpectedEOLEvent);
                }

                modified_subject_metadata.active = false;
                (
                    validation,
                    ActualProtocols::None,
                    Some(event_request),
                    None,
                    None,
                )
            }
            _ => {
                return Err(SubjectError::EventProtocolMismatch);
            }
        };

        if let Some(event_request) = event_request {
            if event_request.verify().is_err() {
                return Err(SubjectError::SignatureVerificationFailed {
                    context: "event request signature verification failed"
                        .to_string(),
                });
            }

            let signer = event_request.signature().signer.clone();
            if !event_request.content().check_request_signature(
                &signer,
                &subject_metadata.owner,
                &subject_metadata.new_owner,
            ) {
                let (event, expected) = match event_request.content() {
                    EventRequest::Create(..) => {
                        ("create", subject_metadata.owner.to_string())
                    }
                    EventRequest::Transfer(..) => {
                        ("transfer", subject_metadata.owner.to_string())
                    }
                    EventRequest::EOL(..) => {
                        ("eol", subject_metadata.owner.to_string())
                    }
                    EventRequest::Confirm(..) => (
                        "confirm",
                        subject_metadata.new_owner.as_ref().map_or_else(
                            || "new_owner".to_owned(),
                            ToString::to_string,
                        ),
                    ),
                    EventRequest::Reject(..) => (
                        "reject",
                        subject_metadata.new_owner.as_ref().map_or_else(
                            || "new_owner".to_owned(),
                            ToString::to_string,
                        ),
                    ),
                    EventRequest::Fact(..) => ("fact", signer.to_string()),
                };

                return Err(SubjectError::InvalidEventRequestSigner {
                    event: event.to_owned(),
                    expected,
                    actual: signer.to_string(),
                });
            }

            let event_subject_id = event_request.content().get_subject_id();
            if event_subject_id != subject_metadata.subject_id {
                return Err(SubjectError::SubjectIdMismatch {
                    expected: subject_metadata.subject_id.to_string(),
                    actual: event_subject_id.to_string(),
                });
            }
        }

        if modified_subject_metadata.schema_id.is_gov()
            && new_actual_protocols.is_success()
        {
            let mut gov_data = serde_json::from_value::<GovernanceData>(
                modified_subject_metadata.properties.0,
            )
            .map_err(|e| {
                SubjectError::GovernanceDataConversionFailed {
                    details: e.to_string(),
                }
            })?;

            gov_data.version += 1;
            modified_subject_metadata.properties = gov_data.to_value_wrapper();
        }

        modified_subject_metadata.prev_ledger_event_hash =
            actual_ledger_event_hash.clone();

        let meta_wo_props =
            MetadataWithoutProperties::from(modified_subject_metadata.clone());

        let meta_wo_props_hash = hash_borsh(&*hash.hasher(), &meta_wo_props)
            .map_err(|e| SubjectError::ModifiedMetadataHashFailed {
                details: e.to_string(),
            })?;

        let (event_request_hash, viewpoints_hash) = if let Some(event_request) =
            event_request
        {
            (
                hash_borsh(&*hash.hasher(), event_request).map_err(|e| {
                    SubjectError::HashCreationFailed {
                        details: e.to_string(),
                    }
                })?,
                Self::hash_viewpoints(
                    hash,
                    &Self::request_viewpoints(event_request.content()),
                )?,
            )
        } else {
            (
                opaque_event_request_hash.ok_or_else(|| {
                    SubjectError::CannotObtain {
                        what: "tracker opaque event_request_hash".to_owned(),
                    }
                })?,
                opaque_viewpoints_hash.ok_or_else(|| {
                    SubjectError::CannotObtain {
                        what: "tracker opaque viewpoints_hash".to_owned(),
                    }
                })?,
            )
        };

        let propierties_hash = if full_view
            && let Some(event_request) = event_request
        {
            let validation_req = ValidationReq::Event {
                actual_protocols: Box::new(new_actual_protocols),
                event_request: event_request.clone(),
                ledger_hash: actual_ledger_event_hash,
                metadata: Box::new(subject_metadata.clone()),
                last_data: Box::new(last_data),
                gov_version: new_ledger_event.gov_version,
                sn: new_ledger_event.sn,
            };

            let signed_validation_req = Signed::from_parts(
                validation_req,
                validation.validation_req_signature.clone(),
            );

            if signed_validation_req.verify().is_err() {
                return Err(SubjectError::InvalidValidationRequestSignature);
            }

            let hash_signed_val_req =
                hash_borsh(&*hash.hasher(), &signed_validation_req).map_err(
                    |e| SubjectError::ValidationRequestHashFailed {
                        details: e.to_string(),
                    },
                )?;

            if hash_signed_val_req != validation.validation_req_hash {
                return Err(SubjectError::ValidationRequestHashMismatch);
            }

            let prop_hash = hash_borsh(
                &*hash.hasher(),
                &modified_subject_metadata.properties,
            )
            .map_err(|e| {
                SubjectError::ModifiedMetadataHashFailed {
                    details: e.to_string(),
                }
            })?;

            if let ValidationMetadata::ModifiedHash {
                propierties_hash,
                modified_metadata_without_propierties_hash,
                event_request_hash: validation_event_request_hash,
                viewpoints_hash: validation_viewpoints_hash,
            } = &validation.validation_metadata
            {
                if modified_metadata_without_propierties_hash
                    != &meta_wo_props_hash
                {
                    return Err(
                        SubjectError::ModifiedMetadataWithoutPropertiesHashMismatch {
                            expected: meta_wo_props_hash.to_string(),
                            actual: modified_metadata_without_propierties_hash
                                .to_string(),
                        },
                    );
                }

                if &prop_hash != propierties_hash {
                    return Err(SubjectError::PropertiesHashMismatch {
                        expected: prop_hash.to_string(),
                        actual: propierties_hash.to_string(),
                    });
                }

                if &event_request_hash != validation_event_request_hash {
                    return Err(SubjectError::EventRequestHashMismatch {
                        expected: event_request_hash.to_string(),
                        actual: validation_event_request_hash.to_string(),
                    });
                }

                if &viewpoints_hash != validation_viewpoints_hash {
                    return Err(SubjectError::ViewpointsHashMismatch {
                        expected: viewpoints_hash.to_string(),
                        actual: validation_viewpoints_hash.to_string(),
                    });
                }
            } else {
                return Err(SubjectError::InvalidNonCreationValidationMetadata);
            }

            prop_hash
        } else {
            if let ValidationMetadata::ModifiedHash {
                propierties_hash,
                modified_metadata_without_propierties_hash,
                event_request_hash: validation_event_request_hash,
                viewpoints_hash: validation_viewpoints_hash,
            } = &validation.validation_metadata
            {
                if modified_metadata_without_propierties_hash
                    != &meta_wo_props_hash
                {
                    return Err(
                        SubjectError::ModifiedMetadataWithoutPropertiesHashMismatch {
                            expected: meta_wo_props_hash.to_string(),
                            actual: modified_metadata_without_propierties_hash
                                .to_string(),
                        },
                    );
                }

                if &event_request_hash != validation_event_request_hash {
                    return Err(SubjectError::EventRequestHashMismatch {
                        expected: event_request_hash.to_string(),
                        actual: validation_event_request_hash.to_string(),
                    });
                }

                if &viewpoints_hash != validation_viewpoints_hash {
                    return Err(SubjectError::ViewpointsHashMismatch {
                        expected: viewpoints_hash.to_string(),
                        actual: validation_viewpoints_hash.to_string(),
                    });
                }

                propierties_hash.clone()
            } else {
                return Err(SubjectError::InvalidNonCreationValidationMetadata);
            }
        };

        let validation_res = ValidationRes::Response {
            vali_req_hash: validation.validation_req_hash.clone(),
            modified_metadata_without_propierties_hash: meta_wo_props_hash,
            propierties_hash,
            event_request_hash,
            viewpoints_hash,
        };

        let role_data = get_validation_roles_register(
            ctx,
            &subject_metadata.governance_id,
            SearchRole {
                schema_id: subject_metadata.schema_id,
                namespace: subject_metadata.namespace,
            },
            new_ledger_event.gov_version,
        )
        .await
        .map_err(|e| SubjectError::ValidatorsRetrievalFailed {
            details: e.to_string(),
        })?;

        if !check_quorum_signers(
            &validation
                .validators_signatures
                .iter()
                .map(|x| x.signer.clone())
                .collect::<HashSet<PublicKey>>(),
            &role_data.quorum,
            &role_data.workers,
        ) {
            return Err(SubjectError::InvalidQuorum);
        }

        for signature in validation.validators_signatures.iter() {
            let signed_res =
                Signed::from_parts(validation_res.clone(), signature.clone());

            if signed_res.verify().is_err() {
                return Err(SubjectError::InvalidValidatorSignature);
            }
        }

        Ok(new_ledger_event.protocols.is_success())
    }

    async fn verify_first_ledger_event(
        ctx: &mut ActorContext<Self>,
        ledger_event: &Ledger,
        hash: &HashAlgorithm,
        subject_metadata: Metadata,
    ) -> Result<(), SubjectError> {
        if ledger_event.sn != 0 {
            return Err(SubjectError::InvalidCreationSequenceNumber);
        }

        let protocols_hash = ledger_event
            .protocols
            .hash_for_ledger(hash)
            .map_err(|e| SubjectError::HashCreationFailed {
                details: e.to_string(),
            })?;

        let ledger_seal = LedgerSeal {
            gov_version: ledger_event.gov_version,
            sn: ledger_event.sn,
            prev_ledger_event_hash: ledger_event.prev_ledger_event_hash.clone(),
            protocols_hash,
        };

        if ledger_event
            .ledger_seal_signature
            .verify(&ledger_seal)
            .is_err()
        {
            return Err(SubjectError::SignatureVerificationFailed {
                context: "first ledger event signature verification failed"
                    .to_string(),
            });
        }

        if ledger_event.ledger_seal_signature.signer != subject_metadata.owner {
            return Err(SubjectError::IncorrectSigner {
                expected: subject_metadata.owner.to_string(),
                actual: ledger_event.ledger_seal_signature.signer.to_string(),
            });
        }

        let (validation, event_request) = match &ledger_event.protocols {
            Protocols::Create {
                validation,
                event_request,
            } => {
                if let EventRequest::Create(..) = event_request.content() {
                } else {
                    return Err(SubjectError::EventProtocolMismatch);
                }

                if event_request.verify().is_err() {
                    return Err(SubjectError::SignatureVerificationFailed {
                        context: "event request signature verification failed"
                            .to_string(),
                    });
                }

                let event_request_signer =
                    event_request.signature().signer.clone();
                if event_request_signer != subject_metadata.owner {
                    return Err(SubjectError::InvalidEventRequestSigner {
                        event: "Create".to_owned(),
                        expected: subject_metadata.owner.to_string(),
                        actual: event_request_signer.to_string(),
                    });
                }

                (validation, event_request)
            }
            _ => {
                return Err(SubjectError::EventProtocolMismatch);
            }
        };

        if !ledger_event.prev_ledger_event_hash.is_empty() {
            return Err(SubjectError::NonEmptyPreviousHashInCreation);
        }

        let ValidationMetadata::Metadata(metadata) =
            &validation.validation_metadata
        else {
            return Err(SubjectError::InvalidValidationMetadata);
        };

        let validation_req = ValidationReq::Create {
            event_request: event_request.clone(),
            gov_version: ledger_event.gov_version,
            subject_id: subject_metadata.subject_id.clone(),
        };

        let signed_validation_req = Signed::from_parts(
            validation_req,
            validation.validation_req_signature.clone(),
        );

        if signed_validation_req.verify().is_err() {
            return Err(SubjectError::InvalidValidationRequestSignature);
        }

        let hash_signed_val_req =
            hash_borsh(&*hash.hasher(), &signed_validation_req).map_err(
                |e| SubjectError::ValidationRequestHashFailed {
                    details: e.to_string(),
                },
            )?;

        if hash_signed_val_req != validation.validation_req_hash {
            return Err(SubjectError::ValidationRequestHashMismatch);
        }

        if metadata.deref() != &subject_metadata {
            return Err(SubjectError::MetadataMismatch);
        }

        if metadata.schema_id == SchemaType::Governance {
            serde_json::from_value::<GovernanceData>(
                metadata.properties.0.clone(),
            )
            .map_err(|e| {
                SubjectError::GovernancePropertiesConversionFailed {
                    details: e.to_string(),
                }
            })?;
        }

        let validation_res = ValidationRes::Create {
            vali_req_hash: hash_signed_val_req,
            subject_metadata: Box::new(subject_metadata),
        };

        let role_data = match metadata.schema_id {
            SchemaType::Governance => RoleDataRegister {
                workers: HashSet::from([metadata.owner.clone()]),
                quorum: Quorum::Majority,
            },
            SchemaType::Type(_) => get_validation_roles_register(
                ctx,
                &metadata.governance_id,
                SearchRole {
                    schema_id: metadata.schema_id.clone(),
                    namespace: metadata.namespace.clone(),
                },
                ledger_event.gov_version,
            )
            .await
            .map_err(|e| {
                SubjectError::ValidatorsRetrievalFailed {
                    details: e.to_string(),
                }
            })?,
            SchemaType::TrackerSchemas => {
                return Err(SubjectError::InvalidSchemaId);
            }
        };

        if !check_quorum_signers(
            &validation
                .validators_signatures
                .iter()
                .map(|x| x.signer.clone())
                .collect::<HashSet<PublicKey>>(),
            &role_data.quorum,
            &role_data.workers,
        ) {
            return Err(SubjectError::InvalidQuorum);
        }

        for signature in validation.validators_signatures.iter() {
            let signed_res =
                Signed::from_parts(validation_res.clone(), signature.clone());

            if signed_res.verify().is_err() {
                return Err(SubjectError::InvalidValidatorSignature);
            }
        }

        Ok(())
    }

    async fn register(
        ctx: &mut ActorContext<Self>,
        message: RegisterMessage,
    ) -> Result<(), ActorError> {
        let register_path = ActorPath::from("/user/node/register");
        match ctx.system().get_actor::<Register>(&register_path).await {
            Ok(register) => {
                register.tell(message.clone()).await?;

                debug!(
                    message = ?message,
                    "Register message sent successfully"
                );
            }
            Err(e) => {
                error!(
                    path = %register_path,
                    "Register actor not found"
                );
                return Err(e);
            }
        };

        Ok(())
    }

    async fn event_to_sink(
        ctx: &mut ActorContext<Self>,
        data: DataForSink,
        event: Option<EventRequest>,
    ) -> Result<(), ActorError> {
        let msg = SinkDataMessage::Event {
            event: Box::new(data_to_sink_event(data.clone(), event)),
            event_request_timestamp: data.event_request_timestamp,
            event_ledger_timestamp: data.event_ledger_timestamp,
        };

        Self::publish_sink(ctx, msg).await
    }

    async fn publish_sink(
        ctx: &mut ActorContext<Self>,
        message: SinkDataMessage,
    ) -> Result<(), ActorError> {
        let sink_data = ctx.get_child::<SinkData>("sink_data").await?;
        let (subject_id, schema_id) = message.get_subject_schema();

        sink_data.tell(message).await?;
        debug!(
            subject_id = %subject_id,
            schema_id = %schema_id,
            "Message published to sink successfully"
        );

        Ok(())
    }

    async fn get_ledger(
        &self,
        ctx: &mut ActorContext<Self>,
        lo_sn: Option<u64>,
        hi_sn: u64,
    ) -> Result<(Vec<<Self as Actor>::Event>, bool), ActorError> {
        if let Some(lo_sn) = lo_sn {
            let actual_sn = lo_sn + 1;
            if hi_sn < actual_sn {
                Ok((Vec::new(), true))
            } else {
                Ok((
                    get_n_events(ctx, actual_sn, hi_sn - actual_sn).await?,
                    true,
                ))
            }
        } else {
            Ok((get_n_events(ctx, 0, hi_sn).await?, true))
        }
    }

    async fn update_sn(
        &self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError>;

    async fn reject(
        &self,
        ctx: &mut ActorContext<Self>,
        gov_version: u64,
    ) -> Result<(), ActorError>;

    async fn confirm(
        &self,
        ctx: &mut ActorContext<Self>,
        new_owner: PublicKey,
        gov_version: u64,
    ) -> Result<(), ActorError>;

    async fn transfer(
        &self,
        ctx: &mut ActorContext<Self>,
        new_owner: PublicKey,
        gov_version: u64,
    ) -> Result<(), ActorError>;

    async fn eol(&self, ctx: &mut ActorContext<Self>)
    -> Result<(), ActorError>;

    fn apply_patch(
        &mut self,
        json_patch: ValueWrapper,
    ) -> Result<(), ActorError>;

    async fn manager_new_ledger_events(
        &mut self,
        ctx: &mut ActorContext<Self>,
        events: Vec<Ledger>,
    ) -> Result<(), ActorError>;

    async fn get_last_ledger(
        &self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<Option<Ledger>, ActorError>;
}
