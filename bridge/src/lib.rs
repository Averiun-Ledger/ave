use std::{collections::HashSet, str::FromStr};

pub use ave_common::Namespace;
pub use ave_common::response::MonitorNetworkState;
pub use ave_common::{
    bridge::request::SinksQuery,
    bridge::response::{SinkInfo, SinkStatusInfo},
    sink::{
        HttpSinkConfig, KafkaSecurityConfig, KafkaSinkConfig, SinkConfigEntry,
        SinkServer, SinkTarget, SinkTransportConfig,
    },
};
use ave_common::{
    bridge::request::{
        AbortsQuery, ApprovalState, ApprovalStateRes, BridgeSignedEventRequest,
        EventRequestType, EventsQuery, SinkEventsQuery, SinkReplayRequest,
        UpdateSubjectQuery,
    },
    identity::{DigestIdentifier, PublicKey, Signature, Signed},
    request::EventRequest,
    response::{
        ApprovalEntry, GovsData, LedgerDB, PaginatorAborts, PaginatorEvents,
        RequestData as RequestDataRes, RequestInfo, RequestInfoExtend,
        RequestsInManager, RequestsInManagerSubject, SinkEventsPage,
        SinkReplayResponse, SubjectDB, SubjsData, TransferSubject,
    },
};
pub use ave_core::config::{MachineSpec, resolve_spec};
pub use ave_core::{
    Api as AveApi,
    auth::AuthWitness,
    config::Config as AveConfig,
    config::{
        AveExternalDBConfig, AveInternalDBConfig, LoggingConfig, LoggingOutput,
        LoggingRotation,
    },
    error::Error,
};
pub use ave_network::{
    Config as NetworkConfig, ControlListConfig, MemoryLimitsConfig, NodeType,
    RoutingConfig, RoutingNode,
};
use config::Config;
use prometheus_client::registry::Registry;
use tokio::{
    signal::unix::{SignalKind, signal},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;
use utils::key_pair;

pub mod config;
pub use http::{CorsConfig, HttpConfig, ProxyConfig, SelfSignedCertConfig};
pub mod conversions;
pub mod error;
pub mod http;
pub mod settings;
pub mod utils;
pub use clap;
pub mod auth;

pub use error::BridgeError;

pub use ave_common;

#[cfg(feature = "prometheus")]
pub mod prometheus;

use crate::conversions::{
    core_approval_req_to_common, core_tranfer_subject_to_common,
};

#[cfg(all(feature = "sqlite", feature = "rocksdb"))]
compile_error!("Select only one: 'sqlite' or 'rocksdb'");

#[cfg(not(any(feature = "sqlite", feature = "rocksdb")))]
compile_error!("You must enable 'sqlite' or 'rocksdb'");

#[cfg(not(feature = "ext-sqlite"))]
compile_error!("You must enable 'ext-sqlite'");

#[derive(Clone)]
pub struct Bridge {
    api: AveApi,
    config: Config,
    graceful_token: CancellationToken,
    crash_token: CancellationToken,
    #[cfg(feature = "prometheus")]
    registry: std::sync::Arc<
        tokio::sync::Mutex<prometheus_client::registry::Registry>,
    >,
}

impl Bridge {
    pub async fn build(
        settings: &Config,
        password: &str,
        graceful_token: Option<CancellationToken>,
        crash_token: Option<CancellationToken>,
    ) -> Result<(Self, Vec<JoinHandle<()>>), BridgeError> {
        settings
            .validate()
            .map_err(|e| BridgeError::ConfigBuild(e.to_string()))?;

        utils::validate_keys_path(&settings.keys_path)
            .map_err(BridgeError::KeyPathInvalid)?;

        let keys = key_pair(settings, password)?;

        let mut registry = <Registry>::default();

        let graceful_token = graceful_token.unwrap_or_default();
        let crash_token = crash_token.unwrap_or_default();

        let (api, runners) = AveApi::build(
            keys,
            settings.node.clone(),
            settings.sinks.clone(),
            &mut registry,
            password,
            graceful_token.clone(),
            crash_token.clone(),
        )
        .await?;

        Self::bind_with_shutdown(graceful_token.clone())?;

        #[cfg(feature = "prometheus")]
        let registry = std::sync::Arc::new(tokio::sync::Mutex::new(registry));

        Ok((
            Self {
                api,
                config: settings.clone(),
                graceful_token,
                crash_token,
                #[cfg(feature = "prometheus")]
                registry,
            },
            runners,
        ))
    }

    pub const fn graceful_token(&self) -> &CancellationToken {
        &self.graceful_token
    }

    pub const fn crash_token(&self) -> &CancellationToken {
        &self.crash_token
    }

    #[cfg(feature = "prometheus")]
    pub fn registry(
        &self,
    ) -> std::sync::Arc<tokio::sync::Mutex<prometheus_client::registry::Registry>>
    {
        self.registry.clone()
    }

    fn bind_with_shutdown(token: CancellationToken) -> Result<(), BridgeError> {
        let cancellation_token = token;
        let mut sigterm = signal(SignalKind::terminate()).map_err(|e| {
            tracing::error!(error = %e, "Failed to register SIGTERM handler");
            BridgeError::SignalRegistration(e.to_string())
        })?;

        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = sigterm.recv() => {},
            }

            cancellation_token.cancel();
        });

        Ok(())
    }

    ///////// General
    ////////////////////////////
    pub fn get_peer_id(&self) -> &str {
        self.api.peer_id()
    }

    pub fn get_public_key(&self) -> &str {
        self.api.public_key()
    }

    pub fn get_config(&self) -> Config {
        self.config.clone()
    }

    ///////// Network
    ////////////////////////////
    pub async fn get_network_state(
        &self,
    ) -> Result<MonitorNetworkState, BridgeError> {
        Ok(self.api.get_network_state().await?)
    }

    ///////// Request
    ////////////////////////////
    pub async fn get_requests_in_manager(
        &self,
    ) -> Result<RequestsInManager, BridgeError> {
        Ok(self.api.get_requests_in_manager().await?)
    }

    pub async fn get_requests_in_manager_subject_id(
        &self,
        subject_id: String,
    ) -> Result<RequestsInManagerSubject, BridgeError> {
        let subject_id = Self::parse_subject_id(subject_id)?;

        Ok(self
            .api
            .get_requests_in_manager_subject_id(subject_id)
            .await?)
    }

    pub async fn post_event_request(
        &self,
        request: BridgeSignedEventRequest,
    ) -> Result<RequestDataRes, BridgeError> {
        let event: EventRequest =
            conversions::bridge_to_event_request(request.request)?;
        let result = if let Some(signature) = request.signature {
            let signature = Signature::try_from(signature).map_err(|e| {
                BridgeError::InvalidSignature(format!("{:?}", e))
            })?;

            let signed_request = Signed::from_parts(event, signature);

            self.api.external_request(signed_request).await?
        } else {
            self.api.own_request(event).await?
        };
        Ok(conversions::core_request_to_common(result))
    }

    pub async fn get_approval(
        &self,
        subject_id: String,
        state: Option<ApprovalState>,
    ) -> Result<Option<ApprovalEntry>, BridgeError> {
        let subject_id = Self::parse_subject_id(subject_id)?;

        Ok(self.api.get_approval(subject_id, state).await?.map(|x| {
            ApprovalEntry {
                request: core_approval_req_to_common(x.0),
                state: x.1,
            }
        }))
    }

    pub async fn get_approvals(
        &self,
        state: Option<ApprovalState>,
    ) -> Result<Vec<ApprovalEntry>, BridgeError> {
        let res = self.api.get_approvals(state).await?;

        Ok(res
            .iter()
            .map(|x| ApprovalEntry {
                request: core_approval_req_to_common(x.0.clone()),
                state: x.1.clone(),
            })
            .collect())
    }

    pub async fn patch_approve(
        &self,
        subject_id: String,
        state: ApprovalStateRes,
    ) -> Result<String, BridgeError> {
        let subject_id = Self::parse_subject_id(subject_id)?;
        if state == ApprovalStateRes::Obsolete {
            return Err(BridgeError::Core(Error::InvalidApprovalState(
                "Obsolete is not a valid target approval state".to_owned(),
            )));
        }

        Ok(self.api.approve(subject_id, state).await?)
    }

    pub async fn post_manual_request_abort(
        &self,
        subject_id: String,
    ) -> Result<String, BridgeError> {
        let subject_id = Self::parse_subject_id(subject_id)?;

        Ok(self.api.manual_request_abort(subject_id).await?)
    }

    ///////// Tracking
    ////////////////////////////
    pub async fn get_request_state(
        &self,
        request_id: String,
    ) -> Result<RequestInfo, BridgeError> {
        let request_id = Self::parse_request_id(request_id)?;

        Ok(self.api.get_request_state(request_id).await?)
    }

    pub async fn get_all_request_state(
        &self,
    ) -> Result<Vec<RequestInfoExtend>, BridgeError> {
        Ok(self.api.all_request_state().await?)
    }

    ///////// Node
    ////////////////////////////
    pub async fn get_pending_transfers(
        &self,
    ) -> Result<Vec<TransferSubject>, BridgeError> {
        let res = self.api.get_pending_transfers().await?;
        Ok(res
            .iter()
            .map(|x| core_tranfer_subject_to_common(x.clone()))
            .collect())
    }

    ///////// Sink
    ////////////////////////////
    pub async fn get_sinks(
        &self,
        query: SinksQuery,
    ) -> Result<Vec<SinkInfo>, BridgeError> {
        ave_core::validate_sinks_query(&query)?;

        Ok(self.api.get_sinks(query).await?)
    }

    pub async fn get_sink(
        &self,
        sink_name: String,
    ) -> Result<SinkInfo, BridgeError> {
        Self::require_non_empty_str("sink_name", &sink_name)?;

        Ok(self.api.get_sink(sink_name).await?)
    }

    pub async fn get_sinks_status(
        &self,
    ) -> Result<Vec<SinkStatusInfo>, BridgeError> {
        Ok(self.api.get_sinks_status().await?)
    }

    pub async fn unblock_sink(
        &self,
        sink_name: String,
    ) -> Result<(), BridgeError> {
        Self::require_non_empty_str("sink_name", &sink_name)?;

        self.api
            .unblock_sink(sink_name)
            .await
            .map_err(BridgeError::Core)
    }

    pub async fn reset_sink_cursors(
        &self,
        sink_name: String,
    ) -> Result<(), BridgeError> {
        Self::require_non_empty_str("sink_name", &sink_name)?;

        self.api
            .reset_sink_cursors(sink_name)
            .await
            .map_err(BridgeError::Core)
    }

    pub async fn replay_sink_events(
        &self,
        request: SinkReplayRequest,
    ) -> Result<SinkReplayResponse, BridgeError> {
        ave_core::validate_sink_replay_request(&request)?;

        self.api
            .replay_sink_events(request)
            .await
            .map_err(BridgeError::Core)
    }

    pub async fn test_sink(
        &self,
        sink_name: String,
    ) -> Result<(), BridgeError> {
        Self::require_non_empty_str("sink_name", &sink_name)?;

        self.api
            .test_sink(sink_name)
            .await
            .map_err(BridgeError::Core)
    }

    ///////// SubjectAccess
    ////////////////////////////
    pub async fn authorize_governance(
        &self,
        subject_id: String,
        witnesses: Vec<String>,
    ) -> Result<String, BridgeError> {
        let subject_id = Self::parse_subject_id(subject_id)?;
        let witnesses_key: Vec<PublicKey> = witnesses
            .into_iter()
            .map(|key| Self::parse_public_key_labeled("witness", key))
            .collect::<Result<Vec<_>, _>>()?;

        let auth_witness = if witnesses_key.is_empty() {
            AuthWitness::None
        } else if witnesses_key.len() == 1 {
            AuthWitness::One(witnesses_key[0].clone())
        } else {
            AuthWitness::Many(witnesses_key)
        };

        Ok(self
            .api
            .authorize_governance(subject_id, auth_witness)
            .await?)
    }

    pub async fn disauthorize_governance(
        &self,
        subject_id: String,
    ) -> Result<String, BridgeError> {
        let subject_id = Self::parse_subject_id(subject_id)?;

        Ok(self.api.disauthorize_governance(subject_id).await?)
    }

    pub async fn authorized_governances(
        &self,
    ) -> Result<Vec<String>, BridgeError> {
        let res = self.api.authorized_governances().await?;

        Ok(res.iter().map(|x| x.to_string()).collect())
    }

    pub async fn is_governance_authorized(
        &self,
        subject_id: String,
    ) -> Result<bool, BridgeError> {
        let subject_id = Self::parse_subject_id(subject_id)?;

        Ok(self.api.is_governance_authorized(subject_id).await?)
    }

    pub async fn ban_tracker(
        &self,
        subject_id: String,
    ) -> Result<String, BridgeError> {
        let subject_id = Self::parse_subject_id(subject_id)?;

        Ok(self.api.ban_tracker(subject_id).await?)
    }

    pub async fn unban_tracker(
        &self,
        subject_id: String,
    ) -> Result<String, BridgeError> {
        let subject_id = Self::parse_subject_id(subject_id)?;

        Ok(self.api.unban_tracker(subject_id).await?)
    }

    pub async fn is_tracker_banned(
        &self,
        subject_id: String,
    ) -> Result<bool, BridgeError> {
        let subject_id = Self::parse_subject_id(subject_id)?;

        Ok(self.api.is_tracker_banned(subject_id).await?)
    }

    pub async fn banned_trackers(&self) -> Result<Vec<String>, BridgeError> {
        let res = self.api.banned_trackers().await?;

        Ok(res.iter().map(|x| x.to_string()).collect())
    }

    pub async fn add_sync_peer(
        &self,
        subject_id: String,
        peers: Vec<String>,
    ) -> Result<String, BridgeError> {
        let subject_id = Self::parse_subject_id(subject_id)?;
        let peers_key = Self::parse_public_keys(peers, "peer")?;

        Ok(self.api.add_sync_peer(subject_id, peers_key).await?)
    }

    pub async fn remove_sync_peer(
        &self,
        subject_id: String,
        peers: Vec<String>,
    ) -> Result<String, BridgeError> {
        let subject_id = Self::parse_subject_id(subject_id)?;
        let peers_key = Self::parse_public_keys(peers, "peer")?;

        Ok(self.api.remove_sync_peer(subject_id, peers_key).await?)
    }

    pub async fn get_sync_peers(
        &self,
        subject_id: String,
    ) -> Result<HashSet<String>, BridgeError> {
        let subject_id = Self::parse_subject_id(subject_id)?;

        let res = self.api.sync_peers(subject_id).await?;

        Ok(res.iter().map(|x| x.to_string()).collect())
    }

    pub async fn subjects_with_sync_peers(
        &self,
    ) -> Result<Vec<String>, BridgeError> {
        let res = self.api.subjects_with_sync_peers().await?;

        Ok(res.iter().map(|x| x.to_string()).collect())
    }

    pub async fn post_update_subject(
        &self,
        subject_id: String,
        query: UpdateSubjectQuery,
    ) -> Result<String, BridgeError> {
        let subject_id = Self::parse_subject_id(subject_id)?;

        Ok(self
            .api
            .update_subject_with_options(
                subject_id,
                query.strict.unwrap_or(false),
            )
            .await?)
    }

    pub async fn delete_subject(
        &self,
        subject_id: String,
    ) -> Result<String, BridgeError> {
        let subject_id = Self::parse_subject_id(subject_id)?;

        Ok(self.api.delete_subject(subject_id).await?)
    }

    ///////// manual distribution
    ////////////////////////////
    pub async fn post_manual_distribution(
        &self,
        subject_id: String,
    ) -> Result<String, BridgeError> {
        let subject_id = Self::parse_subject_id(subject_id)?;

        Ok(self.api.manual_distribution(subject_id).await?)
    }

    ///////// Register
    ////////////////////////////
    pub async fn get_all_govs(
        &self,
        active: Option<bool>,
    ) -> Result<Vec<GovsData>, BridgeError> {
        Ok(self.api.all_govs(active).await?)
    }

    pub async fn get_all_subjs(
        &self,
        governance_id: String,
        active: Option<bool>,
        schema_id: Option<String>,
    ) -> Result<Vec<SubjsData>, BridgeError> {
        let governance_id = Self::parse_governance_id(governance_id)?;
        if let Some(schema_id) = schema_id.as_deref() {
            Self::require_non_empty_str("schema_id", schema_id)?;
        }

        Ok(self.api.all_subjs(governance_id, active, schema_id).await?)
    }

    ///////// Query
    ////////////////////////////
    pub async fn get_events(
        &self,
        subject_id: String,
        query: EventsQuery,
    ) -> Result<PaginatorEvents, BridgeError> {
        let subject_id = Self::parse_subject_id(subject_id)?;
        ave_core::validate_events_query(&query)?;

        Ok(self.api.get_events(subject_id, query).await?)
    }

    pub async fn get_sink_events(
        &self,
        subject_id: String,
        query: SinkEventsQuery,
    ) -> Result<SinkEventsPage, BridgeError> {
        let subject_id = Self::parse_subject_id(subject_id)?;
        ave_core::validate_sink_events_query(&query)?;

        Ok(self.api.get_sink_events(subject_id, query).await?)
    }

    pub async fn get_aborts(
        &self,
        subject_id: String,
        query: AbortsQuery,
    ) -> Result<PaginatorAborts, BridgeError> {
        let subject_id = Self::parse_subject_id(subject_id)?;
        ave_core::validate_aborts_query(&query)?;

        Ok(self.api.get_aborts(subject_id, query).await?)
    }

    pub async fn get_event_sn(
        &self,
        subject_id: String,
        sn: u64,
    ) -> Result<LedgerDB, BridgeError> {
        let subject_id = Self::parse_subject_id(subject_id)?;

        Ok(self.api.get_event_sn(subject_id, sn).await?)
    }

    pub async fn get_first_or_end_events(
        &self,
        subject_id: String,
        quantity: Option<u64>,
        reverse: Option<bool>,
        event_type: Option<EventRequestType>,
    ) -> Result<Vec<LedgerDB>, BridgeError> {
        let subject_id = Self::parse_subject_id(subject_id)?;
        if let Some(quantity) = quantity {
            Self::require_positive_u64("quantity", quantity)?;
        }

        Ok(self
            .api
            .get_first_or_end_events(subject_id, quantity, reverse, event_type)
            .await?)
    }

    pub async fn get_subject_state(
        &self,
        subject_id: String,
    ) -> Result<SubjectDB, BridgeError> {
        let subject_id = Self::parse_subject_id(subject_id)?;

        Ok(self.api.get_subject_state(subject_id).await?)
    }

    ///////// Input validation helpers
    ////////////////////////////

    fn parse_subject_id(
        subject_id: String,
    ) -> Result<DigestIdentifier, BridgeError> {
        if subject_id.is_empty() {
            return Err(BridgeError::InvalidSubjectId(
                "subject_id must not be empty".to_owned(),
            ));
        }
        DigestIdentifier::from_str(&subject_id).map_err(|e| {
            BridgeError::InvalidSubjectId(format!("subject_id is invalid: {e}"))
        })
    }

    fn parse_governance_id(
        governance_id: String,
    ) -> Result<DigestIdentifier, BridgeError> {
        if governance_id.is_empty() {
            return Err(BridgeError::InvalidGovernanceId(
                "governance_id must not be empty".to_owned(),
            ));
        }
        DigestIdentifier::from_str(&governance_id).map_err(|e| {
            BridgeError::InvalidGovernanceId(format!(
                "governance_id is invalid: {e}"
            ))
        })
    }

    fn parse_request_id(
        request_id: String,
    ) -> Result<DigestIdentifier, BridgeError> {
        if request_id.is_empty() {
            return Err(BridgeError::InvalidRequestId(
                "request_id must not be empty".to_owned(),
            ));
        }
        DigestIdentifier::from_str(&request_id).map_err(|e| {
            BridgeError::InvalidRequestId(format!("request_id is invalid: {e}"))
        })
    }

    fn parse_public_key_labeled(
        label: &'static str,
        key: String,
    ) -> Result<PublicKey, BridgeError> {
        if key.is_empty() {
            return Err(BridgeError::InvalidPublicKey(format!(
                "{label} must not be empty"
            )));
        }
        PublicKey::from_str(&key).map_err(|e| {
            BridgeError::InvalidPublicKey(format!("{label} is invalid: {e}"))
        })
    }

    fn parse_public_keys(
        keys: Vec<String>,
        label: &'static str,
    ) -> Result<Vec<PublicKey>, BridgeError> {
        if keys.is_empty() {
            return Err(BridgeError::InvalidPublicKey(format!(
                "{label} must not be empty"
            )));
        }
        keys.into_iter()
            .map(|key| Self::parse_public_key_labeled(label, key))
            .collect()
    }

    fn require_non_empty_str(
        name: &'static str,
        value: &str,
    ) -> Result<(), BridgeError> {
        if value.is_empty() {
            return Err(BridgeError::Core(Error::InvalidQueryParams(format!(
                "{name} must not be empty"
            ))));
        }
        Ok(())
    }

    fn require_positive_u64(
        name: &'static str,
        value: u64,
    ) -> Result<(), BridgeError> {
        if value == 0 {
            return Err(BridgeError::Core(Error::InvalidQueryParams(format!(
                "{name} must be greater than zero, got 0"
            ))));
        }
        Ok(())
    }
}
