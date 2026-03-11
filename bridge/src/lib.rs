use std::{collections::HashSet, str::FromStr};

pub use ave_common::Namespace;
pub use ave_common::response::MonitorNetworkState;
use ave_common::{
    bridge::request::{
        ApprovalState, ApprovalStateRes, BridgeSignedEventRequest,
        EventRequestType, EventsQuery,
    },
    identity::{DigestIdentifier, PublicKey, Signature, Signed},
    request::EventRequest,
    response::{
        ApprovalEntry, GovsData, LedgerDB, PaginatorAborts, PaginatorEvents,
        RequestData as RequestDataRes, RequestInfo, RequestInfoExtend,
        RequestsInManager, RequestsInManagerSubject, SubjectDB, SubjsData,
        TransferSubject,
    },
};
pub use ave_core::config::{MachineSpec, resolve_spec};
pub use ave_core::{
    Api as AveApi,
    auth::AuthWitness,
    config::Config as AveConfig,
    config::{
        AveExternalDBConfig, AveInternalDBConfig, LoggingConfig, LoggingOutput,
        LoggingRotation, SinkConfig, SinkServer,
    },
    error::Error,
};
use ave_core::{config::SinkAuth, helpers::sink::obtain_token};
use config::Config;
pub use network::{
    Config as NetworkConfig, ControlListConfig, MemoryLimitsConfig,
    RoutingConfig, RoutingNode,
};
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
    registry: std::sync::Arc<tokio::sync::Mutex<prometheus_client::registry::Registry>>,
}

impl Bridge {
    pub async fn build(
        settings: &Config,
        password: &str,
        password_sink: &str,
        sink_api_key: &str,
        graceful_token: Option<CancellationToken>,
        crash_token: Option<CancellationToken>,
    ) -> Result<(Self, Vec<JoinHandle<()>>), BridgeError> {
        let keys = key_pair(settings, password)?;

        // Skip bearer token acquisition when using api_key mode
        let auth_token =
            if sink_api_key.is_empty() && !settings.sink.auth.is_empty() {
                Some(
                    obtain_token(
                        &settings.sink.auth,
                        &settings.sink.username,
                        password_sink,
                    )
                    .await?,
                )
            } else {
                None
            };

        let mut registry = <Registry>::default();

        let graceful_token = graceful_token.unwrap_or_default();
        let crash_token = crash_token.unwrap_or_default();

        let (api, runners) = AveApi::build(
            keys,
            settings.node.clone(),
            SinkAuth {
                sink: settings.sink.clone(),
                token: auth_token,
                password: password_sink.to_owned(),
                api_key: sink_api_key.to_owned(),
            },
            &mut registry,
            password,
            graceful_token.clone(),
            crash_token.clone()

        )
        .await?;

        Self::bind_with_shutdown(graceful_token.clone());

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
    ) -> std::sync::Arc<tokio::sync::Mutex<prometheus_client::registry::Registry>> {
        self.registry.clone()
    }

    fn bind_with_shutdown(token: CancellationToken) {
        let cancellation_token = token;
        let mut sigterm = signal(SignalKind::terminate())
            .expect("It could not be registered SIGTERM");

        tokio::spawn(async move {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {},
                _ = sigterm.recv() => {},
            }

            cancellation_token.cancel();
        });
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
        let subject_id = DigestIdentifier::from_str(&subject_id)
            .map_err(|e| BridgeError::InvalidSubjectId(e.to_string()))?;

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
        let subject_id = DigestIdentifier::from_str(&subject_id)
            .map_err(|e| BridgeError::InvalidSubjectId(e.to_string()))?;

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
        let subject_id = DigestIdentifier::from_str(&subject_id)
            .map_err(|e| BridgeError::InvalidSubjectId(e.to_string()))?;

        Ok(self.api.approve(subject_id, state).await?)
    }

    pub async fn post_manual_request_abort(
        &self,
        subject_id: String,
    ) -> Result<String, BridgeError> {
        let subject_id = DigestIdentifier::from_str(&subject_id)
            .map_err(|e| BridgeError::InvalidSubjectId(e.to_string()))?;

        Ok(self.api.manual_request_abort(subject_id).await?)
    }

    ///////// Tracking
    ////////////////////////////
    pub async fn get_request_state(
        &self,
        request_id: String,
    ) -> Result<RequestInfo, BridgeError> {
        let request_id = DigestIdentifier::from_str(&request_id)
            .map_err(|e| BridgeError::InvalidRequestId(e.to_string()))?;

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

    ///////// Auth
    ////////////////////////////
    pub async fn put_auth_subject(
        &self,
        subject_id: String,
        witnesses: Vec<String>,
    ) -> Result<String, BridgeError> {
        let subject_id = DigestIdentifier::from_str(&subject_id)
            .map_err(|e| BridgeError::InvalidSubjectId(e.to_string()))?;

        let mut witnesses_key = vec![];

        for witness in witnesses {
            witnesses_key.push(
                PublicKey::from_str(&witness).map_err(|e| {
                    BridgeError::InvalidPublicKey(e.to_string())
                })?,
            );
        }

        let auh_witness = if witnesses_key.is_empty() {
            AuthWitness::None
        } else if witnesses_key.len() == 1 {
            AuthWitness::One(witnesses_key[0].clone())
        } else {
            AuthWitness::Many(witnesses_key)
        };

        Ok(self.api.auth_subject(subject_id, auh_witness).await?)
    }

    pub async fn get_all_auth_subjects(
        &self,
    ) -> Result<Vec<String>, BridgeError> {
        let res = self.api.all_auth_subjects().await?;

        Ok(res.iter().map(|x| x.to_string()).collect())
    }

    pub async fn get_witnesses_subject(
        &self,
        subject_id: String,
    ) -> Result<HashSet<String>, BridgeError> {
        let subject_id = DigestIdentifier::from_str(&subject_id)
            .map_err(|e| BridgeError::InvalidSubjectId(e.to_string()))?;

        let res = self.api.witnesses_subject(subject_id).await?;

        Ok(res.iter().map(|x| x.to_string()).collect())
    }

    pub async fn delete_auth_subject(
        &self,
        subject_id: String,
    ) -> Result<String, BridgeError> {
        let subject_id = DigestIdentifier::from_str(&subject_id)
            .map_err(|e| BridgeError::InvalidSubjectId(e.to_string()))?;

        Ok(self.api.delete_auth_subject(subject_id).await?)
    }

    pub async fn post_update_subject(
        &self,
        subject_id: String,
    ) -> Result<String, BridgeError> {
        let subject_id = DigestIdentifier::from_str(&subject_id)
            .map_err(|e| BridgeError::InvalidSubjectId(e.to_string()))?;

        Ok(self.api.update_subject(subject_id).await?)
    }

    ///////// manual distribution
    ////////////////////////////
    pub async fn post_manual_distribution(
        &self,
        subject_id: String,
    ) -> Result<String, BridgeError> {
        let subject_id = DigestIdentifier::from_str(&subject_id)
            .map_err(|e| BridgeError::InvalidSubjectId(e.to_string()))?;

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
        let governance_id = DigestIdentifier::from_str(&governance_id)
            .map_err(|e| BridgeError::InvalidSubjectId(e.to_string()))?;

        Ok(self.api.all_subjs(governance_id, active, schema_id).await?)
    }

    ///////// Query
    ////////////////////////////
    pub async fn get_events(
        &self,
        subject_id: String,
        query: EventsQuery,
    ) -> Result<PaginatorEvents, BridgeError> {
        let subject_id = DigestIdentifier::from_str(&subject_id)
            .map_err(|e| BridgeError::InvalidSubjectId(e.to_string()))?;

        Ok(self.api.get_events(subject_id, query).await?)
    }

    pub async fn get_aborts(
        &self,
        subject_id: String,
        request_id: Option<String>,
        sn: Option<u64>,
        quantity: Option<u64>,
        page: Option<u64>,
        reverse: Option<bool>,
    ) -> Result<PaginatorAborts, BridgeError> {
        let subject_id = DigestIdentifier::from_str(&subject_id)
            .map_err(|e| BridgeError::InvalidSubjectId(e.to_string()))?;

        let request_id =
            if let Some(request_id) = request_id {
                Some(DigestIdentifier::from_str(&request_id).map_err(|e| {
                    BridgeError::InvalidRequestId(e.to_string())
                })?)
            } else {
                None
            };

        Ok(self
            .api
            .get_aborts(subject_id, request_id, sn, quantity, page, reverse)
            .await?)
    }

    pub async fn get_event_sn(
        &self,
        subject_id: String,
        sn: u64,
    ) -> Result<LedgerDB, BridgeError> {
        let subject_id = DigestIdentifier::from_str(&subject_id)
            .map_err(|e| BridgeError::InvalidSubjectId(e.to_string()))?;

        Ok(self.api.get_event_sn(subject_id, sn).await?)
    }

    pub async fn get_first_or_end_events(
        &self,
        subject_id: String,
        quantity: Option<u64>,
        reverse: Option<bool>,
        event_type: Option<EventRequestType>,
    ) -> Result<Vec<LedgerDB>, BridgeError> {
        let subject_id = DigestIdentifier::from_str(&subject_id)
            .map_err(|e| BridgeError::InvalidSubjectId(e.to_string()))?;

        Ok(self
            .api
            .get_first_or_end_events(subject_id, quantity, reverse, event_type)
            .await?)
    }

    pub async fn get_subject_state(
        &self,
        subject_id: String,
    ) -> Result<SubjectDB, BridgeError> {
        let subject_id = DigestIdentifier::from_str(&subject_id)
            .map_err(|e| BridgeError::InvalidSubjectId(e.to_string()))?;

        Ok(self.api.get_subject_state(subject_id).await?)
    }
}
