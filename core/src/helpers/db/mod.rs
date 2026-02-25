mod error;

use crate::{
    external_db::DBManager,
    request::tracking::RequestTrackingEvent,
    subject::{SignedLedger, sinkdata::SinkDataEvent},
};

use crate::config::{AveExternalDBFeatureConfig, MachineSpec};

use async_trait::async_trait;
use ave_actors::{ActorRef, Subscriber};

use ave_common::{
    bridge::request::{EventRequestType, EventsQuery},
    response::{LedgerDB, PaginatorAborts, PaginatorEvents, SubjectDB},
};
pub use error::DatabaseError;
#[cfg(feature = "ext-sqlite")]
use sqlite::SqliteLocal;
use std::path::Path;
use tokio::fs;
use tracing::{debug, error};
#[cfg(feature = "ext-sqlite")]
mod sqlite;

#[async_trait]
pub trait Querys {
    // events
    async fn get_events(
        &self,
        subject_id: &str,
        query: EventsQuery,
    ) -> Result<PaginatorEvents, DatabaseError>;

    async fn get_aborts(
        &self,
        subject_id: &str,
        request_id: Option<String>,
        sn: Option<u64>,
        quantity: Option<u64>,
        page: Option<u64>,
        reverse: Option<bool>,
    ) -> Result<PaginatorAborts, DatabaseError>;

    // events sn
    async fn get_event_sn(
        &self,
        subject_id: &str,
        sn: u64,
    ) -> Result<LedgerDB, DatabaseError>;

    // n first or last events
    async fn get_first_or_end_events(
        &self,
        subject_id: &str,
        quantity: Option<u64>,
        reverse: Option<bool>,
        event_type: Option<EventRequestType>,
    ) -> Result<Vec<LedgerDB>, DatabaseError>;

    // subject
    async fn get_subject_state(
        &self,
        subject_id: &str,
    ) -> Result<SubjectDB, DatabaseError>;
}

#[derive(Clone)]
pub enum ExternalDB {
    #[cfg(feature = "ext-sqlite")]
    SqliteLocal(SqliteLocal),
}

impl ExternalDB {
    pub async fn build(
        ext_db: AveExternalDBFeatureConfig,
        durability: bool,
        manager: ActorRef<DBManager>,
        spec: Option<MachineSpec>,
    ) -> Result<Self, DatabaseError> {
        match ext_db {
            #[cfg(feature = "ext-sqlite")]
            AveExternalDBFeatureConfig::Sqlite { path } => {
                if !Path::new(&path).exists() {
                    fs::create_dir_all(&path).await.map_err(|e| {
                        error!(
                            path = %path.display(),
                            error = %e,
                            "Failed to create database directory"
                        );
                        DatabaseError::DirectoryCreation(e.to_string())
                    })?;
                    debug!(
                        path = %path.display(),
                        "Database directory created"
                    );
                }
                let db_path = path.join("database.db");
                let sqlite =
                    SqliteLocal::new(&db_path, manager, durability, spec)
                        .await?;
                debug!(
                    path = %db_path.display(),
                    "External SQLite database built successfully"
                );
                Ok(Self::SqliteLocal(sqlite))
            }
        }
    }

    pub fn get_subject(&self) -> impl Subscriber<SignedLedger> {
        match self {
            #[cfg(feature = "ext-sqlite")]
            Self::SqliteLocal(sqlite_local) => sqlite_local.clone(),
        }
    }

    pub fn get_sink_data(&self) -> impl Subscriber<SinkDataEvent> {
        match self {
            #[cfg(feature = "ext-sqlite")]
            Self::SqliteLocal(sqlite_local) => sqlite_local.clone(),
        }
    }

    pub fn get_request_tracking(
        &self,
    ) -> impl Subscriber<RequestTrackingEvent> {
        match self {
            #[cfg(feature = "ext-sqlite")]
            Self::SqliteLocal(sqlite_local) => sqlite_local.clone(),
        }
    }
}

#[async_trait]
impl Querys for ExternalDB {
    async fn get_aborts(
        &self,
        subject_id: &str,
        request_id: Option<String>,
        sn: Option<u64>,
        quantity: Option<u64>,
        page: Option<u64>,
        reverse: Option<bool>,
    ) -> Result<PaginatorAborts, DatabaseError> {
        match self {
            #[cfg(feature = "ext-sqlite")]
            Self::SqliteLocal(sqlite_local) => {
                sqlite_local
                    .get_aborts(
                        subject_id, request_id, sn, quantity, page, reverse,
                    )
                    .await
            }
        }
    }

    async fn get_subject_state(
        &self,
        subject_id: &str,
    ) -> Result<SubjectDB, DatabaseError> {
        match self {
            #[cfg(feature = "ext-sqlite")]
            Self::SqliteLocal(sqlite_local) => {
                sqlite_local.get_subject_state(subject_id).await
            }
        }
    }

    async fn get_events(
        &self,
        subject_id: &str,
        query: EventsQuery,
    ) -> Result<PaginatorEvents, DatabaseError> {
        match self {
            #[cfg(feature = "ext-sqlite")]
            Self::SqliteLocal(sqlite_local) => {
                sqlite_local.get_events(subject_id, query).await
            }
        }
    }

    async fn get_event_sn(
        &self,
        subject_id: &str,
        sn: u64,
    ) -> Result<LedgerDB, DatabaseError> {
        match self {
            #[cfg(feature = "ext-sqlite")]
            Self::SqliteLocal(sqlite_local) => {
                sqlite_local.get_event_sn(subject_id, sn).await
            }
        }
    }

    async fn get_first_or_end_events(
        &self,
        subject_id: &str,
        quantity: Option<u64>,
        reverse: Option<bool>,
        event_type: Option<EventRequestType>,
    ) -> Result<Vec<LedgerDB>, DatabaseError> {
        match self {
            #[cfg(feature = "ext-sqlite")]
            Self::SqliteLocal(sqlite_local) => {
                sqlite_local
                    .get_first_or_end_events(
                        subject_id, quantity, reverse, event_type,
                    )
                    .await
            }
        }
    }
}
