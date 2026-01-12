use crate::{
    error::Error,
    external_db::DBManager,
    subject::{SignedLedger, sinkdata::SinkDataEvent},
};

use crate::config::ExternalDbConfig;

use async_trait::async_trait;
use ave_actors::{ActorRef, Subscriber};

use ave_common::response::{EventInfo, PaginatorEvents, SubjectInfo};
#[cfg(feature = "ext-sqlite")]
use sqlite::SqliteLocal;
use std::path::Path;
use tokio::fs;
#[cfg(feature = "ext-sqlite")]
mod sqlite;

pub mod common;

#[async_trait]
pub trait Querys {
    // events
    async fn get_events(
        &self,
        subject_id: &str,
        quantity: Option<u64>,
        page: Option<u64>,
        reverse: Option<bool>,
    ) -> Result<PaginatorEvents, Error>;

    // events sn
    async fn get_events_sn(
        &self,
        subject_id: &str,
        sn: u64,
    ) -> Result<EventInfo, Error>;

    // n first or last events
    async fn get_first_or_end_events(
        &self,
        subject_id: &str,
        quantity: Option<u64>,
        reverse: Option<bool>,
        sucess: Option<bool>,
    ) -> Result<Vec<EventInfo>, Error>;

    // subject
    async fn get_subject_state(
        &self,
        subject_id: &str,
    ) -> Result<SubjectInfo, Error>;
}

#[derive(Clone)]
pub enum ExternalDB {
    #[cfg(feature = "ext-sqlite")]
    SqliteLocal(SqliteLocal),
}

impl ExternalDB {
    pub async fn build(
        ext_db: ExternalDbConfig,
        manager: ActorRef<DBManager>,
    ) -> Result<Self, Error> {
        match ext_db {
            #[cfg(feature = "ext-sqlite")]
            ExternalDbConfig::Sqlite { path } => {
                if !Path::new(&path).exists() {
                    fs::create_dir_all(&path).await.map_err(|e| {
                        Error::Node(format!("Can not create src dir: {}", e))
                    })?;
                }
                let path = path.join("database.db");
                let sqlite = SqliteLocal::new(&path, manager).await?;
                Ok(ExternalDB::SqliteLocal(sqlite))
            }
        }
    }

    pub fn get_subject(&self) -> impl Subscriber<SignedLedger> {
        match self {
            #[cfg(feature = "ext-sqlite")]
            ExternalDB::SqliteLocal(sqlite_local) => sqlite_local.clone(),
        }
    }

    pub fn get_sink_data(&self) -> impl Subscriber<SinkDataEvent> {
        match self {
            #[cfg(feature = "ext-sqlite")]
            ExternalDB::SqliteLocal(sqlite_local) => sqlite_local.clone(),
        }
    }
}

#[async_trait]
impl Querys for ExternalDB {
    async fn get_subject_state(
        &self,
        subject_id: &str,
    ) -> Result<SubjectInfo, Error> {
        match self {
            #[cfg(feature = "ext-sqlite")]
            ExternalDB::SqliteLocal(sqlite_local) => {
                sqlite_local.get_subject_state(subject_id).await
            }
        }
    }

    async fn get_events(
        &self,
        subject_id: &str,
        quantity: Option<u64>,
        page: Option<u64>,
        reverse: Option<bool>,
    ) -> Result<PaginatorEvents, Error> {
        match self {
            #[cfg(feature = "ext-sqlite")]
            ExternalDB::SqliteLocal(sqlite_local) => {
                sqlite_local
                    .get_events(subject_id, quantity, page, reverse)
                    .await
            }
        }
    }

    async fn get_events_sn(
        &self,
        subject_id: &str,
        sn: u64,
    ) -> Result<EventInfo, Error> {
        match self {
            #[cfg(feature = "ext-sqlite")]
            ExternalDB::SqliteLocal(sqlite_local) => {
                sqlite_local.get_events_sn(subject_id, sn).await
            }
        }
    }

    async fn get_first_or_end_events(
        &self,
        subject_id: &str,
        quantity: Option<u64>,
        reverse: Option<bool>,
        sucess: Option<bool>,
    ) -> Result<Vec<EventInfo>, Error> {
        match self {
            #[cfg(feature = "ext-sqlite")]
            ExternalDB::SqliteLocal(sqlite_local) => {
                sqlite_local
                    .get_first_or_end_events(
                        subject_id, quantity, reverse, sucess,
                    )
                    .await
            }
        }
    }
}
