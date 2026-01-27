use std::path::PathBuf;
use std::str::FromStr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ave_actors::{ActorRef, Subscriber};
use rusqlite::{Connection, OpenFlags, params};
use serde_json::{Value, json};
use tracing::error;

use crate::approval::approver::ApproverEvent;
use crate::approval::request::ApprovalReq;
use crate::error::Error;
use crate::external_db::{DBManager, DBManagerMessage};
use crate::helpers::db::common::{ApprovalReqInfo, ApproveInfo, EventDB};
use crate::model::event::LedgerValue;
use crate::subject::SignedLedger;
use crate::subject::laststate::LastStateEvent;
use crate::subject::sinkdata::{SinkDataEvent, SinkDataMessage};

use super::Querys;
use super::common::{
    EventInfo, Paginator, PaginatorEvents, SignaturesDB, SignaturesInfo,
    SubjectDB, SubjectInfo,
};

const TARGET_SQLITE: &str = "Ave-Helper-DB-Sqlite";

#[derive(Clone)]
pub struct SqliteLocal {
    manager: ActorRef<DBManager>,
    conn: Arc<Mutex<Connection>>,
}

#[async_trait]
impl Querys for SqliteLocal {
    async fn get_subject_state(
        &self,
        subject_id: &str,
    ) -> Result<SubjectInfo, Error> {
        let subject_id = subject_id.to_owned();

        let subject: SubjectDB = {
            if let Ok(conn) = self.conn.lock() {
                let sql = "SELECT * FROM subjects WHERE subject_id = ?1";

                conn.query_row(sql, params![subject_id], |row| {
                    Ok(SubjectDB {
                        name: row.get(0)?,
                        description: row.get(1)?,
                        subject_id: row.get(2)?,
                        governance_id: row.get(3)?,
                        genesis_gov_version: row.get(4)?,
                        namespace: row.get(5)?,
                        schema_id: row.get(6)?,
                        owner: row.get(7)?,
                        creator: row.get(8)?,
                        active: row.get(9)?,
                        sn: row.get(10)?,
                        properties: row.get(11)?,
                        new_owner: row.get(12)?,
                    })
                })
                .map_err(|e| Error::ExtDB(e.to_string()))?
            } else {
                return Err(Error::ExtDB(
                    "Can not lock mutex connection with DB".to_owned(),
                ));
            }
        };

        Ok(SubjectInfo {
            name: subject.name.unwrap_or_default(),
            description: subject.description.unwrap_or_default(),
            subject_id: subject.subject_id,
            governance_id: subject.governance_id,
            genesis_gov_version: subject.genesis_gov_version,
            namespace: subject.namespace,
            schema_id: subject.schema_id,
            owner: subject.owner,
            creator: subject.creator,
            active: subject.active,
            sn: subject.sn,
            properties: Value::from_str(&subject.properties).map_err(|e| {
                Error::ExtDB(format!(
                    "Can not convert properties into Value: {}",
                    e
                ))
            })?,
            new_owner: subject.new_owner,
        })
    }

    async fn get_events(
        &self,
        subject_id: &str,
        quantity: Option<u64>,
        page: Option<u64>,
        reverse: Option<bool>,
    ) -> Result<PaginatorEvents, Error> {
        let mut quantity = quantity.unwrap_or(50);
        let mut page = page.unwrap_or(1);
        if page == 0 {
            page = 1;
        }
        if quantity == 0 {
            quantity = 1;
        }

        let subject_id_cloned = subject_id.to_owned();

        let sql = "SELECT COUNT(*) FROM events WHERE subject_id = ?1";

        if let Ok(conn) = self.conn.lock() {
            let total: u64 = conn
                .query_row(sql, params![subject_id_cloned], |row| row.get(0))
                .map_err(|e| Error::ExtDB(e.to_string()))?;

            if total == 0 {
                return Err(Error::ExtDB(format!(
                    "There is no event for subject {}",
                    subject_id
                )));
            }

            let mut pages = if total.is_multiple_of(quantity) {
                total / quantity
            } else {
                total / quantity + 1
            };

            if pages == 0 {
                pages = 1;
            }

            if page > pages {
                page = pages
            }

            let offset = (page - 1) * quantity;
            let subject_id = subject_id.to_owned();

            let order_clause = if reverse.unwrap_or_default() {
                "sn DESC"
            } else {
                "sn ASC"
            };

            let sql = format!(
                "SELECT * FROM events WHERE subject_id = ?1 ORDER BY {} LIMIT ?2 OFFSET ?3",
                order_clause
            );
            let mut stmt = conn
                .prepare(&sql)
                .map_err(|e| Error::ExtDB(e.to_string()))?;

            let events = stmt.query_map(params![subject_id, quantity, offset], |row| {
                    Ok(EventDB {
                        subject_id: row.get(0)?,
                        sn: row.get(1)?,
                        patch: row.get(2)?,
                        error: row.get(3)?,
                        event_req: row.get(4)?,
                        succes: row.get(5)?,
                    })
                }).map_err(|e| Error::ExtDB(e.to_string()))?.map(|x| {
                    let event = x.map_err(|e| Error::ExtDB(e.to_string()))?;

                    let patch = if let Some(patch) = event.patch {
                        Some(Value::from_str(&patch).map_err(|e| Error::ExtDB(format!("Can not convert patch into Value: {}", e)))?)
                    } else {
                        None
                    };

                    let error =  if let Some(error) = event.error {
                        Some(serde_json::from_str(&error).map_err(|e| Error::ExtDB(format!("Can not convert patch into Value: {}", e)))?)
                    } else {
                        None
                    };
                    Ok(EventInfo { subject_id: event.subject_id, sn: event.sn, patch, error, event_req: serde_json::from_str(&event.event_req).map_err(|e| Error::ExtDB(format!("Can not convert event_req into EventRequestInfo: {}", e)))?, succes: event.succes })
                }).collect::<std::result::Result<Vec<EventInfo>, Error>>()?;

            let prev = if page <= 1 { None } else { Some(page - 1) };

            let next = if page < pages { Some(page + 1) } else { None };
            let paginator = Paginator { pages, next, prev };

            Ok(PaginatorEvents { paginator, events })
        } else {
            return Err(Error::ExtDB(
                "Can not lock mutex connection with DB".to_owned(),
            ));
        }
    }

    async fn get_events_sn(
        &self,
        subject_id: &str,
        sn: u64,
    ) -> Result<EventInfo, Error> {
        let subject_id = subject_id.to_owned();

        let event = {
            if let Ok(conn) = self.conn.lock() {
                let sql =
                    "SELECT * FROM events WHERE subject_id = ?1 AND sn = ?2";

                conn.query_row(sql, params![subject_id, sn], |row| {
                    Ok(EventDB {
                        subject_id: row.get(0)?,
                        sn: row.get(1)?,
                        patch: row.get(2)?,
                        error: row.get(3)?,
                        event_req: row.get(4)?,
                        succes: row.get(5)?,
                    })
                })
                .map_err(|e| Error::ExtDB(e.to_string()))?
            } else {
                return Err(Error::ExtDB(
                    "Can not lock mutex connection with DB".to_owned(),
                ));
            }
        };

        let patch = if let Some(patch) = event.patch {
            Some(Value::from_str(&patch).map_err(|e| {
                Error::ExtDB(format!("Can not convert patch into Value: {}", e))
            })?)
        } else {
            None
        };

        let error = if let Some(error) = event.error {
            Some(serde_json::from_str(&error).map_err(|e| {
                Error::ExtDB(format!("Can not convert patch into Value: {}", e))
            })?)
        } else {
            None
        };

        Ok(EventInfo {
            subject_id: event.subject_id,
            sn: event.sn,
            patch,
            error,
            event_req: serde_json::from_str(&event.event_req).map_err(|e| {
                Error::ExtDB(format!(
                    "Can not convert event_req into EventRequestInfo: {}",
                    e
                ))
            })?,
            succes: event.succes,
        })
    }

    async fn get_first_or_end_events(
        &self,
        subject_id: &str,
        quantity: Option<u64>,
        reverse: Option<bool>,
        sucess: Option<bool>,
    ) -> Result<Vec<EventInfo>, Error> {
        let subject_id = subject_id.to_owned();
        let mut quantity = quantity.unwrap_or(50);
        if quantity == 0 {
            quantity = 1;
        }
        let reverse = reverse.unwrap_or_default();
        let order = if reverse { "DESC" } else { "ASC" };
        let sucess_condition = if let Some(sucess_value) = sucess {
            format!("AND succes = {}", if sucess_value { 1 } else { 0 })
        } else {
            String::default()
        };

        if let Ok(conn) = self.conn.lock() {
            let sql = format!(
                "SELECT * FROM events WHERE subject_id = ?1 {} ORDER BY sn {} LIMIT ?2",
                sucess_condition, order
            );

            let mut stmt = conn
                .prepare(&sql)
                .map_err(|e| Error::ExtDB(e.to_string()))?;

            stmt.query_map(params![subject_id, quantity], |row| {
                Ok(EventDB {
                    subject_id: row.get(0)?,
                    sn: row.get(1)?,
                    patch: row.get(2)?,
                    error: row.get(3)?,
                    event_req: row.get(4)?,
                    succes: row.get(5)?,
                })
            }).map_err(|e| Error::ExtDB(e.to_string()))?.map(|x| {
                let event = x.map_err(|e| Error::ExtDB(e.to_string()))?;

                let patch = if let Some(patch) = event.patch {
                    Some(Value::from_str(&patch).map_err(|e| Error::ExtDB(format!("Can not convert patch into Value: {}", e)))?)
                } else {
                    None
                };

                let error =  if let Some(error) = event.error {
                    Some(serde_json::from_str(&error).map_err(|e| Error::ExtDB(format!("Can not convert patch into Value: {}", e)))?)
                } else {
                    None
                };
                Ok(EventInfo { subject_id: event.subject_id, sn: event.sn, patch, error, event_req: serde_json::from_str(&event.event_req).map_err(|e| Error::ExtDB(format!("Can not convert event_req into EventRequestInfo: {}", e)))?, succes: event.succes })
            }).collect::<std::result::Result<Vec<EventInfo>, Error>>()
        } else {
            return Err(Error::ExtDB(
                "Can not lock mutex connection with DB".to_owned(),
            ));
        }
    }
}

impl SqliteLocal {
    pub async fn new(
        path: &PathBuf,
        manager: ActorRef<DBManager>,
    ) -> Result<Self, Error> {
        let flags = OpenFlags::default();
        let conn = Connection::open_with_flags(path, flags).map_err(|e| {
            Error::ExtDB(format!("SQLite fail open connection: {}", e))
        })?;

        // Run database migrations
        let migration_001 =
            include_str!("../../../migrations/001_initial_schema.sql");
        conn.execute_batch(migration_001).map_err(|e| {
            Error::ExtDB(format!("Migration 001 failed: {}", e))
        })?;

        Ok(SqliteLocal {
            conn: Arc::new(Mutex::new(conn)),
            manager,
        })
    }
}

#[async_trait]
impl Subscriber<ApproverEvent> for SqliteLocal {
    async fn notify(&self, event: ApproverEvent) {
        match event {
            ApproverEvent::ChangeState { subject_id, state } => {
                let response = state.to_string();

                if let Ok(conn) = self.conn.lock() {
                    let sql =
                        "UPDATE approval SET state = ?1 WHERE subject_id = ?2";

                    let _ = conn.execute(sql, params![response, subject_id]).map_err(async |e| {
                        let e = Error::ExtDB(format!("Can not update approval: {}", e));
                        error!(TARGET_SQLITE, "Subscriber<ApproverEvent> ApproverEvent::ChangeState: {}", e);
                        if let Err(e) = self.manager.tell(DBManagerMessage::Error(e)).await
                        {
                            error!(
                                TARGET_SQLITE,
                                "Can no send message to DBManager actor: {}", e
                            );
                        }
                    });
                } else {
                    let e = Error::ExtDB(
                        "Can not lock mutex connection with DB".to_owned(),
                    );
                    error!(
                        TARGET_SQLITE,
                        "Subscriber<ApproverEvent> ApproverEvent::ChangeState: {}",
                        e
                    );
                    if let Err(e) =
                        self.manager.tell(DBManagerMessage::Error(e)).await
                    {
                        error!(
                            TARGET_SQLITE,
                            "Can no send message to DBManager actor: {}", e
                        );
                    }
                }
            }
            ApproverEvent::SafeState {
                subject_id,
                request,
                state,
                ..
            } => {
                let Ok(request) = serde_json::to_string(&request) else {
                    let e = Error::ExtDB(
                        "Can not Serialize request as String".to_owned(),
                    );
                    error!(
                        TARGET_SQLITE,
                        "Subscriber<ApproverEvent> ApproverEvent::SafeState: {}",
                        e
                    );
                    if let Err(e) =
                        self.manager.tell(DBManagerMessage::Error(e)).await
                    {
                        error!(
                            TARGET_SQLITE,
                            "Can no send message to DBManager actor: {}", e
                        );
                    }
                    return;
                };

                if let Ok(conn) = self.conn.lock() {
                    let sql = "INSERT OR REPLACE INTO approval (subject_id, data, state) VALUES (?1, ?2, ?3)";

                    let _ = conn.execute(sql, params![subject_id, request, state.to_string()]).map_err(async |e| {
                        let e = Error::ExtDB(format!("Can not update approval: {}", e));
                        error!(TARGET_SQLITE, "Subscriber<ApproverEvent> ApproverEvent::SafeState: {}", e);
                        if let Err(e) = self.manager.tell(DBManagerMessage::Error(e)).await
                        {
                            error!(
                                TARGET_SQLITE,
                                "Can no send message to DBManager actor: {}", e
                            );
                        }
                    });
                } else {
                    let e = Error::ExtDB(
                        "Can not lock mutex connection with DB".to_owned(),
                    );
                    error!(
                        TARGET_SQLITE,
                        "Subscriber<ApproverEvent> ApproverEvent::SafeState: {}",
                        e
                    );
                    if let Err(e) =
                        self.manager.tell(DBManagerMessage::Error(e)).await
                    {
                        error!(
                            TARGET_SQLITE,
                            "Can no send message to DBManager actor: {}", e
                        );
                    }
                }
            }
        }
    }
}

#[async_trait]
impl Subscriber<LastStateEvent> for SqliteLocal {
    async fn notify(&self, event: LastStateEvent) {
        let sn = event.event.content().sn;
        let subject_id = event.event.content().subject_id.to_string();

        let sig_eval = if let Some(sig_eval) = event.event.content().evaluators
        {
            let Ok(sig_eval) = serde_json::to_string(&sig_eval) else {
                let e = Error::ExtDB(
                    "Can not Serialize evaluators as String".to_owned(),
                );
                error!(TARGET_SQLITE, "Subscriber<LedgerEventEvent>: {}", e);
                if let Err(e) =
                    self.manager.tell(DBManagerMessage::Error(e)).await
                {
                    error!(
                        TARGET_SQLITE,
                        "Can no send message to DBManager actor: {}", e
                    );
                }
                return;
            };

            Some(sig_eval)
        } else {
            None
        };

        let sig_appr = if let Some(sig_appr) = event.event.content().approvers {
            let Ok(sig_appr) = serde_json::to_string(&sig_appr) else {
                let e = Error::ExtDB(
                    "Can not Serialize approvers as String".to_owned(),
                );
                error!(TARGET_SQLITE, "Subscriber<LedgerEventEvent>: {}", e);
                if let Err(e) =
                    self.manager.tell(DBManagerMessage::Error(e)).await
                {
                    error!(
                        TARGET_SQLITE,
                        "Can no send message to DBManager actor: {}", e
                    );
                }
                return;
            };

            Some(sig_appr)
        } else {
            None
        };

        let Ok(sig_vali) =
            serde_json::to_string(&event.event.content().validators)
        else {
            let e = Error::ExtDB(
                "Can not Serialize validators as String".to_owned(),
            );
            error!(TARGET_SQLITE, "Subscriber<LedgerEventEvent>: {}", e);
            if let Err(e) = self.manager.tell(DBManagerMessage::Error(e)).await
            {
                error!(
                    TARGET_SQLITE,
                    "Can no send message to DBManager actor: {}", e
                );
            }
            return;
        };

        if let Ok(conn) = self.conn.lock() {
            let sql = "INSERT OR REPLACE INTO signatures (subject_id, sn, signatures_eval, signatures_appr, signatures_vali) VALUES (?1, ?2, ?3, ?4, ?5)";

            let _ = conn
                .execute(
                    sql,
                    params![subject_id, sn, sig_eval, sig_appr, sig_vali],
                )
                .map_err(async |e| {
                    let e = Error::ExtDB(format!(
                        "Can not update signatures: {}",
                        e
                    ));
                    error!(
                        TARGET_SQLITE,
                        "Subscriber<LedgerEventEvent>: {}", e
                    );
                    if let Err(e) =
                        self.manager.tell(DBManagerMessage::Error(e)).await
                    {
                        error!(
                            TARGET_SQLITE,
                            "Can no send message to DBManager actor: {}", e
                        );
                    }
                });
        } else {
            let e = Error::ExtDB(
                "Can not lock mutex connection with DB".to_owned(),
            );
            error!(TARGET_SQLITE, "Subscriber<LedgerEventEvent>: {}", e);
            if let Err(e) = self.manager.tell(DBManagerMessage::Error(e)).await
            {
                error!(
                    TARGET_SQLITE,
                    "Can no send message to DBManager actor: {}", e
                );
            }
        }
    }
}

#[async_trait]
impl Subscriber<SignedLedger> for SqliteLocal {
    async fn notify(&self, event: SignedLedger) {
        let subject_id = event.content().subject_id.to_string();
        let sn = event.content().sn;
        let succes: i32;
        let Ok(event_req) = serde_json::to_string(&json!(
            event.content().event_request.content
        )) else {
            let e = Error::ExtDB(
                "Can not Serialize protocols_error as String".to_owned(),
            );
            error!(TARGET_SQLITE, "Subscriber<Signed<Ledger>>: {}", e);
            if let Err(e) = self.manager.tell(DBManagerMessage::Error(e)).await
            {
                error!(
                    TARGET_SQLITE,
                    "Can no send message to DBManager actor: {}", e
                );
            }
            return;
        };
        let (patch, error): (Option<String>, Option<String>) =
            match event.content().value.clone() {
                LedgerValue::Patch(value_wrapper) => {
                    succes = 1;
                    (Some(value_wrapper.0.to_string()), None)
                }
                LedgerValue::Error(protocols_error) => {
                    let Ok(string) = serde_json::to_string(&protocols_error)
                    else {
                        let e = Error::ExtDB(
                            "Can not Serialize protocols_error as String"
                                .to_owned(),
                        );
                        error!(
                            TARGET_SQLITE,
                            "Subscriber<Signed<Ledger>> LedgerValue::Error: {}",
                            e
                        );
                        if let Err(e) =
                            self.manager.tell(DBManagerMessage::Error(e)).await
                        {
                            error!(
                                TARGET_SQLITE,
                                "Can no send message to DBManager actor: {}", e
                            );
                        }
                        return;
                    };
                    succes = 0;
                    (None, Some(string))
                }
            };

        if let Ok(conn) = self.conn.lock() {
            let sql = "INSERT INTO events (subject_id, sn, patch, error, event_req, succes) VALUES (?1, ?2, ?3, ?4, ?5, ?6)";

            let _ = conn
                .execute(
                    sql,
                    params![subject_id, sn, patch, error, event_req, succes],
                )
                .map_err(async |e| {
                    let e =
                        Error::ExtDB(format!("Can not update events: {}", e));
                    error!(TARGET_SQLITE, "Subscriber<Signed<Ledger>>: {}", e);
                    if let Err(e) =
                        self.manager.tell(DBManagerMessage::Error(e)).await
                    {
                        error!(
                            TARGET_SQLITE,
                            "Can no send message to DBManager actor: {}", e
                        );
                    }
                });
        } else {
            let e = Error::ExtDB(
                "Can not lock mutex connection with DB".to_owned(),
            );
            if let Err(e) = self.manager.tell(DBManagerMessage::Error(e)).await
            {
                error!(
                    TARGET_SQLITE,
                    "Can no send message to DBManager actor: {}", e
                );
            }
        }
    }
}

#[async_trait]
impl Subscriber<SinkDataEvent> for SqliteLocal {
    async fn notify(&self, event: SinkDataEvent) {
        let SinkDataMessage::UpdateState(metadata) = event.event else {
            return;
        };

        let name = metadata.name;
        let description = metadata.description;
        let subject_id = metadata.subject_id.to_string();
        let governance_id = metadata.governance_id.to_string();
        let genesis_gov_version = metadata.genesis_gov_version;
        let namespace = metadata.namespace.to_string();
        let schema_id = metadata.schema_id.to_string();
        let owner = metadata.owner.to_string();
        let creator = metadata.creator.to_string();
        let active = metadata.active as i32;
        let sn = metadata.sn;
        let properties = metadata.properties.0.to_string();
        let new_owner =
            metadata.new_owner.map(|new_owner| new_owner.to_string());

        if let Ok(conn) = self.conn.lock() {
            let sql = "INSERT OR REPLACE INTO subjects (name, description, subject_id, governance_id, genesis_gov_version, namespace, schema_id, owner, creator, active, sn, properties, new_owner) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13)";

            let _ = conn
                .execute(
                    sql,
                    params![
                        name,
                        description,
                        subject_id,
                        governance_id,
                        genesis_gov_version,
                        namespace,
                        schema_id,
                        owner,
                        creator,
                        active,
                        sn,
                        properties,
                        new_owner
                    ],
                )
                .map_err(async |e| {
                    let e =
                        Error::ExtDB(format!("Can not update subject: {}", e));
                    error!(TARGET_SQLITE, "Subscriber<SinkDataEvent>: {}", e);
                    if let Err(e) =
                        self.manager.tell(DBManagerMessage::Error(e)).await
                    {
                        error!(
                            TARGET_SQLITE,
                            "Can no send message to DBManager actor: {}", e
                        );
                    }
                });
        } else {
            let e = Error::ExtDB(
                "Can not lock mutex connection with DB".to_owned(),
            );
            error!(TARGET_SQLITE, "Subscriber<SinkDataEvent>: {}", e);
            if let Err(e) = self.manager.tell(DBManagerMessage::Error(e)).await
            {
                error!(
                    TARGET_SQLITE,
                    "Can no send message to DBManager actor: {}", e
                );
            }
        }
    }
}
