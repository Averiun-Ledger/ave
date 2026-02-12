use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use ave_actors::{ActorRef, Subscriber};
use ave_common::bridge::request::EventRequestType;
use ave_common::response::{
    AbortDB, LedgerDB, Paginator, PaginatorAborts, PaginatorEvents,
    RequestEventDB, SubjectDB, TimeRange,
};
use rusqlite::types::Type;
use rusqlite::{Connection, OpenFlags, params};
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tracing::{debug, error};

use super::{DatabaseError, Querys};
use crate::external_db::{DBManager, DBManagerMessage};
use crate::request::tracking::RequestTrackingEvent;
use crate::subject::sinkdata::SinkDataEvent;
use crate::subject::{Metadata, SignedLedger};

/// Serializes an `EventRequestType` to its serde string representation.
fn event_request_type_to_string(et: &EventRequestType) -> Result<String, DatabaseError> {
    match serde_json::to_value(et) {
        Ok(Value::String(s)) => Ok(s),
        _ => Err(DatabaseError::JsonSerialize(
            "Failed to serialize EventRequestType".to_owned(),
        )),
    }
}

/// Parses an ISO 8601 string and converts it to nanoseconds (i64 for SQLite).
fn parse_iso8601_to_nanos(s: &str) -> Result<i64, DatabaseError> {
    let dt = OffsetDateTime::parse(s, &Rfc3339).map_err(|e| {
        DatabaseError::DateTimeParse(format!(
            "Invalid ISO 8601 date '{}': {}",
            s, e
        ))
    })?;
    let nanos = dt.unix_timestamp_nanos();
    i64::try_from(nanos).map_err(|_| {
        DatabaseError::IntegerConversion(format!(
            "Timestamp nanoseconds out of range for i64: {}",
            nanos
        ))
    })
}

#[derive(Clone)]
pub struct SqliteLocal {
    manager: ActorRef<DBManager>,
    conn: Arc<Mutex<Connection>>,
}

#[async_trait]
impl Querys for SqliteLocal {
    async fn get_aborts(
        &self,
        subject_id: &str,
        request_id: Option<String>,
        sn: Option<u64>,
        quantity: Option<u64>,
        page: Option<u64>,
        reverse: Option<bool>,
    ) -> Result<PaginatorAborts, DatabaseError> {
        let quantity = quantity.unwrap_or(50).max(1);
        let mut page = page.unwrap_or(1).max(1);

        // Build WHERE clauses and parameters
        let mut where_clauses = vec!["subject_id = ?1".to_string()];
        let mut params_values: Vec<rusqlite::types::Value> =
            vec![subject_id.to_string().into()];

        if let Some(rid) = request_id {
            params_values.push(rid.into());
            where_clauses
                .push(format!("request_id = ?{}", params_values.len()));
        }

        if let Some(sn_val) = sn {
            let sn_i64 = i64::try_from(sn_val).map_err(|_| {
                DatabaseError::IntegerConversion(format!(
                    "sn out of range for SQLite INTEGER (i64): {sn_val}"
                ))
            })?;
            params_values.push(sn_i64.into());
            where_clauses.push(format!("sn = ?{}", params_values.len()));
        }

        let where_sql = where_clauses.join(" AND ");

        let conn = self.conn.lock().map_err(|_| DatabaseError::MutexLock)?;

        // Count query with filters
        let count_sql =
            format!("SELECT COUNT(*) FROM aborts WHERE {}", where_sql);
        let params_refs: Vec<&dyn rusqlite::ToSql> = params_values
            .iter()
            .map(|v| v as &dyn rusqlite::ToSql)
            .collect();

        let total_i64: i64 = conn
            .query_row(&count_sql, params_refs.as_slice(), |row| row.get(0))
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        let total = u64::try_from(total_i64).map_err(|_| {
            DatabaseError::IntegerConversion(
                "COUNT(*) returned invalid value".to_owned(),
            )
        })?;

        if total == 0 {
            return Ok(PaginatorAborts {
                paginator: Paginator {
                    pages: 0,
                    next: None,
                    prev: None,
                },
                events: vec![],
            });
        }

        let mut pages = (total + quantity - 1) / quantity;
        if pages == 0 {
            pages = 1;
        }
        if page > pages {
            page = pages;
        }

        let offset = (page - 1) * quantity;

        let order_clause = if reverse.unwrap_or(false) {
            "sn DESC"
        } else {
            "sn ASC"
        };

        let quantity_i64 = i64::try_from(quantity).map_err(|_| {
            DatabaseError::IntegerConversion(format!(
                "quantity out of range for SQLite INTEGER (i64): {quantity}"
            ))
        })?;
        let offset_i64 = i64::try_from(offset).map_err(|_| {
            DatabaseError::IntegerConversion(format!(
                "offset out of range for SQLite INTEGER (i64): {offset}"
            ))
        })?;

        // Add LIMIT and OFFSET params
        params_values.push(quantity_i64.into());
        let limit_idx = params_values.len();
        params_values.push(offset_i64.into());
        let offset_idx = params_values.len();

        let sql = format!(
            r#"
            SELECT request_id, subject_id, sn, error, who, abort_type
            FROM aborts
            WHERE {}
            ORDER BY {}
            LIMIT ?{} OFFSET ?{}
            "#,
            where_sql, order_clause, limit_idx, offset_idx
        );

        let params_refs: Vec<&dyn rusqlite::ToSql> = params_values
            .iter()
            .map(|v| v as &dyn rusqlite::ToSql)
            .collect();

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        let aborts: Vec<AbortDB> = stmt
            .query_map(params_refs.as_slice(), |row| {
                let sn_opt: Option<i64> = row.get(2)?;
                let sn = sn_opt
                    .map(|v| {
                        u64::try_from(v).map_err(|e| {
                            rusqlite::Error::FromSqlConversionFailure(
                                2,
                                Type::Integer,
                                Box::new(e),
                            )
                        })
                    })
                    .transpose()?;

                Ok(AbortDB {
                    request_id: row.get(0)?,
                    subject_id: row.get(1)?,
                    sn,
                    error: row.get(3)?,
                    who: row.get(4)?,
                    abort_type: row.get(5)?,
                })
            })
            .map_err(|e| DatabaseError::Query(e.to_string()))?
            .map(|r| r.map_err(|e| DatabaseError::Query(e.to_string())))
            .collect::<Result<Vec<_>, DatabaseError>>()?;

        let prev = if page <= 1 { None } else { Some(page - 1) };
        let next = if page < pages { Some(page + 1) } else { None };
        let paginator = Paginator { pages, next, prev };

        Ok(PaginatorAborts {
            paginator,
            events: aborts,
        })
    }

    async fn get_subject_state(
        &self,
        subject_id: &str,
    ) -> Result<SubjectDB, DatabaseError> {
        let subject_id = subject_id.to_owned();

        let subject: SubjectDB = {
            let conn =
                self.conn.lock().map_err(|_| DatabaseError::MutexLock)?;

            let sql = r#"
            SELECT
                name, description, subject_id, governance_id, genesis_gov_version,
                prev_ledger_event_hash, schema_id, namespace, sn,
                creator, owner, new_owner, active, properties
            FROM subjects
            WHERE subject_id = ?1
        "#;

            conn.query_row(sql, params![subject_id], |row| {
                let props_str: String = row.get(13)?;
                let props_val: Value = serde_json::from_str(&props_str)
                    .map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            13,
                            Type::Text,
                            Box::new(e),
                        )
                    })?;

                let genesis_gov_version =
                    u64::try_from(row.get::<usize, i64>(4)?).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            4,
                            Type::Integer,
                            Box::new(e),
                        )
                    })?;
                let sn =
                    u64::try_from(row.get::<usize, i64>(8)?).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            8,
                            Type::Integer,
                            Box::new(e),
                        )
                    })?;

                Ok(SubjectDB {
                    name: row.get(0)?,
                    description: row.get(1)?,
                    subject_id: row.get(2)?,
                    governance_id: row.get(3)?,
                    genesis_gov_version,
                    prev_ledger_event_hash: row.get(5)?,
                    schema_id: row.get(6)?,
                    namespace: row.get(7)?,
                    sn,
                    creator: row.get(9)?,
                    owner: row.get(10)?,
                    new_owner: row.get(11)?,
                    active: row.get::<usize, i64>(12)? != 0,
                    properties: props_val,
                })
            })
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => {
                    DatabaseError::SubjectNotFound(subject_id.clone())
                }
                _ => DatabaseError::Query(e.to_string()),
            })?
        };

        Ok(subject)
    }

    async fn get_events(
        &self,
        subject_id: &str,
        quantity: Option<u64>,
        page: Option<u64>,
        reverse: Option<bool>,
        event_request_ts: Option<TimeRange>,
        event_ledger_ts: Option<TimeRange>,
        sink_ts: Option<TimeRange>,
        event_type: Option<EventRequestType>
    ) -> Result<PaginatorEvents, DatabaseError> {
        let quantity = quantity.unwrap_or(50).max(1);
        let mut page = page.unwrap_or(1).max(1);

        // Build WHERE clauses and parameters for timestamp filters
        let mut where_clauses = vec!["subject_id = ?1".to_string()];
        let mut params_values: Vec<rusqlite::types::Value> =
            vec![subject_id.to_string().into()];

        // Helper to add timestamp range filters
        let mut add_ts_filter = |col: &str,
                                 range: Option<TimeRange>|
         -> Result<(), DatabaseError> {
            if let Some(r) = range {
                if let Some(from) = r.from {
                    let nanos = parse_iso8601_to_nanos(&from)?;
                    params_values.push(nanos.into());
                    where_clauses.push(format!(
                        "{} >= ?{}",
                        col,
                        params_values.len()
                    ));
                }
                if let Some(to) = r.to {
                    let nanos = parse_iso8601_to_nanos(&to)?;
                    params_values.push(nanos.into());
                    where_clauses.push(format!(
                        "{} <= ?{}",
                        col,
                        params_values.len()
                    ));
                }
            }
            Ok(())
        };

        add_ts_filter("event_request_timestamp", event_request_ts)?;
        add_ts_filter("event_ledger_timestamp", event_ledger_ts)?;
        add_ts_filter("sink_timestamp", sink_ts)?;

        if let Some(et) = event_type {
            params_values.push(event_request_type_to_string(&et)?.into());
            where_clauses
                .push(format!("event_type = ?{}", params_values.len()));
        }

        let where_sql = where_clauses.join(" AND ");

        let conn = self.conn.lock().map_err(|_| DatabaseError::MutexLock)?;

        // Count query with filters
        let count_sql =
            format!("SELECT COUNT(*) FROM events WHERE {}", where_sql);
        let params_refs: Vec<&dyn rusqlite::ToSql> = params_values
            .iter()
            .map(|v| v as &dyn rusqlite::ToSql)
            .collect();

        let total_i64: i64 = conn
            .query_row(&count_sql, params_refs.as_slice(), |row| row.get(0))
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        let total = u64::try_from(total_i64).map_err(|_| {
            DatabaseError::IntegerConversion(
                "COUNT(*) returned invalid value".to_owned(),
            )
        })?;

        if total == 0 {
            return Err(DatabaseError::NoEvents(subject_id.to_owned()));
        }

        let mut pages = (total + quantity - 1) / quantity;
        if pages == 0 {
            pages = 1;
        }
        if page > pages {
            page = pages;
        }

        let offset = (page - 1) * quantity;

        let order_clause = if reverse.unwrap_or(false) {
            "sn DESC"
        } else {
            "sn ASC"
        };

        let quantity_i64 = i64::try_from(quantity).map_err(|_| {
            DatabaseError::IntegerConversion(format!(
                "quantity out of range for SQLite INTEGER (i64): {quantity}"
            ))
        })?;
        let offset_i64 = i64::try_from(offset).map_err(|_| {
            DatabaseError::IntegerConversion(format!(
                "offset out of range for SQLite INTEGER (i64): {offset}"
            ))
        })?;

        // Add LIMIT and OFFSET params
        params_values.push(quantity_i64.into());
        let limit_idx = params_values.len();
        params_values.push(offset_i64.into());
        let offset_idx = params_values.len();

        let sql = format!(
            r#"
        SELECT
            subject_id, sn, event_request_timestamp, event_ledger_timestamp, sink_timestamp, event, event_type
        FROM events
        WHERE {}
        ORDER BY {}
        LIMIT ?{} OFFSET ?{}
        "#,
            where_sql, order_clause, limit_idx, offset_idx
        );

        let params_refs: Vec<&dyn rusqlite::ToSql> = params_values
            .iter()
            .map(|v| v as &dyn rusqlite::ToSql)
            .collect();

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        let events: Vec<LedgerDB> = stmt
            .query_map(params_refs.as_slice(), |row| {
                let event_str: String = row.get(5)?;
                let event: RequestEventDB = serde_json::from_str(&event_str)
                    .map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            5,
                            Type::Text,
                            Box::new(e),
                        )
                    })?;

                let sn =
                    u64::try_from(row.get::<usize, i64>(1)?).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            Type::Integer,
                            Box::new(e),
                        )
                    })?;
                let event_request_timestamp =
                    u64::try_from(row.get::<usize, i64>(2)?).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            2,
                            Type::Integer,
                            Box::new(e),
                        )
                    })?;
                let event_ledger_timestamp =
                    u64::try_from(row.get::<usize, i64>(3)?).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            3,
                            Type::Integer,
                            Box::new(e),
                        )
                    })?;
                let sink_timestamp = u64::try_from(row.get::<usize, i64>(4)?)
                    .map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        4,
                        Type::Integer,
                        Box::new(e),
                    )
                })?;

                let event_type_str: String = row.get(6)?;
                let event_type: EventRequestType =
                    serde_json::from_value(Value::String(
                        event_type_str,
                    ))
                    .map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            6,
                            Type::Text,
                            Box::new(e),
                        )
                    })?;

                Ok(LedgerDB {
                    subject_id: row.get(0)?,
                    sn,
                    event_request_timestamp,
                    event_ledger_timestamp,
                    sink_timestamp,
                    event,
                    event_type,
                })
            })
            .map_err(|e| DatabaseError::Query(e.to_string()))?
            .map(|r| r.map_err(|e| DatabaseError::Query(e.to_string())))
            .collect::<Result<Vec<_>, DatabaseError>>()?;

        let prev = if page <= 1 { None } else { Some(page - 1) };
        let next = if page < pages { Some(page + 1) } else { None };
        let paginator = Paginator { pages, next, prev };

        Ok(PaginatorEvents { paginator, events })
    }

    async fn get_event_sn(
        &self,
        subject_id: &str,
        sn: u64,
    ) -> Result<LedgerDB, DatabaseError> {
        let conn = self.conn.lock().map_err(|_| DatabaseError::MutexLock)?;

        let sn_i64 = i64::try_from(sn).map_err(|_| {
            DatabaseError::IntegerConversion(format!(
                "sn out of range for SQLite INTEGER (i64): {sn}"
            ))
        })?;

        let sql = r#"
        SELECT
            subject_id, sn, event_request_timestamp, event_ledger_timestamp, sink_timestamp, event, event_type
        FROM events
        WHERE subject_id = ?1 AND sn = ?2
    "#;

        let ledger = conn
            .query_row(sql, params![subject_id, sn_i64], |row| {
                let event_str: String = row.get(5)?;
                let event: RequestEventDB = serde_json::from_str(&event_str)
                    .map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            5,
                            Type::Text,
                            Box::new(e),
                        )
                    })?;

                let sn =
                    u64::try_from(row.get::<usize, i64>(1)?).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            Type::Integer,
                            Box::new(e),
                        )
                    })?;
                let event_request_timestamp =
                    u64::try_from(row.get::<usize, i64>(2)?).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            2,
                            Type::Integer,
                            Box::new(e),
                        )
                    })?;
                let event_ledger_timestamp =
                    u64::try_from(row.get::<usize, i64>(3)?).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            3,
                            Type::Integer,
                            Box::new(e),
                        )
                    })?;
                let sink_timestamp = u64::try_from(row.get::<usize, i64>(4)?)
                    .map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        4,
                        Type::Integer,
                        Box::new(e),
                    )
                })?;

                let event_type_str: String = row.get(6)?;
                let event_type: EventRequestType =
                    serde_json::from_value(Value::String(
                        event_type_str,
                    ))
                    .map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            6,
                            Type::Text,
                            Box::new(e),
                        )
                    })?;

                Ok(LedgerDB {
                    subject_id: row.get(0)?,
                    sn,
                    event_request_timestamp,
                    event_ledger_timestamp,
                    sink_timestamp,
                    event,
                    event_type,
                })
            })
            .map_err(|e| match e {
                rusqlite::Error::QueryReturnedNoRows => {
                    DatabaseError::EventNotFound {
                        subject_id: subject_id.to_owned(),
                        sn,
                    }
                }
                _ => DatabaseError::Query(e.to_string()),
            })?;

        Ok(ledger)
    }

    async fn get_first_or_end_events(
        &self,
        subject_id: &str,
        quantity: Option<u64>,
        reverse: Option<bool>,
        event_type: Option<EventRequestType>
    ) -> Result<Vec<LedgerDB>, DatabaseError> {
        let quantity = quantity.unwrap_or(50).max(1);
        let reverse = reverse.unwrap_or(false);
        let order = if reverse { "DESC" } else { "ASC" };

        let conn = self.conn.lock().map_err(|_| DatabaseError::MutexLock)?;

        let limit_i64 = i64::try_from(quantity).map_err(|_| {
            DatabaseError::IntegerConversion(format!(
                "quantity out of range for SQLite INTEGER (i64): {quantity}"
            ))
        })?;

        let mut where_clauses = vec!["subject_id = ?1".to_string()];
        let mut params_values: Vec<rusqlite::types::Value> =
            vec![subject_id.to_string().into()];

        if let Some(et) = event_type {
            params_values.push(event_request_type_to_string(&et)?.into());
            where_clauses
                .push(format!("event_type = ?{}", params_values.len()));
        }

        let where_sql = where_clauses.join(" AND ");

        params_values.push(limit_i64.into());
        let limit_idx = params_values.len();

        let sql = format!(
            r#"
        SELECT
            subject_id, sn, event_request_timestamp, event_ledger_timestamp, sink_timestamp, event, event_type
        FROM events
        WHERE {}
        ORDER BY sn {}
        LIMIT ?{}
        "#,
            where_sql, order, limit_idx
        );

        let params_refs: Vec<&dyn rusqlite::ToSql> = params_values
            .iter()
            .map(|v| v as &dyn rusqlite::ToSql)
            .collect();

        let mut stmt = conn
            .prepare(&sql)
            .map_err(|e| DatabaseError::Query(e.to_string()))?;

        let events: Vec<LedgerDB> = stmt
            .query_map(params_refs.as_slice(), |row| {
                let event_str: String = row.get(5)?;
                let event: RequestEventDB = serde_json::from_str(&event_str)
                    .map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            5,
                            Type::Text,
                            Box::new(e),
                        )
                    })?;

                let sn =
                    u64::try_from(row.get::<usize, i64>(1)?).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            1,
                            Type::Integer,
                            Box::new(e),
                        )
                    })?;
                let event_request_timestamp =
                    u64::try_from(row.get::<usize, i64>(2)?).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            2,
                            Type::Integer,
                            Box::new(e),
                        )
                    })?;
                let event_ledger_timestamp =
                    u64::try_from(row.get::<usize, i64>(3)?).map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            3,
                            Type::Integer,
                            Box::new(e),
                        )
                    })?;
                let sink_timestamp = u64::try_from(row.get::<usize, i64>(4)?)
                    .map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        4,
                        Type::Integer,
                        Box::new(e),
                    )
                })?;

                let event_type_str: String = row.get(6)?;
                let event_type: EventRequestType =
                    serde_json::from_value(Value::String(
                        event_type_str,
                    ))
                    .map_err(|e| {
                        rusqlite::Error::FromSqlConversionFailure(
                            6,
                            Type::Text,
                            Box::new(e),
                        )
                    })?;

                Ok(LedgerDB {
                    subject_id: row.get(0)?,
                    sn,
                    event_request_timestamp,
                    event_ledger_timestamp,
                    sink_timestamp,
                    event,
                    event_type,
                })
            })
            .map_err(|e| DatabaseError::Query(e.to_string()))?
            .map(|r| r.map_err(|e| DatabaseError::Query(e.to_string())))
            .collect::<Result<Vec<_>, DatabaseError>>()?;

        Ok(events)
    }
}

impl SqliteLocal {
    pub async fn new(
        path: &PathBuf,
        manager: ActorRef<DBManager>,
    ) -> Result<Self, DatabaseError> {
        let flags = OpenFlags::default();
        let conn = Connection::open_with_flags(path, flags).map_err(|e| {
            error!(
                path = %path.display(),
                error = %e,
                "Failed to open SQLite database connection"
            );
            DatabaseError::ConnectionOpen(e.to_string())
        })?;

        let migration_001 =
            include_str!("../../../migrations/001_initial_schema.sql");
        conn.execute_batch(migration_001).map_err(|e| {
            error!(
                path = %path.display(),
                error = %e,
                "Failed to run SQLite migrations"
            );
            DatabaseError::Migration(e.to_string())
        })?;

        debug!(
            path = %path.display(),
            "SQLite database connection established and migrations applied"
        );

        Ok(SqliteLocal {
            conn: Arc::new(Mutex::new(conn)),
            manager,
        })
    }
}

impl SqliteLocal {
    async fn save_signed_ledger(
        &self,
        event: &SignedLedger,
    ) -> Result<(), DatabaseError> {
        let event_db = event
            .content()
            .build_ledger_db(event.signature().timestamp.as_nanos());

        let sn_i64 = i64::try_from(event_db.sn).map_err(|_| {
            DatabaseError::IntegerConversion(format!(
                "sn out of range for SQLite INTEGER (i64): {}",
                event_db.sn
            ))
        })?;
        let req_ts_i64 = i64::try_from(event_db.event_request_timestamp)
            .map_err(|_| {
                DatabaseError::IntegerConversion(format!(
                    "event_request_timestamp out of range for SQLite INTEGER (i64): {}",
                    event_db.event_request_timestamp
                ))
            })?;
        let ledger_ts_i64 = i64::try_from(event_db.event_ledger_timestamp)
            .map_err(|_| {
                DatabaseError::IntegerConversion(format!(
                    "event_ledger_timestamp out of range for SQLite INTEGER (i64): {}",
                    event_db.event_ledger_timestamp
                ))
            })?;
        let sink_timestamp_i64 = i64::try_from(event_db.sink_timestamp)
            .map_err(|_| {
                DatabaseError::IntegerConversion(format!(
                    "sink_timestamp out of range for SQLite INTEGER (i64): {}",
                    event_db.sink_timestamp
                ))
            })?;

        let event_json = serde_json::to_string(&event_db.event)
            .map_err(|e| DatabaseError::JsonSerialize(e.to_string()))?;

        let event_type_str = event_request_type_to_string(&event_db.event_type)?;

        let conn = self.conn.lock().map_err(|_| DatabaseError::MutexLock)?;

        conn.execute(
            r#"
        INSERT INTO events (
            subject_id, sn, event_request_timestamp, event_ledger_timestamp, sink_timestamp, event, event_type
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
        "#,
            params![
                event_db.subject_id,
                sn_i64,
                req_ts_i64,
                ledger_ts_i64,
                sink_timestamp_i64,
                event_json,
                event_type_str
            ],
        )
        .map_err(|e| DatabaseError::Query(e.to_string()))?;

        Ok(())
    }

    async fn save_subject_state(
        &self,
        metadata: &Metadata,
    ) -> Result<(), DatabaseError> {
        let prev_ledger_event_hash =
            if metadata.prev_ledger_event_hash.is_empty() {
                None
            } else {
                Some(metadata.prev_ledger_event_hash.to_string())
            };

        let s = SubjectDB {
            name: metadata.name.clone(),
            description: metadata.description.clone(),
            subject_id: metadata.subject_id.to_string(),
            governance_id: metadata.governance_id.to_string(),
            genesis_gov_version: metadata.genesis_gov_version,
            prev_ledger_event_hash,
            schema_id: metadata.schema_id.to_string(),
            namespace: metadata.namespace.to_string(),
            sn: metadata.sn,
            creator: metadata.creator.to_string(),
            owner: metadata.owner.to_string(),
            new_owner: metadata.new_owner.clone().map(|x| x.to_string()),
            active: metadata.active,
            properties: metadata.properties.0.clone(),
        };

        let properties_json = serde_json::to_string(&s.properties)
            .map_err(|e| DatabaseError::JsonSerialize(e.to_string()))?;

        let active = if s.active { 1 } else { 0 };

        let genesis_gov_version_i64 =
            i64::try_from(s.genesis_gov_version).map_err(|_| {
                DatabaseError::IntegerConversion(format!(
                    "genesis_gov_version out of range for SQLite INTEGER (i64): {}",
                    s.genesis_gov_version
                ))
            })?;
        let sn_i64 = i64::try_from(s.sn).map_err(|_| {
            DatabaseError::IntegerConversion(format!(
                "sn out of range for SQLite INTEGER (i64): {}",
                s.sn
            ))
        })?;

        let conn = self.conn.lock().map_err(|_| DatabaseError::MutexLock)?;

        conn.execute(
            r#"
        INSERT OR REPLACE INTO subjects (
            name, description, subject_id, governance_id, genesis_gov_version,
            prev_ledger_event_hash, schema_id, namespace, sn,
            creator, owner, new_owner, active, properties
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5,
            ?6, ?7, ?8, ?9,
            ?10, ?11, ?12, ?13, ?14
        )
        "#,
            params![
                s.name,
                s.description,
                s.subject_id,
                s.governance_id,
                genesis_gov_version_i64,
                s.prev_ledger_event_hash,
                s.schema_id,
                s.namespace,
                sn_i64,
                s.creator,
                s.owner,
                s.new_owner,
                active,
                properties_json
            ],
        )
        .map_err(|e| DatabaseError::Query(e.to_string()))?;

        Ok(())
    }

    async fn save_abort(
        &self,
        request_id: String,
        subject_id: String,
        sn: Option<u64>,
        error: String,
        who: String,
        abort_type: String
    ) -> Result<(), DatabaseError> {
        let conn = self.conn.lock().map_err(|_| DatabaseError::MutexLock)?;

        let sn_i64 = if let Some(sn) = sn {
            Some(i64::try_from(sn).map_err(|_| {
            DatabaseError::IntegerConversion(format!(
                "sn out of range for SQLite INTEGER (i64): {}",
                sn
            ))
        })?)
        } else {
            None
        };

        conn.execute(
            r#"
        INSERT OR REPLACE INTO aborts (
            request_id, subject_id, sn, error, who, abort_type
        ) VALUES (
            ?1, ?2, ?3, ?4, ?5, ?6
        )
        "#,
            params![request_id, subject_id, sn_i64, error, who, abort_type],
        )
        .map_err(|e| DatabaseError::Query(e.to_string()))?;

        Ok(())
    }
}

#[async_trait]
impl Subscriber<SignedLedger> for SqliteLocal {
    async fn notify(&self, event: SignedLedger) {
        let subject_id = event
            .content()
            .get_subject_id()
            .to_string();
        let sn = event.content().sn;

        if let Err(e) = self.save_signed_ledger(&event).await {
            error!(
                subject_id = %subject_id,
                sn = sn,
                error = %e,
                "Failed to save signed ledger to SQLite"
            );
            if let Err(e) = self.manager.tell(DBManagerMessage::Error(e)).await
            {
                error!(
                    subject_id = %subject_id,
                    sn = sn,
                    error = %e,
                    "Failed to notify DBManager about ledger save error"
                );
            }
        } else {
            debug!(
                subject_id = %subject_id,
                sn = sn,
                "Signed ledger saved to SQLite successfully"
            );
        }
    }
}

#[async_trait]
impl Subscriber<SinkDataEvent> for SqliteLocal {
    async fn notify(&self, event: SinkDataEvent) {
        let SinkDataEvent::State(metadata) = event else {
            return;
        };

        let subject_id = metadata.subject_id.to_string();
        let sn = metadata.sn;

        if let Err(e) = self.save_subject_state(&metadata).await {
            error!(
                subject_id = %subject_id,
                sn = sn,
                error = %e,
                "Failed to save subject state to SQLite"
            );
            if let Err(e) = self.manager.tell(DBManagerMessage::Error(e)).await
            {
                error!(
                    subject_id = %subject_id,
                    sn = sn,
                    error = %e,
                    "Failed to notify DBManager about state save error"
                );
            }
        } else {
            debug!(
                subject_id = %subject_id,
                sn = sn,
                "Subject state saved to SQLite successfully"
            );
        }
    }
}

#[async_trait]
impl Subscriber<RequestTrackingEvent> for SqliteLocal {
    async fn notify(&self, event: RequestTrackingEvent) {
        let request_id = event.request_id.clone();
        let subject_id = event.subject_id.clone();
        let sn = event.sn;
        let who = event.who.clone();

        if let Err(e) = self
            .save_abort(
                event.request_id,
                event.subject_id,
                event.sn,
                event.error,
                event.who,
                event.abort_type,
            )
            .await
        {
            error!(
                subject_id = %subject_id,
                request_id = %request_id,
                sn = ?sn,
                error = %e,
                "Failed to save abort record to SQLite"
            );
            if let Err(e) = self.manager.tell(DBManagerMessage::Error(e)).await
            {
                error!(
                    subject_id = %subject_id,
                    request_id = %request_id,
                    sn = ?sn,
                    error = %e,
                    "Failed to notify DBManager about abort save error"
                );
            }
        } else {
            debug!(
                subject_id = %subject_id,
                request_id = %request_id,
                sn = ?sn,
                who = %who,
                "Abort record saved to SQLite successfully"
            );
        }
    }
}
