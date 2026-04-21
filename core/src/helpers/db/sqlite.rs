use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::{
    Arc, Condvar, Mutex, MutexGuard,
    atomic::{AtomicU64, AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use ave_actors::rusqlite;
use ave_actors::rusqlite::types::Type;
use ave_actors::{ActorRef, Subscriber};
use ave_common::SchemaType;
use ave_common::bridge::request::{AbortsQuery, EventRequestType, EventsQuery};
use ave_common::response::{
    AbortDB, GovsData, LedgerDB, Paginator, PaginatorAborts, PaginatorEvents,
    RequestEventDB, SubjectDB, SubjsData, TimeRange, TrackerVisibilityStateDB,
};
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{
        counter::Counter, family::Family, gauge::Gauge, histogram::Histogram,
    },
    registry::Registry,
};
use rusqlite::{Connection, OpenFlags, TransactionBehavior, params};
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use tokio::sync::{Mutex as AsyncMutex, mpsc, oneshot};
use tokio::task::{self, JoinHandle};
use tokio::time::timeout;
use tokio_util::sync::CancellationToken;
use tracing::{debug, error};

use super::{DatabaseError, DbMetricsSnapshot, ReadStore};
use crate::config::{MachineSpec, resolve_spec};
use crate::external_db::{DBManager, DBManagerMessage};
use crate::model::event::Ledger;
use crate::node::register::RegisterEvent;
use crate::request::tracking::RequestTrackingEvent;
use crate::subject::sinkdata::SinkDataEvent;

const WRITE_QUEUE_CAPACITY: usize = 1024;
const WRITE_BATCH_MAX: usize = 128;
const WRITE_BATCH_MIN_FOR_WINDOW: usize = 8;
const WRITE_BATCH_WINDOW: Duration = Duration::from_millis(3);
const WRITE_BATCH_RETRY_ATTEMPTS: usize = 3;
const WRITE_BATCH_RETRY_BASE_BACKOFF: Duration = Duration::from_millis(5);
const READER_STATEMENT_CACHE_CAPACITY: usize = 32;
const WRITER_STATEMENT_CACHE_CAPACITY: usize = 128;
const PAGE_ANCHOR_CACHE_MAX_QUERIES: usize = 256;
const PAGE_ANCHOR_CACHE_MAX_ANCHORS_PER_QUERY: usize = 64;
const PAGE_ANCHOR_WALK_THRESHOLD: u64 = 8;

const SQL_GET_SUBJECT_STATE: &str = r#"
    SELECT
        name, description, subject_id, governance_id, genesis_gov_version,
        prev_ledger_event_hash, schema_id, namespace, sn,
        creator, owner, new_owner, active, tracker_visibility, properties
    FROM subjects
    WHERE subject_id = ?1
"#;

const SQL_GET_EVENT_SN: &str = r#"
    SELECT
        subject_id, sn, event_request_timestamp, event_ledger_timestamp, sink_timestamp, event, event_type
    FROM events
    WHERE subject_id = ?1 AND sn = ?2
"#;

const SQL_COUNT_EVENTS_SUBJECT_ONLY: &str = r#"
    SELECT COUNT(*) FROM events WHERE subject_id = ?1
"#;

const SQL_COUNT_ABORTS_SUBJECT_ONLY: &str = r#"
    SELECT COUNT(*) FROM aborts WHERE subject_id = ?1
"#;

const SQL_JUMP_EVENTS_SUBJECT_ONLY_ASC: &str = r#"
    WITH page_keys AS (
        SELECT sn
        FROM events
        WHERE subject_id = ?1
        ORDER BY sn ASC
        LIMIT ?2 OFFSET ?3
    )
    SELECT
        e.subject_id, e.sn, e.event_request_timestamp, e.event_ledger_timestamp, e.sink_timestamp, e.event, e.event_type
    FROM events e
    JOIN page_keys k ON e.subject_id = ?1 AND e.sn = k.sn
    ORDER BY e.sn ASC
"#;

const SQL_JUMP_EVENTS_SUBJECT_ONLY_DESC: &str = r#"
    WITH page_keys AS (
        SELECT sn
        FROM events
        WHERE subject_id = ?1
        ORDER BY sn DESC
        LIMIT ?2 OFFSET ?3
    )
    SELECT
        e.subject_id, e.sn, e.event_request_timestamp, e.event_ledger_timestamp, e.sink_timestamp, e.event, e.event_type
    FROM events e
    JOIN page_keys k ON e.subject_id = ?1 AND e.sn = k.sn
    ORDER BY e.sn DESC
"#;

const SQL_JUMP_ABORTS_SUBJECT_ONLY_ASC: &str = r#"
    WITH page_keys AS (
        SELECT request_id
        FROM aborts
        WHERE subject_id = ?1
        ORDER BY COALESCE(sn, -1) ASC, request_id ASC
        LIMIT ?2 OFFSET ?3
    )
    SELECT a.request_id, a.subject_id, a.sn, a.error, a.who, a.abort_type
    FROM aborts a
    JOIN page_keys k ON a.request_id = k.request_id
    ORDER BY COALESCE(a.sn, -1) ASC, a.request_id ASC
"#;

const SQL_JUMP_ABORTS_SUBJECT_ONLY_DESC: &str = r#"
    WITH page_keys AS (
        SELECT request_id
        FROM aborts
        WHERE subject_id = ?1
        ORDER BY COALESCE(sn, -1) DESC, request_id DESC
        LIMIT ?2 OFFSET ?3
    )
    SELECT a.request_id, a.subject_id, a.sn, a.error, a.who, a.abort_type
    FROM aborts a
    JOIN page_keys k ON a.request_id = k.request_id
    ORDER BY COALESCE(a.sn, -1) DESC, a.request_id DESC
"#;

const SQL_GET_EVENTS_SUBJECT_ONLY_ASC: &str = r#"
    SELECT
        subject_id, sn, event_request_timestamp, event_ledger_timestamp, sink_timestamp, event, event_type
    FROM events
    WHERE subject_id = ?1
    ORDER BY sn ASC
    LIMIT ?2
"#;

const SQL_GET_EVENTS_SUBJECT_ONLY_AFTER_ASC: &str = r#"
    SELECT
        subject_id, sn, event_request_timestamp, event_ledger_timestamp, sink_timestamp, event, event_type
    FROM events
    WHERE subject_id = ?1 AND sn > ?2
    ORDER BY sn ASC
    LIMIT ?3
"#;

const SQL_GET_EVENTS_SUBJECT_ONLY_DESC: &str = r#"
    SELECT
        subject_id, sn, event_request_timestamp, event_ledger_timestamp, sink_timestamp, event, event_type
    FROM events
    WHERE subject_id = ?1
    ORDER BY sn DESC
    LIMIT ?2
"#;

const SQL_GET_EVENTS_SUBJECT_ONLY_BEFORE_DESC: &str = r#"
    SELECT
        subject_id, sn, event_request_timestamp, event_ledger_timestamp, sink_timestamp, event, event_type
    FROM events
    WHERE subject_id = ?1 AND sn < ?2
    ORDER BY sn DESC
    LIMIT ?3
"#;

const SQL_GET_ABORTS_SUBJECT_ONLY_ASC: &str = r#"
    SELECT request_id, subject_id, sn, error, who, abort_type
    FROM aborts
    WHERE subject_id = ?1
    ORDER BY COALESCE(sn, -1) ASC, request_id ASC
    LIMIT ?2
"#;

const SQL_GET_ABORTS_SUBJECT_ONLY_AFTER_ASC: &str = r#"
    SELECT request_id, subject_id, sn, error, who, abort_type
    FROM aborts
    WHERE subject_id = ?1
      AND (COALESCE(sn, -1) > ?2 OR (COALESCE(sn, -1) = ?2 AND request_id > ?3))
    ORDER BY COALESCE(sn, -1) ASC, request_id ASC
    LIMIT ?4
"#;

const SQL_GET_ABORTS_SUBJECT_ONLY_DESC: &str = r#"
    SELECT request_id, subject_id, sn, error, who, abort_type
    FROM aborts
    WHERE subject_id = ?1
    ORDER BY COALESCE(sn, -1) DESC, request_id DESC
    LIMIT ?2
"#;

const SQL_GET_ABORTS_SUBJECT_ONLY_BEFORE_DESC: &str = r#"
    SELECT request_id, subject_id, sn, error, who, abort_type
    FROM aborts
    WHERE subject_id = ?1
      AND (COALESCE(sn, -1) < ?2 OR (COALESCE(sn, -1) = ?2 AND request_id < ?3))
    ORDER BY COALESCE(sn, -1) DESC, request_id DESC
    LIMIT ?4
"#;

const SQL_GET_FIRST_EVENTS: &str = r#"
    SELECT
        subject_id, sn, event_request_timestamp, event_ledger_timestamp, sink_timestamp, event, event_type
    FROM events
    WHERE subject_id = ?1
    ORDER BY sn ASC
    LIMIT ?2
"#;

const SQL_GET_LAST_EVENTS: &str = r#"
    SELECT
        subject_id, sn, event_request_timestamp, event_ledger_timestamp, sink_timestamp, event, event_type
    FROM events
    WHERE subject_id = ?1
    ORDER BY sn DESC
    LIMIT ?2
"#;

const SQL_GET_FIRST_EVENTS_BY_TYPE: &str = r#"
    SELECT
        subject_id, sn, event_request_timestamp, event_ledger_timestamp, sink_timestamp, event, event_type
    FROM events
    WHERE subject_id = ?1 AND event_type = ?2
    ORDER BY sn ASC
    LIMIT ?3
"#;

const SQL_GET_LAST_EVENTS_BY_TYPE: &str = r#"
    SELECT
        subject_id, sn, event_request_timestamp, event_ledger_timestamp, sink_timestamp, event, event_type
    FROM events
    WHERE subject_id = ?1 AND event_type = ?2
    ORDER BY sn DESC
    LIMIT ?3
"#;

const SQL_INSERT_EVENT: &str = r#"
    INSERT INTO events (
        subject_id, sn, event_request_timestamp, event_ledger_timestamp, sink_timestamp, event, event_type
    ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
"#;

const SQL_UPSERT_SUBJECT: &str = r#"
    INSERT INTO subjects (
        name, description, subject_id, governance_id, genesis_gov_version,
        prev_ledger_event_hash, schema_id, namespace, sn,
        creator, owner, new_owner, active, tracker_visibility, properties
    ) VALUES (
        ?1, ?2, ?3, ?4, ?5,
        ?6, ?7, ?8, ?9,
        ?10, ?11, ?12, ?13, ?14, ?15
    )
    ON CONFLICT(subject_id) DO UPDATE SET
        name = excluded.name,
        description = excluded.description,
        governance_id = excluded.governance_id,
        genesis_gov_version = excluded.genesis_gov_version,
        prev_ledger_event_hash = excluded.prev_ledger_event_hash,
        schema_id = excluded.schema_id,
        namespace = excluded.namespace,
        sn = excluded.sn,
        creator = excluded.creator,
        owner = excluded.owner,
        new_owner = excluded.new_owner,
        active = excluded.active,
        tracker_visibility = excluded.tracker_visibility,
        properties = excluded.properties
"#;

const SQL_UPSERT_ABORT: &str = r#"
    INSERT INTO aborts (
        request_id, subject_id, sn, error, who, abort_type
    ) VALUES (
        ?1, ?2, ?3, ?4, ?5, ?6
    )
    ON CONFLICT(request_id) DO UPDATE SET
        subject_id = excluded.subject_id,
        sn = excluded.sn,
        error = excluded.error,
        who = excluded.who,
        abort_type = excluded.abort_type
"#;

const SQL_UPSERT_REGISTER_GOV: &str = r#"
    INSERT INTO register_govs (
        governance_id, active, name, description
    ) VALUES (
        ?1, ?2, ?3, ?4
    )
    ON CONFLICT(governance_id) DO UPDATE SET
        active = excluded.active,
        name = excluded.name,
        description = excluded.description
"#;

const SQL_EOL_REGISTER_GOV: &str = r#"
    UPDATE register_govs
    SET active = 0
    WHERE governance_id = ?1
"#;

const SQL_UPSERT_REGISTER_SUBJECT: &str = r#"
    INSERT INTO register_subjects (
        governance_id, subject_id, schema_id, active, namespace, name, description
    ) VALUES (
        ?1, ?2, ?3, ?4, ?5, ?6, ?7
    )
    ON CONFLICT(governance_id, subject_id) DO UPDATE SET
        schema_id = excluded.schema_id,
        active = excluded.active,
        namespace = excluded.namespace,
        name = excluded.name,
        description = excluded.description
"#;

const SQL_EOL_REGISTER_SUBJECT: &str = r#"
    UPDATE register_subjects
    SET active = 0
    WHERE governance_id = ?1 AND subject_id = ?2
"#;

const SQL_DELETE_SUBJECT_STATE: &str = r#"
    DELETE FROM subjects
    WHERE subject_id = ?1
"#;

const SQL_DELETE_EVENTS_SUBJECT: &str = r#"
    DELETE FROM events
    WHERE subject_id = ?1
"#;

const SQL_DELETE_ABORTS_SUBJECT: &str = r#"
    DELETE FROM aborts
    WHERE subject_id = ?1
"#;

const SQL_DELETE_REGISTER_SUBJECT: &str = r#"
    DELETE FROM register_subjects
    WHERE subject_id = ?1
"#;

const SQL_DELETE_REGISTER_GOV: &str = r#"
    DELETE FROM register_govs
    WHERE governance_id = ?1
"#;

const SQL_GET_REGISTER_GOVS: &str = r#"
    SELECT governance_id, active, name, description
    FROM register_govs
    ORDER BY governance_id ASC
"#;

const SQL_GET_REGISTER_GOVS_BY_ACTIVE: &str = r#"
    SELECT governance_id, active, name, description
    FROM register_govs
    WHERE active = ?1
    ORDER BY governance_id ASC
"#;

const SQL_GET_REGISTER_SUBJECTS: &str = r#"
    SELECT subject_id, schema_id, active, namespace, name, description
    FROM register_subjects
    WHERE governance_id = ?1
    ORDER BY subject_id ASC
"#;

const SQL_GET_REGISTER_SUBJECTS_BY_ACTIVE: &str = r#"
    SELECT subject_id, schema_id, active, namespace, name, description
    FROM register_subjects
    WHERE governance_id = ?1 AND active = ?2
    ORDER BY subject_id ASC
"#;

const SQL_GET_REGISTER_SUBJECTS_BY_SCHEMA: &str = r#"
    SELECT subject_id, schema_id, active, namespace, name, description
    FROM register_subjects
    WHERE governance_id = ?1 AND schema_id = ?2
    ORDER BY subject_id ASC
"#;

const SQL_GET_REGISTER_SUBJECTS_BY_ACTIVE_SCHEMA: &str = r#"
    SELECT subject_id, schema_id, active, namespace, name, description
    FROM register_subjects
    WHERE governance_id = ?1 AND active = ?2 AND schema_id = ?3
    ORDER BY subject_id ASC
"#;

const SQL_REGISTER_GOV_EXISTS: &str = r#"
    SELECT 1
    FROM register_govs
    WHERE governance_id = ?1
    LIMIT 1
"#;

/// Serializes an `EventRequestType` to its serde string representation.
fn event_request_type_to_string(
    et: &EventRequestType,
) -> Result<String, DatabaseError> {
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
    reader: SqliteReadStore,
    writer: SqliteWriteStore,
}

#[derive(Clone)]
struct SqliteReadStore {
    runtime: Arc<SqliteRuntime>,
}

#[derive(Clone)]
pub struct SqliteWriteStore {
    inner: Arc<SqliteWriteStoreInner>,
}

struct SqliteWriteStoreInner {
    manager: ActorRef<DBManager>,
    metrics: Arc<SqliteMetrics>,
    sender: mpsc::Sender<WriteJob>,
    shutdown: CancellationToken,
    worker: AsyncMutex<Option<JoinHandle<()>>>,
}

#[derive(Clone)]
struct CursorEventsQuery {
    quantity: u64,
    cursor: Option<String>,
    reverse: bool,
    event_request_ts: Option<TimeRange>,
    event_ledger_ts: Option<TimeRange>,
    sink_ts: Option<TimeRange>,
    event_type: Option<EventRequestType>,
}

#[derive(Clone)]
struct CursorAbortsQuery {
    request_id: Option<String>,
    sn: Option<u64>,
    quantity: u64,
    cursor: Option<String>,
    reverse: bool,
}

enum WriteCommand {
    Ledger(Box<Ledger>),
    SubjectState(SubjectDB),
    Abort(RequestTrackingEvent),
    Register(RegisterEvent),
    DeleteSubject(String),
}

struct WriteJob {
    command: WriteCommand,
    response: oneshot::Sender<Result<(), DatabaseError>>,
}

struct RegisterSubjectRow<'a> {
    governance_id: &'a str,
    subject_id: &'a str,
    schema_id: &'a SchemaType,
    active: bool,
    namespace: &'a str,
    name: Option<String>,
    description: Option<String>,
}

#[derive(Default)]
struct SqliteMetrics {
    reader_wait_ns_total: AtomicU64,
    reader_wait_count: AtomicU64,
    reader_wait_ns_max: AtomicU64,
    writer_queue_depth_current: AtomicUsize,
    writer_queue_depth_max: AtomicUsize,
    writer_batch_size_total: AtomicU64,
    writer_batch_count: AtomicU64,
    writer_batch_size_max: AtomicUsize,
    writer_retry_count: AtomicU64,
    writer_retry_attempt_max: AtomicUsize,
    page_anchor_hit_count: AtomicU64,
    page_anchor_miss_count: AtomicU64,
    pages_walked_from_anchor_total: AtomicU64,
    count_query_ns_total: AtomicU64,
    count_query_count: AtomicU64,
    count_query_ns_max: AtomicU64,
    prometheus: std::sync::OnceLock<Arc<DbPrometheusMetrics>>,
}

#[derive(Debug)]
struct DbPrometheusMetrics {
    reader_wait_seconds: Histogram,
    read_query_seconds: Family<ReadQueryLabels, Histogram, fn() -> Histogram>,
    writer_queue_depth: Gauge,
    writer_batch_size: Histogram,
    writer_batch_duration_seconds: Histogram,
    writer_batch_retries_total: Counter,
    writer_failures_total: Family<WriterFailureLabels, Counter>,
    page_anchor_lookups_total: Family<PageAnchorLabels, Counter>,
    pages_walked_from_anchor_total: Counter,
    count_cache_lookups_total: Family<CountCacheLabels, Counter>,
    count_query_duration_seconds: Histogram,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ReadQueryLabels {
    operation: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct WriterFailureLabels {
    stage: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct PageAnchorLabels {
    result: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct CountCacheLabels {
    result: &'static str,
}

#[derive(Default)]
struct PageAnchorCache {
    subject_generations: HashMap<String, u64>,
    query_entries: HashMap<String, PageAnchorEntry>,
    count_entries: HashMap<String, CountCacheEntry>,
    access_clock: u64,
}

#[derive(Default)]
struct PageAnchorEntry {
    subject_generation: u64,
    last_used: u64,
    anchors: BTreeMap<u64, String>,
}

#[derive(Default)]
struct CountCacheEntry {
    subject_generation: u64,
    last_used: u64,
    total: u64,
}

impl DbPrometheusMetrics {
    fn new() -> Self {
        Self {
            reader_wait_seconds: Histogram::new(vec![
                0.000_1, 0.000_5, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25,
                0.5, 1.0,
            ]),
            read_query_seconds: Family::new_with_constructor(|| {
                Histogram::new(vec![
                    0.000_1, 0.000_5, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1,
                    0.25, 0.5, 1.0,
                ])
            }),
            writer_queue_depth: Gauge::default(),
            writer_batch_size: Histogram::new(vec![
                1.0, 2.0, 4.0, 8.0, 16.0, 32.0, 64.0, 128.0, 256.0,
            ]),
            writer_batch_duration_seconds: Histogram::new(vec![
                0.000_5, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0,
                2.0, 5.0,
            ]),
            writer_batch_retries_total: Counter::default(),
            writer_failures_total: Family::default(),
            page_anchor_lookups_total: Family::default(),
            pages_walked_from_anchor_total: Counter::default(),
            count_cache_lookups_total: Family::default(),
            count_query_duration_seconds: Histogram::new(vec![
                0.000_1, 0.000_5, 0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25,
                0.5, 1.0,
            ]),
        }
    }

    fn register_into(&self, registry: &mut Registry) {
        registry.register(
            "external_db_reader_wait_seconds",
            "Time spent waiting for an external DB SQLite reader connection.",
            self.reader_wait_seconds.clone(),
        );
        registry.register(
            "external_db_read_query_seconds",
            "Duration of external DB read queries, labeled by operation.",
            self.read_query_seconds.clone(),
        );
        registry.register(
            "external_db_writer_queue_depth",
            "Current number of pending writes queued for the external DB writer.",
            self.writer_queue_depth.clone(),
        );
        registry.register(
            "external_db_writer_batch_size",
            "Number of writes grouped into each external DB SQLite writer batch.",
            self.writer_batch_size.clone(),
        );
        registry.register(
            "external_db_writer_batch_duration_seconds",
            "End-to-end duration of external DB writer batches, including retries.",
            self.writer_batch_duration_seconds.clone(),
        );
        registry.register(
            "external_db_writer_batch_retries",
            "Total external DB writer batch retries due to transient write failures.",
            self.writer_batch_retries_total.clone(),
        );
        registry.register(
            "external_db_writer_failures",
            "Total external DB writer failures, labeled by stage.",
            self.writer_failures_total.clone(),
        );
        registry.register(
            "external_db_page_anchor_lookups",
            "Total page anchor cache lookups for external DB pagination, labeled by result.",
            self.page_anchor_lookups_total.clone(),
        );
        registry.register(
            "external_db_pages_walked_from_anchor",
            "Total number of pages walked forward from a cached anchor while resolving pagination.",
            self.pages_walked_from_anchor_total.clone(),
        );
        registry.register(
            "external_db_count_cache_lookups",
            "Total count-cache lookups for pagination queries, labeled by result.",
            self.count_cache_lookups_total.clone(),
        );
        registry.register(
            "external_db_count_query_duration_seconds",
            "Duration of external DB count queries used for pagination.",
            self.count_query_duration_seconds.clone(),
        );
    }
}

impl SqliteMetrics {
    fn duration_to_ns(elapsed: std::time::Duration) -> u64 {
        elapsed.as_nanos().min(u64::MAX as u128) as u64
    }

    fn ns_to_ms(ns: u64) -> f64 {
        ns as f64 / 1_000_000.0
    }

    fn ns_to_seconds(ns: u64) -> f64 {
        ns as f64 / 1_000_000_000.0
    }

    fn avg_ns_to_ms(total: u64, count: u64) -> f64 {
        total.checked_div(count).map_or(0.0, Self::ns_to_ms)
    }

    fn update_max_u64(target: &AtomicU64, value: u64) {
        let mut current = target.load(Ordering::Relaxed);
        while value > current {
            match target.compare_exchange(
                current,
                value,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }

    fn update_max_usize(target: &AtomicUsize, value: usize) {
        let mut current = target.load(Ordering::Relaxed);
        while value > current {
            match target.compare_exchange(
                current,
                value,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
    }

    fn record_reader_wait(&self, elapsed: std::time::Duration) {
        let ns = Self::duration_to_ns(elapsed);
        self.reader_wait_ns_total.fetch_add(ns, Ordering::Relaxed);
        self.reader_wait_count.fetch_add(1, Ordering::Relaxed);
        Self::update_max_u64(&self.reader_wait_ns_max, ns);
        if let Some(metrics) = self.prometheus.get() {
            metrics.reader_wait_seconds.observe(Self::ns_to_seconds(ns));
        }
    }

    fn record_read_query(
        &self,
        operation: &'static str,
        elapsed: std::time::Duration,
    ) {
        if let Some(metrics) = self.prometheus.get() {
            metrics
                .read_query_seconds
                .get_or_create(&ReadQueryLabels { operation })
                .observe(Self::ns_to_seconds(Self::duration_to_ns(elapsed)));
        }
    }

    fn record_writer_enqueue(&self) {
        let depth = self
            .writer_queue_depth_current
            .fetch_add(1, Ordering::Relaxed)
            + 1;
        Self::update_max_usize(&self.writer_queue_depth_max, depth);
        if let Some(metrics) = self.prometheus.get() {
            metrics.writer_queue_depth.set(depth as i64);
        }
    }

    fn record_writer_send_failure(&self) {
        let depth = self
            .writer_queue_depth_current
            .fetch_sub(1, Ordering::Relaxed)
            .saturating_sub(1);
        if let Some(metrics) = self.prometheus.get() {
            metrics.writer_queue_depth.set(depth as i64);
            metrics
                .writer_failures_total
                .get_or_create(&WriterFailureLabels {
                    stage: "enqueue_send",
                })
                .inc();
        }
    }

    fn record_writer_batch(&self, size: usize) {
        let depth = self
            .writer_queue_depth_current
            .fetch_sub(size, Ordering::Relaxed)
            .saturating_sub(size);
        self.writer_batch_count.fetch_add(1, Ordering::Relaxed);
        self.writer_batch_size_total
            .fetch_add(size as u64, Ordering::Relaxed);
        Self::update_max_usize(&self.writer_batch_size_max, size);
        if let Some(metrics) = self.prometheus.get() {
            metrics.writer_queue_depth.set(depth as i64);
            metrics.writer_batch_size.observe(size as f64);
        }
    }

    fn record_writer_retry(&self, attempt: usize) {
        self.writer_retry_count.fetch_add(1, Ordering::Relaxed);
        Self::update_max_usize(&self.writer_retry_attempt_max, attempt);
        if let Some(metrics) = self.prometheus.get() {
            metrics.writer_batch_retries_total.inc();
        }
    }

    fn record_writer_failure(&self, stage: &'static str) {
        if let Some(metrics) = self.prometheus.get() {
            metrics
                .writer_failures_total
                .get_or_create(&WriterFailureLabels { stage })
                .inc();
        }
    }

    fn record_writer_batch_duration(&self, elapsed: std::time::Duration) {
        if let Some(metrics) = self.prometheus.get() {
            metrics
                .writer_batch_duration_seconds
                .observe(Self::ns_to_seconds(Self::duration_to_ns(elapsed)));
        }
    }

    fn record_page_anchor_hit(&self) {
        self.page_anchor_hit_count.fetch_add(1, Ordering::Relaxed);
        if let Some(metrics) = self.prometheus.get() {
            metrics
                .page_anchor_lookups_total
                .get_or_create(&PageAnchorLabels { result: "hit" })
                .inc();
        }
    }

    fn record_page_anchor_miss(&self) {
        self.page_anchor_miss_count.fetch_add(1, Ordering::Relaxed);
        if let Some(metrics) = self.prometheus.get() {
            metrics
                .page_anchor_lookups_total
                .get_or_create(&PageAnchorLabels { result: "miss" })
                .inc();
        }
    }

    fn record_pages_walked_from_anchor(&self, pages: u64) {
        if pages == 0 {
            return;
        }
        self.pages_walked_from_anchor_total
            .fetch_add(pages, Ordering::Relaxed);
        if let Some(metrics) = self.prometheus.get() {
            metrics.pages_walked_from_anchor_total.inc_by(pages);
        }
    }

    fn record_count_cache_lookup(&self, hit: bool) {
        if let Some(metrics) = self.prometheus.get() {
            metrics
                .count_cache_lookups_total
                .get_or_create(&CountCacheLabels {
                    result: if hit { "hit" } else { "miss" },
                })
                .inc();
        }
    }

    fn record_count_query_duration(&self, elapsed: std::time::Duration) {
        let ns = Self::duration_to_ns(elapsed);
        self.count_query_ns_total.fetch_add(ns, Ordering::Relaxed);
        self.count_query_count.fetch_add(1, Ordering::Relaxed);
        Self::update_max_u64(&self.count_query_ns_max, ns);
        if let Some(metrics) = self.prometheus.get() {
            metrics
                .count_query_duration_seconds
                .observe(Self::ns_to_seconds(ns));
        }
    }

    fn snapshot(&self) -> DbMetricsSnapshot {
        let reader_wait_count = self.reader_wait_count.load(Ordering::Relaxed);
        let reader_wait_ns_total =
            self.reader_wait_ns_total.load(Ordering::Relaxed);
        let writer_batch_count =
            self.writer_batch_count.load(Ordering::Relaxed);
        let writer_batch_total =
            self.writer_batch_size_total.load(Ordering::Relaxed);
        let count_query_count = self.count_query_count.load(Ordering::Relaxed);
        let count_query_total =
            self.count_query_ns_total.load(Ordering::Relaxed);

        DbMetricsSnapshot {
            reader_wait_count,
            reader_wait_avg_ms: Self::avg_ns_to_ms(
                reader_wait_ns_total,
                reader_wait_count,
            ),
            reader_wait_max_ms: Self::ns_to_ms(
                self.reader_wait_ns_max.load(Ordering::Relaxed),
            ),
            writer_queue_depth: self
                .writer_queue_depth_current
                .load(Ordering::Relaxed),
            writer_queue_depth_max: self
                .writer_queue_depth_max
                .load(Ordering::Relaxed),
            writer_batch_count,
            writer_batch_avg_size: if writer_batch_count == 0 {
                0.0
            } else {
                writer_batch_total as f64 / writer_batch_count as f64
            },
            writer_batch_max_size: self
                .writer_batch_size_max
                .load(Ordering::Relaxed),
            writer_retry_count: self.writer_retry_count.load(Ordering::Relaxed),
            writer_retry_max_attempt: self
                .writer_retry_attempt_max
                .load(Ordering::Relaxed),
            page_anchor_hit_count: self
                .page_anchor_hit_count
                .load(Ordering::Relaxed),
            page_anchor_miss_count: self
                .page_anchor_miss_count
                .load(Ordering::Relaxed),
            pages_walked_from_anchor: self
                .pages_walked_from_anchor_total
                .load(Ordering::Relaxed),
            count_query_avg_ms: Self::avg_ns_to_ms(
                count_query_total,
                count_query_count,
            ),
            count_query_max_ms: Self::ns_to_ms(
                self.count_query_ns_max.load(Ordering::Relaxed),
            ),
        }
    }

    fn register_prometheus_metrics(&self, registry: &mut Registry) {
        let metrics = self
            .prometheus
            .get_or_init(|| Arc::new(DbPrometheusMetrics::new()));
        metrics.register_into(registry);
        metrics.writer_queue_depth.set(
            self.writer_queue_depth_current.load(Ordering::Relaxed) as i64,
        );
    }
}

impl CursorEventsQuery {
    fn from_public(query: EventsQuery) -> Self {
        Self {
            quantity: query.quantity.unwrap_or(50).max(1),
            cursor: None,
            reverse: query.reverse.unwrap_or(false),
            event_request_ts: query.event_request_ts,
            event_ledger_ts: query.event_ledger_ts,
            sink_ts: query.sink_ts,
            event_type: query.event_type,
        }
    }
}

impl CursorAbortsQuery {
    fn from_public(query: AbortsQuery) -> Self {
        Self {
            request_id: query.request_id,
            sn: query.sn,
            quantity: query.quantity.unwrap_or(50).max(1),
            cursor: None,
            reverse: query.reverse.unwrap_or(false),
        }
    }
}

impl PageAnchorCache {
    const fn next_clock(&mut self) -> u64 {
        self.access_clock = self.access_clock.saturating_add(1);
        self.access_clock
    }

    fn current_subject_generation(&self, subject_id: &str) -> u64 {
        self.subject_generations
            .get(subject_id)
            .copied()
            .unwrap_or(0)
    }

    fn lookup_anchor(
        &mut self,
        key: &str,
        subject_id: &str,
        target_page: u64,
    ) -> Option<(u64, String)> {
        let subject_generation = self.current_subject_generation(subject_id);
        let entry_generation = self
            .query_entries
            .get(key)
            .map(|entry| entry.subject_generation)?;
        if entry_generation != subject_generation {
            self.query_entries.remove(key);
            return None;
        }

        let clock = self.next_clock();
        let entry = self.query_entries.get_mut(key)?;
        entry.last_used = clock;
        entry
            .anchors
            .range(..=target_page)
            .next_back()
            .map(|(page, cursor)| (*page, cursor.clone()))
    }

    fn store_anchor(
        &mut self,
        key: String,
        subject_id: &str,
        target_page: u64,
        cursor: String,
    ) {
        if target_page <= 1 {
            return;
        }

        let subject_generation = self.current_subject_generation(subject_id);
        let clock = self.next_clock();
        let entry = self.query_entries.entry(key).or_default();

        if entry.subject_generation != subject_generation {
            entry.subject_generation = subject_generation;
            entry.anchors.clear();
        }

        entry.last_used = clock;
        entry.anchors.insert(target_page, cursor);
        while entry.anchors.len() > PAGE_ANCHOR_CACHE_MAX_ANCHORS_PER_QUERY {
            let Some(first_page) = entry.anchors.keys().next().copied() else {
                break;
            };
            entry.anchors.remove(&first_page);
        }

        while self.query_entries.len() > PAGE_ANCHOR_CACHE_MAX_QUERIES {
            let Some(oldest_key) = self
                .query_entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.query_entries.remove(&oldest_key);
        }
    }

    fn lookup_count(&mut self, key: &str, subject_id: &str) -> Option<u64> {
        let subject_generation = self.current_subject_generation(subject_id);
        let entry_generation = self
            .count_entries
            .get(key)
            .map(|entry| entry.subject_generation)?;
        if entry_generation != subject_generation {
            self.count_entries.remove(key);
            return None;
        }

        let clock = self.next_clock();
        let entry = self.count_entries.get_mut(key)?;
        entry.last_used = clock;
        Some(entry.total)
    }

    fn store_count(&mut self, key: String, subject_id: &str, total: u64) {
        let subject_generation = self.current_subject_generation(subject_id);
        let clock = self.next_clock();
        let entry = self.count_entries.entry(key).or_default();

        entry.subject_generation = subject_generation;
        entry.last_used = clock;
        entry.total = total;

        while self.count_entries.len() > PAGE_ANCHOR_CACHE_MAX_QUERIES {
            let Some(oldest_key) = self
                .count_entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_used)
                .map(|(key, _)| key.clone())
            else {
                break;
            };
            self.count_entries.remove(&oldest_key);
        }
    }

    fn bump_subject_generation(&mut self, subject_id: &str) {
        let generation = self
            .subject_generations
            .entry(subject_id.to_owned())
            .or_insert(0);
        *generation = generation.saturating_add(1);
    }
}

#[async_trait]
impl ReadStore for SqliteLocal {
    async fn get_aborts(
        &self,
        subject_id: &str,
        query: AbortsQuery,
    ) -> Result<PaginatorAborts, DatabaseError> {
        self.reader.get_aborts(subject_id, query).await
    }

    async fn get_subject_state(
        &self,
        subject_id: &str,
    ) -> Result<SubjectDB, DatabaseError> {
        self.reader.get_subject_state(subject_id).await
    }

    async fn get_governances(
        &self,
        active: Option<bool>,
    ) -> Result<Vec<GovsData>, DatabaseError> {
        self.reader.get_governances(active).await
    }

    async fn get_subjects(
        &self,
        governance_id: &str,
        active: Option<bool>,
        schema_id: Option<String>,
    ) -> Result<Vec<SubjsData>, DatabaseError> {
        self.reader
            .get_subjects(governance_id, active, schema_id)
            .await
    }

    async fn get_events(
        &self,
        subject_id: &str,
        query: EventsQuery,
    ) -> Result<PaginatorEvents, DatabaseError> {
        self.reader.get_events(subject_id, query).await
    }

    async fn get_event_sn(
        &self,
        subject_id: &str,
        sn: u64,
    ) -> Result<LedgerDB, DatabaseError> {
        self.reader.get_event_sn(subject_id, sn).await
    }

    async fn get_first_or_end_events(
        &self,
        subject_id: &str,
        quantity: Option<u64>,
        reverse: Option<bool>,
        event_type: Option<EventRequestType>,
    ) -> Result<Vec<LedgerDB>, DatabaseError> {
        self.reader
            .get_first_or_end_events(subject_id, quantity, reverse, event_type)
            .await
    }
}

#[async_trait]
impl ReadStore for SqliteReadStore {
    async fn get_aborts(
        &self,
        subject_id: &str,
        query: AbortsQuery,
    ) -> Result<PaginatorAborts, DatabaseError> {
        let subject_id = subject_id.to_owned();
        let runtime = Arc::clone(&self.runtime);

        self.with_reader("aborts", move |conn| {
            get_aborts_from_conn(conn, runtime.as_ref(), &subject_id, query)
        })
        .await
    }

    async fn get_subject_state(
        &self,
        subject_id: &str,
    ) -> Result<SubjectDB, DatabaseError> {
        let subject_id = subject_id.to_owned();

        self.with_reader("subject_state", move |conn| {
            get_subject_state_from_conn(conn, &subject_id)
        })
        .await
    }

    async fn get_governances(
        &self,
        active: Option<bool>,
    ) -> Result<Vec<GovsData>, DatabaseError> {
        self.with_reader("governances", move |conn| {
            get_governances_from_conn(conn, active)
        })
        .await
    }

    async fn get_subjects(
        &self,
        governance_id: &str,
        active: Option<bool>,
        schema_id: Option<String>,
    ) -> Result<Vec<SubjsData>, DatabaseError> {
        let governance_id = governance_id.to_owned();

        self.with_reader("subjects", move |conn| {
            get_subjects_from_conn(conn, &governance_id, active, schema_id)
        })
        .await
    }

    async fn get_events(
        &self,
        subject_id: &str,
        query: EventsQuery,
    ) -> Result<PaginatorEvents, DatabaseError> {
        let subject_id = subject_id.to_owned();
        let runtime = Arc::clone(&self.runtime);

        self.with_reader("events", move |conn| {
            get_events_from_conn(conn, runtime.as_ref(), &subject_id, query)
        })
        .await
    }

    async fn get_event_sn(
        &self,
        subject_id: &str,
        sn: u64,
    ) -> Result<LedgerDB, DatabaseError> {
        let subject_id = subject_id.to_owned();

        self.with_reader("event_sn", move |conn| {
            get_event_sn_from_conn(conn, &subject_id, sn)
        })
        .await
    }

    async fn get_first_or_end_events(
        &self,
        subject_id: &str,
        quantity: Option<u64>,
        reverse: Option<bool>,
        event_type: Option<EventRequestType>,
    ) -> Result<Vec<LedgerDB>, DatabaseError> {
        let subject_id = subject_id.to_owned();

        self.with_reader("first_or_end_events", move |conn| {
            get_first_or_end_events_from_conn(
                conn,
                &subject_id,
                quantity,
                reverse,
                event_type,
            )
        })
        .await
    }
}

impl SqliteLocal {
    pub async fn new(
        path: &Path,
        manager: ActorRef<DBManager>,
        durability: bool,
        spec: Option<MachineSpec>,
    ) -> Result<Self, DatabaseError> {
        let resolved = resolve_spec(spec.as_ref());
        let tuning = tuning_for_ram(resolved.ram_mb);
        let sync_mode = if durability { "FULL" } else { "NORMAL" };

        let runtime = SqliteRuntime::new(path, sync_mode, &tuning)?;
        let runtime = Arc::new(runtime);

        debug!(
            path = %path.display(),
            ram_mb = resolved.ram_mb,
            readers = SqliteRuntime::recommended_reader_pool_size(),
            "SQLite database runtime established"
        );

        Ok(Self {
            reader: SqliteReadStore::new(Arc::clone(&runtime)),
            writer: SqliteWriteStore::new(manager, runtime),
        })
    }

    pub fn writer(&self) -> SqliteWriteStore {
        self.writer.clone()
    }

    pub fn metrics_snapshot(&self) -> DbMetricsSnapshot {
        self.reader.runtime.metrics.snapshot()
    }

    pub fn register_prometheus_metrics(&self, registry: &mut Registry) {
        self.reader
            .runtime
            .metrics
            .register_prometheus_metrics(registry);
    }

    pub async fn delete_subject(
        &self,
        subject_id: &str,
    ) -> Result<(), DatabaseError> {
        self.writer.delete_subject(subject_id.to_owned()).await
    }

    pub async fn shutdown(&self) -> Result<(), DatabaseError> {
        self.writer.shutdown().await?;

        let runtime = Arc::clone(&self.reader.runtime);
        task::spawn_blocking(move || runtime.run_shutdown_maintenance())
            .await
            .map_err(|e| DatabaseError::BlockingTask(e.to_string()))?
    }
}

impl SqliteReadStore {
    const fn new(runtime: Arc<SqliteRuntime>) -> Self {
        Self { runtime }
    }

    async fn with_reader<T, F>(
        &self,
        operation_name: &'static str,
        operation: F,
    ) -> Result<T, DatabaseError>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> Result<T, DatabaseError> + Send + 'static,
    {
        let runtime = Arc::clone(&self.runtime);

        task::spawn_blocking(move || {
            let started = Instant::now();
            let conn = runtime.acquire_reader()?;
            let result = operation(&conn);
            runtime
                .metrics
                .record_read_query(operation_name, started.elapsed());
            result
        })
        .await
        .map_err(|e| DatabaseError::BlockingTask(e.to_string()))?
    }
}

impl SqliteWriteStore {
    fn new(manager: ActorRef<DBManager>, runtime: Arc<SqliteRuntime>) -> Self {
        let (sender, receiver) = mpsc::channel(WRITE_QUEUE_CAPACITY);
        let metrics = Arc::clone(&runtime.metrics);
        let shutdown = CancellationToken::new();
        let worker = spawn_write_worker(
            Arc::clone(&runtime),
            receiver,
            shutdown.clone(),
        );
        Self {
            inner: Arc::new(SqliteWriteStoreInner {
                manager,
                metrics,
                sender,
                shutdown,
                worker: AsyncMutex::new(Some(worker)),
            }),
        }
    }

    async fn persist_signed_ledger(
        &self,
        event: Ledger,
    ) -> Result<(), DatabaseError> {
        self.enqueue(WriteCommand::Ledger(Box::new(event))).await
    }

    async fn persist_subject_state(
        &self,
        metadata: SubjectDB,
    ) -> Result<(), DatabaseError> {
        self.enqueue(WriteCommand::SubjectState(metadata)).await
    }

    async fn persist_abort(
        &self,
        event: RequestTrackingEvent,
    ) -> Result<(), DatabaseError> {
        self.enqueue(WriteCommand::Abort(event)).await
    }

    async fn persist_register(
        &self,
        event: RegisterEvent,
    ) -> Result<(), DatabaseError> {
        self.enqueue(WriteCommand::Register(event)).await
    }

    async fn delete_subject(
        &self,
        subject_id: String,
    ) -> Result<(), DatabaseError> {
        self.enqueue(WriteCommand::DeleteSubject(subject_id)).await
    }

    async fn enqueue(
        &self,
        command: WriteCommand,
    ) -> Result<(), DatabaseError> {
        let (response_tx, response_rx) = oneshot::channel();
        self.inner.metrics.record_writer_enqueue();
        self.inner
            .sender
            .send(WriteJob {
                command,
                response: response_tx,
            })
            .await
            .map_err(|_| {
                self.inner.metrics.record_writer_send_failure();
                DatabaseError::Pool("write worker is not available".to_owned())
            })?;

        response_rx.await.map_err(|_| {
            DatabaseError::Pool("write worker stopped before ack".to_owned())
        })?
    }

    async fn shutdown(&self) -> Result<(), DatabaseError> {
        self.inner.shutdown.cancel();

        let mut worker = self.inner.worker.lock().await;
        let Some(handle) = worker.take() else {
            return Ok(());
        };
        drop(worker);

        handle
            .await
            .map_err(|e| DatabaseError::BlockingTask(e.to_string()))
    }
}

fn spawn_write_worker(
    runtime: Arc<SqliteRuntime>,
    mut receiver: mpsc::Receiver<WriteJob>,
    shutdown: CancellationToken,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut shutting_down = false;

        loop {
            let next_job = if shutting_down {
                receiver.recv().await
            } else {
                tokio::select! {
                    _ = shutdown.cancelled() => {
                        receiver.close();
                        shutting_down = true;
                        receiver.recv().await
                    }
                    job = receiver.recv() => job,
                }
            };

            let Some(first_job) = next_job else {
                break;
            };

            let mut jobs = vec![first_job];
            let batch_window_started = Instant::now();

            while jobs.len() < WRITE_BATCH_MAX {
                match receiver.try_recv() {
                    Ok(job) => jobs.push(job),
                    Err(mpsc::error::TryRecvError::Empty) => {
                        if shutting_down
                            || jobs.len() < WRITE_BATCH_MIN_FOR_WINDOW
                        {
                            break;
                        }

                        let Some(remaining) = WRITE_BATCH_WINDOW
                            .checked_sub(batch_window_started.elapsed())
                        else {
                            break;
                        };

                        tokio::select! {
                            _ = shutdown.cancelled() => {
                                receiver.close();
                                shutting_down = true;
                                break;
                            }
                            result = timeout(remaining, receiver.recv()) => {
                                match result {
                                    Ok(Some(job)) => jobs.push(job),
                                    Ok(None) => {
                                        shutting_down = true;
                                        break;
                                    }
                                    Err(_) => break,
                                }
                            }
                        }
                    }
                    Err(mpsc::error::TryRecvError::Disconnected) => {
                        shutting_down = true;
                        break;
                    }
                }
            }

            runtime.metrics.record_writer_batch(jobs.len());

            let result = task::spawn_blocking({
                let runtime = Arc::clone(&runtime);
                move || execute_write_batch(runtime, jobs)
            })
            .await
            .map_err(|e| DatabaseError::BlockingTask(e.to_string()))
            .and_then(|result| result);

            if result.is_err() {
                break;
            }
        }
    })
}

fn execute_write_batch(
    runtime: Arc<SqliteRuntime>,
    jobs: Vec<WriteJob>,
) -> Result<(), DatabaseError> {
    let started = Instant::now();
    let mut attempt = 1;

    loop {
        match persist_write_batch(&runtime, &jobs) {
            Ok(()) => {
                runtime
                    .metrics
                    .record_writer_batch_duration(started.elapsed());
                for job in jobs {
                    let _ = job.response.send(Ok(()));
                }
                return Ok(());
            }
            Err(error)
                if attempt < WRITE_BATCH_RETRY_ATTEMPTS
                    && is_retryable_write_error(&error) =>
            {
                let backoff = retry_backoff(attempt);
                runtime.metrics.record_writer_retry(attempt);
                debug!(
                    attempt = attempt,
                    max_attempts = WRITE_BATCH_RETRY_ATTEMPTS,
                    batch_size = jobs.len(),
                    backoff_ms = backoff.as_millis(),
                    error = %error,
                    "Retrying SQLite write batch after transient query failure"
                );
                std::thread::sleep(backoff);
                attempt += 1;
            }
            Err(error) => {
                runtime.metrics.record_writer_failure("batch_terminal");
                runtime
                    .metrics
                    .record_writer_batch_duration(started.elapsed());
                for job in jobs {
                    let _ = job.response.send(Err(error.clone()));
                }
                return Err(error);
            }
        }
    }
}

fn persist_write_batch(
    runtime: &SqliteRuntime,
    jobs: &[WriteJob],
) -> Result<(), DatabaseError> {
    let mut touched_subjects: Vec<String> = Vec::with_capacity(jobs.len());
    let mut conn = runtime.lock_writer()?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| DatabaseError::Query(e.to_string()))?;

    let mut insert_event_stmt = tx
        .prepare_cached(SQL_INSERT_EVENT)
        .map_err(|e| DatabaseError::Query(e.to_string()))?;
    let mut upsert_subject_stmt = tx
        .prepare_cached(SQL_UPSERT_SUBJECT)
        .map_err(|e| DatabaseError::Query(e.to_string()))?;
    let mut upsert_abort_stmt = tx
        .prepare_cached(SQL_UPSERT_ABORT)
        .map_err(|e| DatabaseError::Query(e.to_string()))?;
    let mut upsert_register_gov_stmt = tx
        .prepare_cached(SQL_UPSERT_REGISTER_GOV)
        .map_err(|e| DatabaseError::Query(e.to_string()))?;
    let mut eol_register_gov_stmt = tx
        .prepare_cached(SQL_EOL_REGISTER_GOV)
        .map_err(|e| DatabaseError::Query(e.to_string()))?;
    let mut upsert_register_subject_stmt = tx
        .prepare_cached(SQL_UPSERT_REGISTER_SUBJECT)
        .map_err(|e| DatabaseError::Query(e.to_string()))?;
    let mut eol_register_subject_stmt = tx
        .prepare_cached(SQL_EOL_REGISTER_SUBJECT)
        .map_err(|e| DatabaseError::Query(e.to_string()))?;
    let mut delete_subject_state_stmt = tx
        .prepare_cached(SQL_DELETE_SUBJECT_STATE)
        .map_err(|e| DatabaseError::Query(e.to_string()))?;
    let mut delete_events_subject_stmt = tx
        .prepare_cached(SQL_DELETE_EVENTS_SUBJECT)
        .map_err(|e| DatabaseError::Query(e.to_string()))?;
    let mut delete_aborts_subject_stmt = tx
        .prepare_cached(SQL_DELETE_ABORTS_SUBJECT)
        .map_err(|e| DatabaseError::Query(e.to_string()))?;
    let mut delete_register_subject_stmt = tx
        .prepare_cached(SQL_DELETE_REGISTER_SUBJECT)
        .map_err(|e| DatabaseError::Query(e.to_string()))?;
    let mut delete_register_gov_stmt = tx
        .prepare_cached(SQL_DELETE_REGISTER_GOV)
        .map_err(|e| DatabaseError::Query(e.to_string()))?;

    for job in jobs {
        match &job.command {
            WriteCommand::Ledger(event) => {
                touched_subjects.push(event.get_subject_id().to_string());
                insert_event_with_stmt(&mut insert_event_stmt, event)?
            }
            WriteCommand::SubjectState(metadata) => {
                touched_subjects.push(metadata.subject_id.to_string());
                upsert_subject_with_stmt(&mut upsert_subject_stmt, metadata)?
            }
            WriteCommand::Abort(event) => upsert_abort_with_stmt(
                &mut upsert_abort_stmt,
                event.request_id.clone(),
                {
                    touched_subjects.push(event.subject_id.clone());
                    event.subject_id.clone()
                },
                event.sn,
                event.error.clone(),
                event.who.clone(),
                event.abort_type.clone(),
            )?,
            WriteCommand::Register(event) => match event {
                RegisterEvent::RegisterGov { gov_id, data } => {
                    upsert_register_governance_with_stmt(
                        &mut upsert_register_gov_stmt,
                        gov_id,
                        data.active,
                        data.name.clone(),
                        data.description.clone(),
                    )?
                }
                RegisterEvent::EOLGov { gov_id } => {
                    eol_register_governance_with_stmt(
                        &mut eol_register_gov_stmt,
                        gov_id,
                    )?
                }
                RegisterEvent::RegisterSubj {
                    gov_id,
                    subject_id,
                    data,
                } => upsert_register_subject_with_stmt(
                    &mut upsert_register_subject_stmt,
                    RegisterSubjectRow {
                        governance_id: gov_id,
                        subject_id,
                        schema_id: &data.schema_id,
                        active: data.active,
                        namespace: &data.namespace,
                        name: data.name.clone(),
                        description: data.description.clone(),
                    },
                )?,
                RegisterEvent::EOLSubj { gov_id, subj_id } => {
                    eol_register_subject_with_stmt(
                        &mut eol_register_subject_stmt,
                        gov_id,
                        subj_id,
                    )?
                }
            },
            WriteCommand::DeleteSubject(subject_id) => {
                touched_subjects.push(subject_id.clone());
                delete_by_subject_with_stmt(
                    &mut delete_subject_state_stmt,
                    subject_id,
                )?;
                delete_by_subject_with_stmt(
                    &mut delete_events_subject_stmt,
                    subject_id,
                )?;
                delete_by_subject_with_stmt(
                    &mut delete_aborts_subject_stmt,
                    subject_id,
                )?;
                delete_by_subject_with_stmt(
                    &mut delete_register_subject_stmt,
                    subject_id,
                )?;
                delete_by_subject_with_stmt(
                    &mut delete_register_gov_stmt,
                    subject_id,
                )?;
            }
        }
    }

    drop(delete_register_gov_stmt);
    drop(delete_register_subject_stmt);
    drop(delete_aborts_subject_stmt);
    drop(delete_events_subject_stmt);
    drop(delete_subject_state_stmt);
    drop(eol_register_subject_stmt);
    drop(upsert_register_subject_stmt);
    drop(eol_register_gov_stmt);
    drop(upsert_register_gov_stmt);
    drop(upsert_abort_stmt);
    drop(upsert_subject_stmt);
    drop(insert_event_stmt);

    tx.commit()
        .map_err(|e| DatabaseError::Query(e.to_string()))?;
    drop(conn);

    touched_subjects.sort();
    touched_subjects.dedup();
    for subject_id in touched_subjects {
        runtime.bump_subject_generation(&subject_id);
    }

    Ok(())
}

const fn is_retryable_write_error(error: &DatabaseError) -> bool {
    matches!(error, DatabaseError::Query(_))
}

const fn retry_backoff(attempt: usize) -> Duration {
    let multiplier = match attempt {
        0 | 1 => 1,
        2 => 2,
        _ => 4,
    };
    WRITE_BATCH_RETRY_BASE_BACKOFF.saturating_mul(multiplier as u32)
}

struct SqliteRuntime {
    writer: Mutex<Connection>,
    readers: Arc<ConnectionPool>,
    metrics: Arc<SqliteMetrics>,
    page_cache: Mutex<PageAnchorCache>,
}

impl SqliteRuntime {
    fn new(
        path: &Path,
        sync_mode: &str,
        tuning: &SqliteTuning,
    ) -> Result<Self, DatabaseError> {
        let metrics = Arc::new(SqliteMetrics::default());
        let writer = open_writer_connection(path, sync_mode, tuning)?;
        let reader_count = Self::recommended_reader_pool_size();
        let mut readers = Vec::with_capacity(reader_count);

        for _ in 0..reader_count {
            readers.push(open_reader_connection(path, tuning)?);
        }

        Ok(Self {
            writer: Mutex::new(writer),
            readers: Arc::new(ConnectionPool::new(readers)),
            metrics,
            page_cache: Mutex::new(PageAnchorCache::default()),
        })
    }

    fn recommended_reader_pool_size() -> usize {
        std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(4)
            .clamp(4, 8)
    }

    fn acquire_reader(&self) -> Result<PooledConnection, DatabaseError> {
        let started = Instant::now();
        let conn = self.readers.acquire()?;
        self.metrics.record_reader_wait(started.elapsed());
        Ok(conn)
    }

    fn lock_writer(&self) -> Result<MutexGuard<'_, Connection>, DatabaseError> {
        self.writer.lock().map_err(|_| {
            DatabaseError::Pool("writer mutex poisoned".to_owned())
        })
    }

    fn lookup_page_anchor(
        &self,
        key: &str,
        subject_id: &str,
        target_page: u64,
    ) -> Option<(u64, String)> {
        self.page_cache.lock().ok().and_then(|mut cache| {
            cache.lookup_anchor(key, subject_id, target_page)
        })
    }

    fn store_page_anchor(
        &self,
        key: String,
        subject_id: &str,
        target_page: u64,
        cursor: String,
    ) {
        if let Ok(mut cache) = self.page_cache.lock() {
            cache.store_anchor(key, subject_id, target_page, cursor);
        }
    }

    fn lookup_count_cache(&self, key: &str, subject_id: &str) -> Option<u64> {
        let cached = self
            .page_cache
            .lock()
            .ok()
            .and_then(|mut cache| cache.lookup_count(key, subject_id));
        self.metrics.record_count_cache_lookup(cached.is_some());
        cached
    }

    fn store_count_cache(&self, key: String, subject_id: &str, total: u64) {
        if let Ok(mut cache) = self.page_cache.lock() {
            cache.store_count(key, subject_id, total);
        }
    }

    fn bump_subject_generation(&self, subject_id: &str) {
        if let Ok(mut cache) = self.page_cache.lock() {
            cache.bump_subject_generation(subject_id);
        }
    }

    fn run_shutdown_maintenance(&self) -> Result<(), DatabaseError> {
        let conn = self.lock_writer()?;
        conn.execute_batch("PRAGMA optimize; PRAGMA wal_checkpoint(TRUNCATE);")
            .map_err(|e| DatabaseError::Query(e.to_string()))
    }
}

struct ConnectionPool {
    connections: Mutex<Vec<Connection>>,
    available: Condvar,
}

impl ConnectionPool {
    const fn new(connections: Vec<Connection>) -> Self {
        Self {
            connections: Mutex::new(connections),
            available: Condvar::new(),
        }
    }

    fn acquire(self: &Arc<Self>) -> Result<PooledConnection, DatabaseError> {
        let mut guard = self.connections.lock().map_err(|_| {
            DatabaseError::Pool("reader pool mutex poisoned".to_owned())
        })?;

        while guard.is_empty() {
            guard = self.available.wait(guard).map_err(|_| {
                DatabaseError::Pool("reader pool wait poisoned".to_owned())
            })?;
        }

        let conn = guard.pop().ok_or_else(|| {
            DatabaseError::Pool("reader pool exhausted".to_owned())
        })?;
        drop(guard);

        Ok(PooledConnection {
            conn: Some(conn),
            pool: Arc::clone(self),
        })
    }

    fn release(&self, conn: Connection) {
        if let Ok(mut guard) = self.connections.lock() {
            guard.push(conn);
            self.available.notify_one();
        }
    }
}

struct PooledConnection {
    conn: Option<Connection>,
    pool: Arc<ConnectionPool>,
}

impl std::ops::Deref for PooledConnection {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        self.conn.as_ref().expect("pooled connection missing")
    }
}

impl Drop for PooledConnection {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            self.pool.release(conn);
        }
    }
}

fn open_writer_connection(
    path: &Path,
    sync_mode: &str,
    tuning: &SqliteTuning,
) -> Result<Connection, DatabaseError> {
    let flags = OpenFlags::SQLITE_OPEN_READ_WRITE
        | OpenFlags::SQLITE_OPEN_CREATE
        | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(path, flags).map_err(|e| {
        error!(
            path = %path.display(),
            error = %e,
            "Failed to open SQLite writer connection"
        );
        DatabaseError::ConnectionOpen(e.to_string())
    })?;

    conn.execute_batch(&format!(
        "
        PRAGMA journal_mode=WAL;
        PRAGMA busy_timeout=5000;
        PRAGMA synchronous={};
        PRAGMA wal_autocheckpoint={};
        PRAGMA journal_size_limit={};
        PRAGMA temp_store=MEMORY;
        PRAGMA cache_size={};
        PRAGMA mmap_size={};
        PRAGMA optimize=0x10002;
        ",
        sync_mode,
        tuning.wal_autocheckpoint_pages,
        tuning.journal_size_limit_bytes,
        tuning.cache_size_kb,
        tuning.mmap_size_bytes,
    ))
    .map_err(|e| {
        error!(error = %e, "Failed to apply SQLite writer PRAGMA tuning");
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

    conn.set_prepared_statement_cache_capacity(WRITER_STATEMENT_CACHE_CAPACITY);

    Ok(conn)
}

fn open_reader_connection(
    path: &Path,
    tuning: &SqliteTuning,
) -> Result<Connection, DatabaseError> {
    let flags =
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX;
    let conn = Connection::open_with_flags(path, flags).map_err(|e| {
        error!(
            path = %path.display(),
            error = %e,
            "Failed to open SQLite reader connection"
        );
        DatabaseError::ConnectionOpen(e.to_string())
    })?;

    conn.execute_batch(&format!(
        "
        PRAGMA busy_timeout=5000;
        PRAGMA temp_store=MEMORY;
        PRAGMA cache_size={};
        PRAGMA mmap_size={};
        PRAGMA query_only=ON;
        ",
        tuning.cache_size_kb, tuning.mmap_size_bytes,
    ))
    .map_err(|e| {
        error!(error = %e, "Failed to apply SQLite reader PRAGMA tuning");
        DatabaseError::ConnectionOpen(e.to_string())
    })?;

    conn.set_prepared_statement_cache_capacity(READER_STATEMENT_CACHE_CAPACITY);

    Ok(conn)
}

/// Compute SQLite tuning parameters from available RAM.
///
/// SQLite is single-writer so CPU cores don't affect tuning here.
/// Designed for a shared Docker container with 3 co-located SQLite instances
/// plus a libp2p process - total DB cache footprint stays at ~6 % of host RAM.
fn tuning_for_ram(ram_mb: u64) -> SqliteTuning {
    // Cache: 2 % of RAM, floor 8 MB, cap 1 GB.
    let cache_mb = (ram_mb * 2 / 100).clamp(8, 1024);
    let cache_size_kb = -(cache_mb as i64 * 1024); // negative = KB in SQLite

    // mmap: half of cache, hard cap 128 MB.
    // Supplements the page cache for sequential reads; kept below cache to
    // avoid doubling memory pressure in a shared container.
    let mmap_size_bytes = (cache_mb as i64 / 2).min(128) * 1024 * 1024;

    // WAL checkpoint: fire when WAL ~= cache/2.
    // pages = (cache_mb/2 MB) / (4 KB/page) = cache_mb * 128.
    // Floor 1000 (SQLite default, prevents thrashing on tiny RAM).
    // Cap 8000 (32 MB WAL max, bounds checkpoint stall under write bursts).
    let wal_autocheckpoint_pages = (cache_mb as i64 * 128).clamp(1_000, 8_000);

    // journal_size_limit: 3x the WAL ceiling - a safety net never reached in
    // normal operation (checkpoints fire first); prevents runaway WAL growth
    // if a checkpoint is delayed. Cap 256 MB to bound disk use in Docker.
    let journal_size_limit_bytes = (wal_autocheckpoint_pages * 4096 * 3)
        .clamp(32 * 1024 * 1024, 256 * 1024 * 1024);

    SqliteTuning {
        wal_autocheckpoint_pages,
        journal_size_limit_bytes,
        cache_size_kb,
        mmap_size_bytes,
    }
}

#[derive(Clone, Copy)]
struct SqliteTuning {
    wal_autocheckpoint_pages: i64,
    journal_size_limit_bytes: i64,
    cache_size_kb: i64,
    mmap_size_bytes: i64,
}

fn get_aborts_from_conn(
    conn: &Connection,
    runtime: &SqliteRuntime,
    subject_id: &str,
    query: AbortsQuery,
) -> Result<PaginatorAborts, DatabaseError> {
    let quantity = query.quantity.unwrap_or(50).max(1);
    let mut page = query.page.unwrap_or(1).max(1);
    let total = count_aborts_from_conn(conn, runtime, subject_id, &query)?;

    if total == 0 {
        return Ok(PaginatorAborts {
            paginator: Paginator {
                pages: 0,
                next: None,
                prev: None,
            },
            events: Vec::new(),
        });
    }

    let mut pages = total.div_ceil(quantity);
    if pages == 0 {
        pages = 1;
    }
    if page > pages {
        page = pages;
    }

    let key = build_aborts_page_cache_key(subject_id, &query);
    let cursor_query = CursorAbortsQuery::from_public(query);
    let events = resolve_abort_page_from_anchors(
        conn,
        runtime,
        subject_id,
        page,
        pages,
        &key,
        cursor_query,
    )?;

    Ok(PaginatorAborts {
        paginator: build_page_paginator(page, pages),
        events,
    })
}

fn get_subject_state_from_conn(
    conn: &Connection,
    subject_id: &str,
) -> Result<SubjectDB, DatabaseError> {
    let subject_id = subject_id.to_owned();
    let mut stmt = conn
        .prepare_cached(SQL_GET_SUBJECT_STATE)
        .map_err(|e| DatabaseError::Query(e.to_string()))?;

    stmt.query_row(params![subject_id], |row| {
        let tracker_visibility = row
            .get::<usize, Option<String>>(13)?
            .map(|tracker_visibility_str| {
                serde_json::from_str::<TrackerVisibilityStateDB>(
                    &tracker_visibility_str,
                )
                .map_err(|e| {
                    rusqlite::Error::FromSqlConversionFailure(
                        13,
                        Type::Text,
                        Box::new(e),
                    )
                })
            })
            .transpose()?;
        let props_str: String = row.get(14)?;
        let props_val: Value =
            serde_json::from_str(&props_str).map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    14,
                    Type::Text,
                    Box::new(e),
                )
            })?;

        let genesis_gov_version = u64::try_from(row.get::<usize, i64>(4)?)
            .map_err(|e| {
                rusqlite::Error::FromSqlConversionFailure(
                    4,
                    Type::Integer,
                    Box::new(e),
                )
            })?;
        let sn = u64::try_from(row.get::<usize, i64>(8)?).map_err(|e| {
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
            tracker_visibility,
            properties: props_val,
        })
    })
    .map_err(|e| match e {
        rusqlite::Error::QueryReturnedNoRows => {
            DatabaseError::SubjectNotFound(subject_id)
        }
        _ => DatabaseError::Query(e.to_string()),
    })
}

fn get_governances_from_conn(
    conn: &Connection,
    active: Option<bool>,
) -> Result<Vec<GovsData>, DatabaseError> {
    let mut stmt = conn
        .prepare_cached(match active {
            Some(_) => SQL_GET_REGISTER_GOVS_BY_ACTIVE,
            None => SQL_GET_REGISTER_GOVS,
        })
        .map_err(|e| DatabaseError::Query(e.to_string()))?;

    let rows = match active {
        Some(active) => stmt
            .query_map(params![if active { 1 } else { 0 }], map_governance_row)
            .map_err(|e| DatabaseError::Query(e.to_string()))?,
        None => stmt
            .query_map([], map_governance_row)
            .map_err(|e| DatabaseError::Query(e.to_string()))?,
    };

    rows.map(|row| row.map_err(|e| DatabaseError::Query(e.to_string())))
        .collect()
}

fn get_subjects_from_conn(
    conn: &Connection,
    governance_id: &str,
    active: Option<bool>,
    schema_id: Option<String>,
) -> Result<Vec<SubjsData>, DatabaseError> {
    let mut stmt = conn
        .prepare_cached(match (active, schema_id.as_ref()) {
            (None, None) => SQL_GET_REGISTER_SUBJECTS,
            (Some(_), None) => SQL_GET_REGISTER_SUBJECTS_BY_ACTIVE,
            (None, Some(_)) => SQL_GET_REGISTER_SUBJECTS_BY_SCHEMA,
            (Some(_), Some(_)) => SQL_GET_REGISTER_SUBJECTS_BY_ACTIVE_SCHEMA,
        })
        .map_err(|e| DatabaseError::Query(e.to_string()))?;

    let rows = match (active, schema_id.as_ref()) {
        (None, None) => stmt
            .query_map(params![governance_id], map_register_subject_row)
            .map_err(|e| DatabaseError::Query(e.to_string()))?,
        (Some(active), None) => stmt
            .query_map(
                params![governance_id, if active { 1 } else { 0 }],
                map_register_subject_row,
            )
            .map_err(|e| DatabaseError::Query(e.to_string()))?,
        (None, Some(schema_id)) => stmt
            .query_map(
                params![governance_id, schema_id],
                map_register_subject_row,
            )
            .map_err(|e| DatabaseError::Query(e.to_string()))?,
        (Some(active), Some(schema_id)) => stmt
            .query_map(
                params![governance_id, if active { 1 } else { 0 }, schema_id],
                map_register_subject_row,
            )
            .map_err(|e| DatabaseError::Query(e.to_string()))?,
    };

    let subjects = rows
        .map(|row| row.map_err(|e| DatabaseError::Query(e.to_string())))
        .collect::<Result<Vec<_>, DatabaseError>>()?;

    if !subjects.is_empty() || register_governance_exists(conn, governance_id)?
    {
        Ok(subjects)
    } else {
        Err(DatabaseError::GovernanceNotFound(governance_id.to_owned()))
    }
}

fn get_events_from_conn(
    conn: &Connection,
    runtime: &SqliteRuntime,
    subject_id: &str,
    query: EventsQuery,
) -> Result<PaginatorEvents, DatabaseError> {
    let quantity = query.quantity.unwrap_or(50).max(1);
    let mut page = query.page.unwrap_or(1).max(1);
    let total = count_events_from_conn(conn, runtime, subject_id, &query)?;

    if total == 0 {
        return Err(DatabaseError::NoEvents(subject_id.to_owned()));
    }

    let mut pages = total.div_ceil(quantity);
    if pages == 0 {
        pages = 1;
    }
    if page > pages {
        page = pages;
    }

    let key = build_events_page_cache_key(subject_id, &query)?;
    let cursor_query = CursorEventsQuery::from_public(query);
    let events = resolve_event_page_from_anchors(
        conn,
        runtime,
        subject_id,
        page,
        pages,
        &key,
        cursor_query,
    )?;

    Ok(PaginatorEvents {
        paginator: build_page_paginator(page, pages),
        events,
    })
}

fn get_event_sn_from_conn(
    conn: &Connection,
    subject_id: &str,
    sn: u64,
) -> Result<LedgerDB, DatabaseError> {
    let sn_i64 = i64::try_from(sn).map_err(|_| {
        DatabaseError::IntegerConversion(format!(
            "sn out of range for SQLite INTEGER (i64): {sn}"
        ))
    })?;

    let mut stmt = conn
        .prepare_cached(SQL_GET_EVENT_SN)
        .map_err(|e| DatabaseError::Query(e.to_string()))?;

    stmt.query_row(params![subject_id, sn_i64], map_event_row)
        .map_err(|e| match e {
            rusqlite::Error::QueryReturnedNoRows => {
                DatabaseError::EventNotFound {
                    subject_id: subject_id.to_owned(),
                    sn,
                }
            }
            _ => DatabaseError::Query(e.to_string()),
        })
}

fn get_first_or_end_events_from_conn(
    conn: &Connection,
    subject_id: &str,
    quantity: Option<u64>,
    reverse: Option<bool>,
    event_type: Option<EventRequestType>,
) -> Result<Vec<LedgerDB>, DatabaseError> {
    let quantity = quantity.unwrap_or(50).max(1);
    let reverse = reverse.unwrap_or(false);
    let limit_i64 = to_sql_i64(quantity, "quantity")?;

    let (sql, event_type_param) = match (reverse, event_type) {
        (false, None) => (SQL_GET_FIRST_EVENTS, None),
        (true, None) => (SQL_GET_LAST_EVENTS, None),
        (false, Some(et)) => (
            SQL_GET_FIRST_EVENTS_BY_TYPE,
            Some(event_request_type_to_string(&et)?),
        ),
        (true, Some(et)) => (
            SQL_GET_LAST_EVENTS_BY_TYPE,
            Some(event_request_type_to_string(&et)?),
        ),
    };

    let mut stmt = conn
        .prepare_cached(sql)
        .map_err(|e| DatabaseError::Query(e.to_string()))?;

    match event_type_param {
        Some(event_type) => stmt
            .query_map(params![subject_id, event_type, limit_i64], |row| {
                map_event_row(row)
            })
            .map_err(|e| DatabaseError::Query(e.to_string()))?
            .map(|r| r.map_err(|e| DatabaseError::Query(e.to_string())))
            .collect::<Result<Vec<_>, DatabaseError>>(),
        None => stmt
            .query_map(params![subject_id, limit_i64], map_event_row)
            .map_err(|e| DatabaseError::Query(e.to_string()))?
            .map(|r| r.map_err(|e| DatabaseError::Query(e.to_string())))
            .collect::<Result<Vec<_>, DatabaseError>>(),
    }
}

const fn build_page_paginator(page: u64, pages: u64) -> Paginator {
    let prev = if page <= 1 { None } else { Some(page - 1) };
    let next = if page < pages { Some(page + 1) } else { None };

    Paginator { pages, next, prev }
}

fn page_offset(page: u64, quantity: u64) -> Result<u64, DatabaseError> {
    let page_index = page.checked_sub(1).ok_or_else(|| {
        DatabaseError::IntegerConversion(format!(
            "page underflow while building offset: {page}"
        ))
    })?;

    page_index.checked_mul(quantity).ok_or_else(|| {
        DatabaseError::IntegerConversion(format!(
            "offset overflow while building page offset: page={page}, quantity={quantity}"
        ))
    })
}

fn to_sql_i64(value: u64, field: &str) -> Result<i64, DatabaseError> {
    i64::try_from(value).map_err(|_| {
        DatabaseError::IntegerConversion(format!(
            "{field} out of range for SQLite INTEGER (i64): {value}"
        ))
    })
}

fn parse_event_cursor(cursor: &str) -> Result<i64, DatabaseError> {
    cursor.parse::<i64>().map_err(|_| {
        DatabaseError::InvalidCursor(format!(
            "event cursor must be a sequence number, got '{cursor}'"
        ))
    })
}

fn encode_event_cursor(sn: u64) -> String {
    sn.to_string()
}

fn parse_abort_cursor(cursor: &str) -> Result<(i64, String), DatabaseError> {
    let (sn_part, request_id) = cursor.split_once('|').ok_or_else(|| {
        DatabaseError::InvalidCursor(format!(
            "abort cursor must be '<sn>|<request_id>', got '{cursor}'"
        ))
    })?;
    if request_id.is_empty() {
        return Err(DatabaseError::InvalidCursor(
            "abort cursor request_id cannot be empty".to_owned(),
        ));
    }

    let sn_key = if sn_part.is_empty() {
        -1
    } else {
        sn_part.parse::<i64>().map_err(|_| {
            DatabaseError::InvalidCursor(format!(
                "abort cursor sn must be an integer, got '{sn_part}'"
            ))
        })?
    };

    Ok((sn_key, request_id.to_owned()))
}

fn encode_abort_cursor(sn: Option<u64>, request_id: &str) -> String {
    sn.map_or_else(
        || format!("|{request_id}"),
        |sn| format!("{sn}|{request_id}"),
    )
}

fn count_aborts_from_conn(
    conn: &Connection,
    runtime: &SqliteRuntime,
    subject_id: &str,
    query: &AbortsQuery,
) -> Result<u64, DatabaseError> {
    let count_cache_key = build_aborts_count_cache_key(subject_id, query);
    if let Some(total) =
        runtime.lookup_count_cache(&count_cache_key, subject_id)
    {
        return Ok(total);
    }

    let started = Instant::now();
    if query.request_id.is_none() && query.sn.is_none() {
        let mut stmt = conn
            .prepare_cached(SQL_COUNT_ABORTS_SUBJECT_ONLY)
            .map_err(|e| DatabaseError::Query(e.to_string()))?;
        let total_i64: i64 = stmt
            .query_row(params![subject_id], |row| row.get(0))
            .map_err(|e| DatabaseError::Query(e.to_string()))?;
        let total = u64::try_from(total_i64).map_err(|_| {
            DatabaseError::IntegerConversion(
                "COUNT(*) returned invalid value".to_owned(),
            )
        })?;
        runtime
            .metrics
            .record_count_query_duration(started.elapsed());
        runtime.store_count_cache(count_cache_key, subject_id, total);
        return Ok(total);
    }

    let mut where_clauses = vec!["subject_id = ?1".to_string()];
    let mut params_values: Vec<rusqlite::types::Value> =
        vec![subject_id.to_string().into()];

    if let Some(rid) = query.request_id.as_ref() {
        params_values.push(rid.clone().into());
        where_clauses.push(format!("request_id = ?{}", params_values.len()));
    }

    if let Some(sn_val) = query.sn {
        let sn_i64 = to_sql_i64(sn_val, "sn")?;
        params_values.push(sn_i64.into());
        where_clauses.push(format!("sn = ?{}", params_values.len()));
    }

    let sql = format!(
        "SELECT COUNT(*) FROM aborts WHERE {}",
        where_clauses.join(" AND ")
    );
    let params_refs: Vec<&dyn rusqlite::ToSql> = params_values
        .iter()
        .map(|v| v as &dyn rusqlite::ToSql)
        .collect();

    let total_i64: i64 = conn
        .query_row(&sql, params_refs.as_slice(), |row| row.get(0))
        .map_err(|e| DatabaseError::Query(e.to_string()))?;
    let total = u64::try_from(total_i64).map_err(|_| {
        DatabaseError::IntegerConversion(
            "COUNT(*) returned invalid value".to_owned(),
        )
    })?;
    runtime
        .metrics
        .record_count_query_duration(started.elapsed());
    runtime.store_count_cache(count_cache_key, subject_id, total);
    Ok(total)
}

fn resolve_abort_page_from_anchors(
    conn: &Connection,
    runtime: &SqliteRuntime,
    subject_id: &str,
    page: u64,
    pages: u64,
    cache_key: &str,
    query: CursorAbortsQuery,
) -> Result<Vec<AbortDB>, DatabaseError> {
    let mut current_query = query.clone();
    let mut current_page = 1;
    let mut anchor_found = false;

    if page > 1 {
        if let Some((anchor_page, cursor)) =
            runtime.lookup_page_anchor(cache_key, subject_id, page)
        {
            runtime.metrics.record_page_anchor_hit();
            current_page = anchor_page;
            current_query.cursor = Some(cursor);
            anchor_found = true;
        } else {
            runtime.metrics.record_page_anchor_miss();
        }
    }

    if page > current_page && (page - current_page) > PAGE_ANCHOR_WALK_THRESHOLD
    {
        let offset = page_offset(page, query.quantity)?;
        let aborts =
            fetch_aborts_with_offset(conn, subject_id, &query, offset)?;
        if page < pages
            && let Some(last) = aborts.last()
        {
            runtime.store_page_anchor(
                cache_key.to_owned(),
                subject_id,
                page + 1,
                encode_abort_cursor(last.sn, &last.request_id),
            );
        }
        return Ok(aborts);
    }

    if anchor_found {
        runtime
            .metrics
            .record_pages_walked_from_anchor(page.saturating_sub(current_page));
    }

    loop {
        let aborts =
            fetch_aborts_with_cursor(conn, subject_id, &current_query)?;
        if aborts.is_empty() {
            return Ok(aborts);
        }

        if current_page < pages
            && let Some(last) = aborts.last()
        {
            runtime.store_page_anchor(
                cache_key.to_owned(),
                subject_id,
                current_page + 1,
                encode_abort_cursor(last.sn, &last.request_id),
            );
        }

        if current_page == page {
            return Ok(aborts);
        }

        let Some(last) = aborts.last() else {
            return Ok(aborts);
        };
        current_query.cursor =
            Some(encode_abort_cursor(last.sn, &last.request_id));
        current_page += 1;
    }
}

fn fetch_aborts_with_cursor(
    conn: &Connection,
    subject_id: &str,
    query: &CursorAbortsQuery,
) -> Result<Vec<AbortDB>, DatabaseError> {
    if query.request_id.is_none() && query.sn.is_none() {
        return fetch_subject_only_aborts_with_cursor(conn, subject_id, query);
    }

    let mut where_clauses = vec!["subject_id = ?1".to_string()];
    let mut params_values: Vec<rusqlite::types::Value> =
        vec![subject_id.to_string().into()];

    if let Some(rid) = query.request_id.as_ref() {
        params_values.push(rid.clone().into());
        where_clauses.push(format!("request_id = ?{}", params_values.len()));
    }

    if let Some(sn_val) = query.sn {
        params_values.push(to_sql_i64(sn_val, "sn")?.into());
        where_clauses.push(format!("sn = ?{}", params_values.len()));
    }

    if let Some(cursor_value) = query.cursor.as_ref() {
        let (cursor_sn, cursor_request_id) = parse_abort_cursor(cursor_value)?;
        params_values.push(cursor_sn.into());
        let cursor_sn_idx = params_values.len();
        params_values.push(cursor_request_id.into());
        let cursor_request_id_idx = params_values.len();

        let cursor_clause = if query.reverse {
            format!(
                "(COALESCE(sn, -1) < ?{cursor_sn_idx} OR (COALESCE(sn, -1) = ?{cursor_sn_idx} AND request_id < ?{cursor_request_id_idx}))"
            )
        } else {
            format!(
                "(COALESCE(sn, -1) > ?{cursor_sn_idx} OR (COALESCE(sn, -1) = ?{cursor_sn_idx} AND request_id > ?{cursor_request_id_idx}))"
            )
        };
        where_clauses.push(cursor_clause);
    }

    let order_clause = if query.reverse {
        "COALESCE(sn, -1) DESC, request_id DESC"
    } else {
        "COALESCE(sn, -1) ASC, request_id ASC"
    };
    params_values.push(to_sql_i64(query.quantity, "quantity")?.into());
    let limit_idx = params_values.len();

    let sql = format!(
        r#"
        SELECT request_id, subject_id, sn, error, who, abort_type
        FROM aborts
        WHERE {}
        ORDER BY {}
        LIMIT ?{}
        "#,
        where_clauses.join(" AND "),
        order_clause,
        limit_idx
    );

    let params_refs: Vec<&dyn rusqlite::ToSql> = params_values
        .iter()
        .map(|value| value as &dyn rusqlite::ToSql)
        .collect();
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| DatabaseError::Query(e.to_string()))?;

    stmt.query_map(params_refs.as_slice(), map_abort_row)
        .map_err(|e| DatabaseError::Query(e.to_string()))?
        .map(|row| row.map_err(|e| DatabaseError::Query(e.to_string())))
        .collect::<Result<Vec<_>, DatabaseError>>()
}

fn fetch_subject_only_aborts_with_cursor(
    conn: &Connection,
    subject_id: &str,
    query: &CursorAbortsQuery,
) -> Result<Vec<AbortDB>, DatabaseError> {
    let limit_i64 = to_sql_i64(query.quantity, "quantity")?;
    match (query.reverse, query.cursor.as_ref()) {
        (false, None) => {
            let mut stmt = conn
                .prepare_cached(SQL_GET_ABORTS_SUBJECT_ONLY_ASC)
                .map_err(|e| DatabaseError::Query(e.to_string()))?;
            stmt.query_map(params![subject_id, limit_i64], |row| {
                map_abort_row(row)
            })
            .map_err(|e| DatabaseError::Query(e.to_string()))?
            .map(|row| row.map_err(|e| DatabaseError::Query(e.to_string())))
            .collect::<Result<Vec<_>, DatabaseError>>()
        }
        (false, Some(cursor)) => {
            let (cursor_sn, cursor_request_id) = parse_abort_cursor(cursor)?;
            let mut stmt = conn
                .prepare_cached(SQL_GET_ABORTS_SUBJECT_ONLY_AFTER_ASC)
                .map_err(|e| DatabaseError::Query(e.to_string()))?;
            stmt.query_map(
                params![subject_id, cursor_sn, cursor_request_id, limit_i64],
                map_abort_row,
            )
            .map_err(|e| DatabaseError::Query(e.to_string()))?
            .map(|row| row.map_err(|e| DatabaseError::Query(e.to_string())))
            .collect::<Result<Vec<_>, DatabaseError>>()
        }
        (true, None) => {
            let mut stmt = conn
                .prepare_cached(SQL_GET_ABORTS_SUBJECT_ONLY_DESC)
                .map_err(|e| DatabaseError::Query(e.to_string()))?;
            stmt.query_map(params![subject_id, limit_i64], |row| {
                map_abort_row(row)
            })
            .map_err(|e| DatabaseError::Query(e.to_string()))?
            .map(|row| row.map_err(|e| DatabaseError::Query(e.to_string())))
            .collect::<Result<Vec<_>, DatabaseError>>()
        }
        (true, Some(cursor)) => {
            let (cursor_sn, cursor_request_id) = parse_abort_cursor(cursor)?;
            let mut stmt = conn
                .prepare_cached(SQL_GET_ABORTS_SUBJECT_ONLY_BEFORE_DESC)
                .map_err(|e| DatabaseError::Query(e.to_string()))?;
            stmt.query_map(
                params![subject_id, cursor_sn, cursor_request_id, limit_i64],
                map_abort_row,
            )
            .map_err(|e| DatabaseError::Query(e.to_string()))?
            .map(|row| row.map_err(|e| DatabaseError::Query(e.to_string())))
            .collect::<Result<Vec<_>, DatabaseError>>()
        }
    }
}

fn fetch_aborts_with_offset(
    conn: &Connection,
    subject_id: &str,
    query: &CursorAbortsQuery,
    offset: u64,
) -> Result<Vec<AbortDB>, DatabaseError> {
    let limit_i64 = to_sql_i64(query.quantity, "quantity")?;
    let offset_i64 = to_sql_i64(offset, "offset")?;

    if query.request_id.is_none() && query.sn.is_none() {
        let sql = if query.reverse {
            SQL_JUMP_ABORTS_SUBJECT_ONLY_DESC
        } else {
            SQL_JUMP_ABORTS_SUBJECT_ONLY_ASC
        };
        let mut stmt = conn
            .prepare_cached(sql)
            .map_err(|e| DatabaseError::Query(e.to_string()))?;
        return stmt
            .query_map(params![subject_id, limit_i64, offset_i64], |row| {
                map_abort_row(row)
            })
            .map_err(|e| DatabaseError::Query(e.to_string()))?
            .map(|row| row.map_err(|e| DatabaseError::Query(e.to_string())))
            .collect::<Result<Vec<_>, DatabaseError>>();
    }

    let mut where_clauses = vec!["subject_id = ?1".to_string()];
    let mut params_values: Vec<rusqlite::types::Value> =
        vec![subject_id.to_string().into()];

    if let Some(rid) = query.request_id.as_ref() {
        params_values.push(rid.clone().into());
        where_clauses.push(format!("request_id = ?{}", params_values.len()));
    }

    if let Some(sn_val) = query.sn {
        params_values.push(to_sql_i64(sn_val, "sn")?.into());
        where_clauses.push(format!("sn = ?{}", params_values.len()));
    }

    params_values.push(limit_i64.into());
    let limit_idx = params_values.len();
    params_values.push(offset_i64.into());
    let offset_idx = params_values.len();
    let order_clause = if query.reverse {
        "COALESCE(sn, -1) DESC, request_id DESC"
    } else {
        "COALESCE(sn, -1) ASC, request_id ASC"
    };

    let sql = format!(
        r#"
        WITH page_keys AS (
            SELECT request_id
            FROM aborts
            WHERE {}
            ORDER BY {}
            LIMIT ?{} OFFSET ?{}
        )
        SELECT a.request_id, a.subject_id, a.sn, a.error, a.who, a.abort_type
        FROM aborts a
        JOIN page_keys k ON a.request_id = k.request_id
        ORDER BY {}
        "#,
        where_clauses.join(" AND "),
        order_clause,
        limit_idx,
        offset_idx,
        order_clause
    );

    let params_refs: Vec<&dyn rusqlite::ToSql> = params_values
        .iter()
        .map(|value| value as &dyn rusqlite::ToSql)
        .collect();
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| DatabaseError::Query(e.to_string()))?;

    stmt.query_map(params_refs.as_slice(), map_abort_row)
        .map_err(|e| DatabaseError::Query(e.to_string()))?
        .map(|row| row.map_err(|e| DatabaseError::Query(e.to_string())))
        .collect::<Result<Vec<_>, DatabaseError>>()
}

fn count_events_from_conn(
    conn: &Connection,
    runtime: &SqliteRuntime,
    subject_id: &str,
    query: &EventsQuery,
) -> Result<u64, DatabaseError> {
    let count_cache_key = build_events_count_cache_key(subject_id, query)?;
    if let Some(total) =
        runtime.lookup_count_cache(&count_cache_key, subject_id)
    {
        return Ok(total);
    }

    let started = Instant::now();
    if query.event_request_ts.is_none()
        && query.event_ledger_ts.is_none()
        && query.sink_ts.is_none()
        && query.event_type.is_none()
    {
        let mut stmt = conn
            .prepare_cached(SQL_COUNT_EVENTS_SUBJECT_ONLY)
            .map_err(|e| DatabaseError::Query(e.to_string()))?;
        let total_i64: i64 = stmt
            .query_row(params![subject_id], |row| row.get(0))
            .map_err(|e| DatabaseError::Query(e.to_string()))?;
        let total = u64::try_from(total_i64).map_err(|_| {
            DatabaseError::IntegerConversion(
                "COUNT(*) returned invalid value".to_owned(),
            )
        })?;
        runtime
            .metrics
            .record_count_query_duration(started.elapsed());
        runtime.store_count_cache(count_cache_key, subject_id, total);
        return Ok(total);
    }

    let mut where_clauses = vec!["subject_id = ?1".to_string()];
    let mut params_values: Vec<rusqlite::types::Value> =
        vec![subject_id.to_string().into()];
    add_event_time_filters(
        &mut where_clauses,
        &mut params_values,
        query.event_request_ts.clone(),
        query.event_ledger_ts.clone(),
        query.sink_ts.clone(),
    )?;

    if let Some(event_type) = query.event_type.as_ref() {
        params_values.push(event_request_type_to_string(event_type)?.into());
        where_clauses.push(format!("event_type = ?{}", params_values.len()));
    }

    let sql = format!(
        "SELECT COUNT(*) FROM events WHERE {}",
        where_clauses.join(" AND ")
    );
    let params_refs: Vec<&dyn rusqlite::ToSql> = params_values
        .iter()
        .map(|value| value as &dyn rusqlite::ToSql)
        .collect();
    let total_i64: i64 = conn
        .query_row(&sql, params_refs.as_slice(), |row| row.get(0))
        .map_err(|e| DatabaseError::Query(e.to_string()))?;
    let total = u64::try_from(total_i64).map_err(|_| {
        DatabaseError::IntegerConversion(
            "COUNT(*) returned invalid value".to_owned(),
        )
    })?;
    runtime
        .metrics
        .record_count_query_duration(started.elapsed());
    runtime.store_count_cache(count_cache_key, subject_id, total);
    Ok(total)
}

fn resolve_event_page_from_anchors(
    conn: &Connection,
    runtime: &SqliteRuntime,
    subject_id: &str,
    page: u64,
    pages: u64,
    cache_key: &str,
    query: CursorEventsQuery,
) -> Result<Vec<LedgerDB>, DatabaseError> {
    let mut current_query = query.clone();
    let mut current_page = 1;
    let mut anchor_found = false;

    if page > 1 {
        if let Some((anchor_page, cursor)) =
            runtime.lookup_page_anchor(cache_key, subject_id, page)
        {
            runtime.metrics.record_page_anchor_hit();
            current_page = anchor_page;
            current_query.cursor = Some(cursor);
            anchor_found = true;
        } else {
            runtime.metrics.record_page_anchor_miss();
        }
    }

    if page > current_page && (page - current_page) > PAGE_ANCHOR_WALK_THRESHOLD
    {
        let offset = page_offset(page, query.quantity)?;
        let events =
            fetch_events_with_offset(conn, subject_id, &query, offset)?;
        if events.is_empty() {
            return Err(DatabaseError::NoEvents(subject_id.to_owned()));
        }
        if page < pages
            && let Some(last) = events.last()
        {
            runtime.store_page_anchor(
                cache_key.to_owned(),
                subject_id,
                page + 1,
                encode_event_cursor(last.sn),
            );
        }
        return Ok(events);
    }

    if anchor_found {
        runtime
            .metrics
            .record_pages_walked_from_anchor(page.saturating_sub(current_page));
    }

    loop {
        let events =
            fetch_events_with_cursor(conn, subject_id, &current_query)?;
        if events.is_empty() {
            return Err(DatabaseError::NoEvents(subject_id.to_owned()));
        }

        if current_page < pages
            && let Some(last) = events.last()
        {
            runtime.store_page_anchor(
                cache_key.to_owned(),
                subject_id,
                current_page + 1,
                encode_event_cursor(last.sn),
            );
        }

        if current_page == page {
            return Ok(events);
        }

        let Some(last) = events.last() else {
            return Err(DatabaseError::NoEvents(subject_id.to_owned()));
        };
        current_query.cursor = Some(encode_event_cursor(last.sn));
        current_page += 1;
    }
}

fn fetch_events_with_cursor(
    conn: &Connection,
    subject_id: &str,
    query: &CursorEventsQuery,
) -> Result<Vec<LedgerDB>, DatabaseError> {
    if query.event_request_ts.is_none()
        && query.event_ledger_ts.is_none()
        && query.sink_ts.is_none()
        && query.event_type.is_none()
    {
        return fetch_subject_only_events_with_cursor(conn, subject_id, query);
    }

    let mut where_clauses = vec!["subject_id = ?1".to_string()];
    let mut params_values: Vec<rusqlite::types::Value> =
        vec![subject_id.to_string().into()];

    add_event_time_filters(
        &mut where_clauses,
        &mut params_values,
        query.event_request_ts.clone(),
        query.event_ledger_ts.clone(),
        query.sink_ts.clone(),
    )?;

    if let Some(event_type) = query.event_type.as_ref() {
        params_values.push(event_request_type_to_string(event_type)?.into());
        where_clauses.push(format!("event_type = ?{}", params_values.len()));
    }

    if let Some(cursor) = query.cursor.as_ref() {
        params_values.push(parse_event_cursor(cursor)?.into());
        let cursor_idx = params_values.len();
        where_clauses.push(if query.reverse {
            format!("sn < ?{cursor_idx}")
        } else {
            format!("sn > ?{cursor_idx}")
        });
    }

    params_values.push(to_sql_i64(query.quantity, "quantity")?.into());
    let limit_idx = params_values.len();

    let sql = format!(
        r#"
        SELECT
            subject_id, sn, event_request_timestamp, event_ledger_timestamp, sink_timestamp, event, event_type
        FROM events
        WHERE {}
        ORDER BY {}
        LIMIT ?{}
        "#,
        where_clauses.join(" AND "),
        if query.reverse { "sn DESC" } else { "sn ASC" },
        limit_idx
    );

    let params_refs: Vec<&dyn rusqlite::ToSql> = params_values
        .iter()
        .map(|value| value as &dyn rusqlite::ToSql)
        .collect();
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| DatabaseError::Query(e.to_string()))?;

    stmt.query_map(params_refs.as_slice(), map_event_row)
        .map_err(|e| DatabaseError::Query(e.to_string()))?
        .map(|row| row.map_err(|e| DatabaseError::Query(e.to_string())))
        .collect::<Result<Vec<_>, DatabaseError>>()
}

fn fetch_subject_only_events_with_cursor(
    conn: &Connection,
    subject_id: &str,
    query: &CursorEventsQuery,
) -> Result<Vec<LedgerDB>, DatabaseError> {
    let limit_i64 = to_sql_i64(query.quantity, "quantity")?;
    match (query.reverse, query.cursor.as_ref()) {
        (false, None) => {
            let mut stmt = conn
                .prepare_cached(SQL_GET_EVENTS_SUBJECT_ONLY_ASC)
                .map_err(|e| DatabaseError::Query(e.to_string()))?;
            stmt.query_map(params![subject_id, limit_i64], |row| {
                map_event_row(row)
            })
            .map_err(|e| DatabaseError::Query(e.to_string()))?
            .map(|row| row.map_err(|e| DatabaseError::Query(e.to_string())))
            .collect::<Result<Vec<_>, DatabaseError>>()
        }
        (false, Some(cursor)) => {
            let mut stmt = conn
                .prepare_cached(SQL_GET_EVENTS_SUBJECT_ONLY_AFTER_ASC)
                .map_err(|e| DatabaseError::Query(e.to_string()))?;
            stmt.query_map(
                params![subject_id, parse_event_cursor(cursor)?, limit_i64],
                map_event_row,
            )
            .map_err(|e| DatabaseError::Query(e.to_string()))?
            .map(|row| row.map_err(|e| DatabaseError::Query(e.to_string())))
            .collect::<Result<Vec<_>, DatabaseError>>()
        }
        (true, None) => {
            let mut stmt = conn
                .prepare_cached(SQL_GET_EVENTS_SUBJECT_ONLY_DESC)
                .map_err(|e| DatabaseError::Query(e.to_string()))?;
            stmt.query_map(params![subject_id, limit_i64], |row| {
                map_event_row(row)
            })
            .map_err(|e| DatabaseError::Query(e.to_string()))?
            .map(|row| row.map_err(|e| DatabaseError::Query(e.to_string())))
            .collect::<Result<Vec<_>, DatabaseError>>()
        }
        (true, Some(cursor)) => {
            let mut stmt = conn
                .prepare_cached(SQL_GET_EVENTS_SUBJECT_ONLY_BEFORE_DESC)
                .map_err(|e| DatabaseError::Query(e.to_string()))?;
            stmt.query_map(
                params![subject_id, parse_event_cursor(cursor)?, limit_i64],
                map_event_row,
            )
            .map_err(|e| DatabaseError::Query(e.to_string()))?
            .map(|row| row.map_err(|e| DatabaseError::Query(e.to_string())))
            .collect::<Result<Vec<_>, DatabaseError>>()
        }
    }
}

fn fetch_events_with_offset(
    conn: &Connection,
    subject_id: &str,
    query: &CursorEventsQuery,
    offset: u64,
) -> Result<Vec<LedgerDB>, DatabaseError> {
    let limit_i64 = to_sql_i64(query.quantity, "quantity")?;
    let offset_i64 = to_sql_i64(offset, "offset")?;

    if query.event_request_ts.is_none()
        && query.event_ledger_ts.is_none()
        && query.sink_ts.is_none()
        && query.event_type.is_none()
    {
        let sql = if query.reverse {
            SQL_JUMP_EVENTS_SUBJECT_ONLY_DESC
        } else {
            SQL_JUMP_EVENTS_SUBJECT_ONLY_ASC
        };
        let mut stmt = conn
            .prepare_cached(sql)
            .map_err(|e| DatabaseError::Query(e.to_string()))?;
        return stmt
            .query_map(params![subject_id, limit_i64, offset_i64], |row| {
                map_event_row(row)
            })
            .map_err(|e| DatabaseError::Query(e.to_string()))?
            .map(|row| row.map_err(|e| DatabaseError::Query(e.to_string())))
            .collect::<Result<Vec<_>, DatabaseError>>();
    }

    let mut where_clauses = vec!["subject_id = ?1".to_string()];
    let mut params_values: Vec<rusqlite::types::Value> =
        vec![subject_id.to_string().into()];

    add_event_time_filters(
        &mut where_clauses,
        &mut params_values,
        query.event_request_ts.clone(),
        query.event_ledger_ts.clone(),
        query.sink_ts.clone(),
    )?;

    if let Some(event_type) = query.event_type.as_ref() {
        params_values.push(event_request_type_to_string(event_type)?.into());
        where_clauses.push(format!("event_type = ?{}", params_values.len()));
    }

    params_values.push(limit_i64.into());
    let limit_idx = params_values.len();
    params_values.push(offset_i64.into());
    let offset_idx = params_values.len();
    let order_clause = if query.reverse { "sn DESC" } else { "sn ASC" };

    let sql = format!(
        r#"
        WITH page_keys AS (
            SELECT sn
            FROM events
            WHERE {}
            ORDER BY {}
            LIMIT ?{} OFFSET ?{}
        )
        SELECT
            e.subject_id, e.sn, e.event_request_timestamp, e.event_ledger_timestamp, e.sink_timestamp, e.event, e.event_type
        FROM events e
        JOIN page_keys k ON e.subject_id = ?1 AND e.sn = k.sn
        ORDER BY {}
        "#,
        where_clauses.join(" AND "),
        order_clause,
        limit_idx,
        offset_idx,
        order_clause
    );

    let params_refs: Vec<&dyn rusqlite::ToSql> = params_values
        .iter()
        .map(|value| value as &dyn rusqlite::ToSql)
        .collect();
    let mut stmt = conn
        .prepare(&sql)
        .map_err(|e| DatabaseError::Query(e.to_string()))?;

    stmt.query_map(params_refs.as_slice(), map_event_row)
        .map_err(|e| DatabaseError::Query(e.to_string()))?
        .map(|row| row.map_err(|e| DatabaseError::Query(e.to_string())))
        .collect::<Result<Vec<_>, DatabaseError>>()
}

fn add_event_time_filters(
    where_clauses: &mut Vec<String>,
    params_values: &mut Vec<rusqlite::types::Value>,
    event_request_ts: Option<TimeRange>,
    event_ledger_ts: Option<TimeRange>,
    sink_ts: Option<TimeRange>,
) -> Result<(), DatabaseError> {
    let mut add_ts_filter =
        |column: &str, range: Option<TimeRange>| -> Result<(), DatabaseError> {
            if let Some(range) = range {
                if let Some(from) = range.from {
                    params_values.push(parse_iso8601_to_nanos(&from)?.into());
                    where_clauses
                        .push(format!("{column} >= ?{}", params_values.len()));
                }
                if let Some(to) = range.to {
                    params_values.push(parse_iso8601_to_nanos(&to)?.into());
                    where_clauses
                        .push(format!("{column} <= ?{}", params_values.len()));
                }
            }
            Ok(())
        };

    add_ts_filter("event_request_timestamp", event_request_ts)?;
    add_ts_filter("event_ledger_timestamp", event_ledger_ts)?;
    add_ts_filter("sink_timestamp", sink_ts)?;
    Ok(())
}

fn build_events_page_cache_key(
    subject_id: &str,
    query: &EventsQuery,
) -> Result<String, DatabaseError> {
    Ok(format!(
        "events|subject={subject_id}|quantity={}|reverse={}|event_request_ts={}|event_ledger_ts={}|sink_ts={}|event_type={}",
        query.quantity.unwrap_or(50).max(1),
        query.reverse.unwrap_or(false),
        format_time_range(query.event_request_ts.as_ref()),
        format_time_range(query.event_ledger_ts.as_ref()),
        format_time_range(query.sink_ts.as_ref()),
        query
            .event_type
            .as_ref()
            .map(event_request_type_to_string)
            .transpose()?
            .unwrap_or_default()
    ))
}

fn build_events_count_cache_key(
    subject_id: &str,
    query: &EventsQuery,
) -> Result<String, DatabaseError> {
    Ok(format!(
        "events-count|subject={subject_id}|event_request_ts={}|event_ledger_ts={}|sink_ts={}|event_type={}",
        format_time_range(query.event_request_ts.as_ref()),
        format_time_range(query.event_ledger_ts.as_ref()),
        format_time_range(query.sink_ts.as_ref()),
        query
            .event_type
            .as_ref()
            .map(event_request_type_to_string)
            .transpose()?
            .unwrap_or_default()
    ))
}

fn build_aborts_page_cache_key(
    subject_id: &str,
    query: &AbortsQuery,
) -> String {
    format!(
        "aborts|subject={subject_id}|request_id={}|sn={}|quantity={}|reverse={}",
        query.request_id.as_deref().unwrap_or_default(),
        query.sn.map(|value| value.to_string()).unwrap_or_default(),
        query.quantity.unwrap_or(50).max(1),
        query.reverse.unwrap_or(false),
    )
}

fn build_aborts_count_cache_key(
    subject_id: &str,
    query: &AbortsQuery,
) -> String {
    format!(
        "aborts-count|subject={subject_id}|request_id={}|sn={}",
        query.request_id.as_deref().unwrap_or_default(),
        query.sn.map(|value| value.to_string()).unwrap_or_default(),
    )
}

fn format_time_range(range: Option<&TimeRange>) -> String {
    range.map_or_else(String::new, |range| {
        format!(
            "{}..{}",
            range.from.as_deref().unwrap_or_default(),
            range.to.as_deref().unwrap_or_default()
        )
    })
}

fn map_abort_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AbortDB> {
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
}

fn map_event_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<LedgerDB> {
    let event_str: String = row.get(5)?;
    let event: RequestEventDB =
        serde_json::from_str(&event_str).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                5,
                Type::Text,
                Box::new(e),
            )
        })?;

    let sn = u64::try_from(row.get::<usize, i64>(1)?).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(1, Type::Integer, Box::new(e))
    })?;
    let event_request_timestamp = u64::try_from(row.get::<usize, i64>(2)?)
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                2,
                Type::Integer,
                Box::new(e),
            )
        })?;
    let event_ledger_timestamp = u64::try_from(row.get::<usize, i64>(3)?)
        .map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                3,
                Type::Integer,
                Box::new(e),
            )
        })?;
    let sink_timestamp =
        u64::try_from(row.get::<usize, i64>(4)?).map_err(|e| {
            rusqlite::Error::FromSqlConversionFailure(
                4,
                Type::Integer,
                Box::new(e),
            )
        })?;

    let event_type_str: String = row.get(6)?;
    let event_type: EventRequestType =
        serde_json::from_value(Value::String(event_type_str)).map_err(|e| {
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
}

fn map_governance_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<GovsData> {
    Ok(GovsData {
        governance_id: row.get(0)?,
        active: row.get::<usize, i64>(1)? != 0,
        name: row.get(2)?,
        description: row.get(3)?,
    })
}

fn map_register_subject_row(
    row: &rusqlite::Row<'_>,
) -> rusqlite::Result<SubjsData> {
    let schema_id: String = row.get(1)?;
    let schema_id = schema_id.parse::<SchemaType>().map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            1,
            Type::Text,
            Box::new(std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
        )
    })?;

    Ok(SubjsData {
        subject_id: row.get(0)?,
        schema_id,
        active: row.get::<usize, i64>(2)? != 0,
        namespace: row.get(3)?,
        name: row.get(4)?,
        description: row.get(5)?,
    })
}

fn register_governance_exists(
    conn: &Connection,
    governance_id: &str,
) -> Result<bool, DatabaseError> {
    let mut stmt = conn
        .prepare_cached(SQL_REGISTER_GOV_EXISTS)
        .map_err(|e| DatabaseError::Query(e.to_string()))?;

    match stmt.query_row(params![governance_id], |_row| Ok(())) {
        Ok(()) => Ok(true),
        Err(rusqlite::Error::QueryReturnedNoRows) => Ok(false),
        Err(e) => Err(DatabaseError::Query(e.to_string())),
    }
}

fn insert_event_with_stmt(
    stmt: &mut rusqlite::CachedStatement<'_>,
    event: &Ledger,
) -> Result<(), DatabaseError> {
    let event_db =
        event.build_ledger_db(event.ledger_seal_signature.timestamp.as_nanos());

    let sn_i64 = i64::try_from(event_db.sn).map_err(|_| {
        DatabaseError::IntegerConversion(format!(
            "sn out of range for SQLite INTEGER (i64): {}",
            event_db.sn
        ))
    })?;
    let req_ts_i64 =
        i64::try_from(event_db.event_request_timestamp).map_err(|_| {
            DatabaseError::IntegerConversion(format!(
                "event_request_timestamp out of range for SQLite INTEGER (i64): {}",
                event_db.event_request_timestamp
            ))
        })?;
    let ledger_ts_i64 =
        i64::try_from(event_db.event_ledger_timestamp).map_err(|_| {
            DatabaseError::IntegerConversion(format!(
                "event_ledger_timestamp out of range for SQLite INTEGER (i64): {}",
                event_db.event_ledger_timestamp
            ))
        })?;
    let sink_timestamp_i64 =
        i64::try_from(event_db.sink_timestamp).map_err(|_| {
            DatabaseError::IntegerConversion(format!(
                "sink_timestamp out of range for SQLite INTEGER (i64): {}",
                event_db.sink_timestamp
            ))
        })?;

    let event_json = serde_json::to_string(&event_db.event)
        .map_err(|e| DatabaseError::JsonSerialize(e.to_string()))?;
    let event_type_str = event_request_type_to_string(&event_db.event_type)?;

    stmt.execute(params![
        event_db.subject_id,
        sn_i64,
        req_ts_i64,
        ledger_ts_i64,
        sink_timestamp_i64,
        event_json,
        event_type_str
    ])
    .map_err(|e| DatabaseError::Query(e.to_string()))?;

    Ok(())
}

fn upsert_subject_with_stmt(
    stmt: &mut rusqlite::CachedStatement<'_>,
    s: &SubjectDB,
) -> Result<(), DatabaseError> {
    let properties_json = serde_json::to_string(&s.properties)
        .map_err(|e| DatabaseError::JsonSerialize(e.to_string()))?;
    let tracker_visibility_json = s
        .tracker_visibility
        .as_ref()
        .map(serde_json::to_string)
        .transpose()
        .map_err(|e| DatabaseError::JsonSerialize(e.to_string()))?;
    let active = if s.active { 1 } else { 0 };
    let genesis_gov_version_i64 = i64::try_from(s.genesis_gov_version)
        .map_err(|_| {
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

    stmt.execute(params![
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
        tracker_visibility_json,
        properties_json
    ])
    .map_err(|e| DatabaseError::Query(e.to_string()))?;

    Ok(())
}

fn upsert_abort_with_stmt(
    stmt: &mut rusqlite::CachedStatement<'_>,
    request_id: String,
    subject_id: String,
    sn: Option<u64>,
    error: String,
    who: String,
    abort_type: String,
) -> Result<(), DatabaseError> {
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

    stmt.execute(params![
        request_id, subject_id, sn_i64, error, who, abort_type
    ])
    .map_err(|e| DatabaseError::Query(e.to_string()))?;

    Ok(())
}

fn upsert_register_governance_with_stmt(
    stmt: &mut rusqlite::CachedStatement<'_>,
    governance_id: &str,
    active: bool,
    name: Option<String>,
    description: Option<String>,
) -> Result<(), DatabaseError> {
    stmt.execute(params![
        governance_id,
        if active { 1 } else { 0 },
        name,
        description
    ])
    .map_err(|e| DatabaseError::Query(e.to_string()))?;

    Ok(())
}

fn eol_register_governance_with_stmt(
    stmt: &mut rusqlite::CachedStatement<'_>,
    governance_id: &str,
) -> Result<(), DatabaseError> {
    stmt.execute(params![governance_id])
        .map_err(|e| DatabaseError::Query(e.to_string()))?;

    Ok(())
}

fn upsert_register_subject_with_stmt(
    stmt: &mut rusqlite::CachedStatement<'_>,
    row: RegisterSubjectRow<'_>,
) -> Result<(), DatabaseError> {
    stmt.execute(params![
        row.governance_id,
        row.subject_id,
        row.schema_id.to_string(),
        if row.active { 1 } else { 0 },
        row.namespace,
        row.name,
        row.description
    ])
    .map_err(|e| DatabaseError::Query(e.to_string()))?;

    Ok(())
}

fn eol_register_subject_with_stmt(
    stmt: &mut rusqlite::CachedStatement<'_>,
    governance_id: &str,
    subject_id: &str,
) -> Result<(), DatabaseError> {
    stmt.execute(params![governance_id, subject_id])
        .map_err(|e| DatabaseError::Query(e.to_string()))?;

    Ok(())
}

fn delete_by_subject_with_stmt(
    stmt: &mut rusqlite::CachedStatement<'_>,
    subject_id: &str,
) -> Result<(), DatabaseError> {
    stmt.execute(params![subject_id])
        .map_err(|e| DatabaseError::Query(e.to_string()))?;

    Ok(())
}

#[async_trait]
impl Subscriber<Ledger> for SqliteWriteStore {
    async fn notify(&self, event: Ledger) {
        let subject_id = event.get_subject_id().to_string();
        let sn = event.sn;

        if let Err(e) = self.persist_signed_ledger(event).await {
            error!(
                subject_id = %subject_id,
                sn = sn,
                error = %e,
                "Failed to save signed ledger to SQLite"
            );
            if let Err(e) =
                self.inner.manager.tell(DBManagerMessage::Error(e)).await
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
impl Subscriber<SinkDataEvent> for SqliteWriteStore {
    async fn notify(&self, event: SinkDataEvent) {
        let SinkDataEvent::State(metadata) = event else {
            return;
        };

        let subject_id = metadata.subject_id.clone();
        let sn = metadata.sn;

        if let Err(e) = self.persist_subject_state(*metadata).await {
            error!(
                subject_id = %subject_id,
                sn = sn,
                error = %e,
                "Failed to save subject state to SQLite"
            );
            if let Err(e) =
                self.inner.manager.tell(DBManagerMessage::Error(e)).await
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
impl Subscriber<RequestTrackingEvent> for SqliteWriteStore {
    async fn notify(&self, event: RequestTrackingEvent) {
        let request_id = event.request_id.clone();
        let subject_id = event.subject_id.clone();
        let sn = event.sn;
        let who = event.who.clone();

        if let Err(e) = self.persist_abort(event).await {
            error!(
                subject_id = %subject_id,
                request_id = %request_id,
                sn = ?sn,
                error = %e,
                "Failed to save abort record to SQLite"
            );
            if let Err(e) =
                self.inner.manager.tell(DBManagerMessage::Error(e)).await
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

#[async_trait]
impl Subscriber<RegisterEvent> for SqliteWriteStore {
    async fn notify(&self, event: RegisterEvent) {
        if let Err(e) = self.persist_register(event.clone()).await {
            error!(error = %e, event = ?event, "Failed to save register event to SQLite");
            if let Err(e) =
                self.inner.manager.tell(DBManagerMessage::Error(e)).await
            {
                error!(
                    error = %e,
                    "Failed to notify DBManager about register save error"
                );
            }
        } else {
            debug!(event = ?event, "Register event saved to SQLite successfully");
        }
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use prometheus_client::{encoding::text::encode, registry::Registry};
    use tempfile::tempdir;

    use super::*;

    fn metric_value(metrics: &str, name: &str) -> f64 {
        metrics
            .lines()
            .find_map(|line| {
                if line.starts_with(name) {
                    line.split_whitespace().nth(1)?.parse::<f64>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0.0)
    }

    #[test]
    fn writer_batch_duration_metric_is_observed() {
        let metrics = SqliteMetrics::default();
        let mut registry = Registry::default();
        metrics.register_prometheus_metrics(&mut registry);

        metrics.record_writer_batch_duration(Duration::from_millis(5));

        let mut text = String::new();
        encode(&mut text, &registry).expect("encode metrics");

        assert_eq!(
            metric_value(
                &text,
                "external_db_writer_batch_duration_seconds_count"
            ),
            1.0
        );
    }

    #[test]
    fn count_cache_lookups_track_hit_and_miss() {
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("database.db");
        let tuning = tuning_for_ram(1024);
        let runtime =
            SqliteRuntime::new(&path, "NORMAL", &tuning).expect("runtime");

        let mut registry = Registry::default();
        runtime.metrics.register_prometheus_metrics(&mut registry);

        assert_eq!(runtime.lookup_count_cache("key", "subject"), None);
        runtime.store_count_cache("key".to_owned(), "subject", 42);
        assert_eq!(runtime.lookup_count_cache("key", "subject"), Some(42));

        let mut text = String::new();
        encode(&mut text, &registry).expect("encode metrics");

        assert_eq!(
            metric_value(
                &text,
                "external_db_count_cache_lookups_total{result=\"miss\"}"
            ),
            1.0
        );
        assert_eq!(
            metric_value(
                &text,
                "external_db_count_cache_lookups_total{result=\"hit\"}"
            ),
            1.0
        );
    }
}
