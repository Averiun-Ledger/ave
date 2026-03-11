use super::database::DatabaseError;
use rusqlite::Connection;
use std::{
    path::Path,
    sync::{Arc, Condvar, Mutex},
};

pub(super) struct AuthDbRuntime {
    primary: Arc<ConnectionPool>,
    maintenance: Arc<ConnectionPool>,
}

struct ConnectionPool {
    connections: Mutex<Vec<Connection>>,
    available: Condvar,
}

pub(super) struct PooledConnection {
    conn: Option<Connection>,
    pool: Arc<ConnectionPool>,
}

pub(super) struct AuthSqliteTuning {
    wal_autocheckpoint_pages: i64,
    journal_size_limit_bytes: i64,
    cache_size_kb: i64,
    mmap_size_bytes: i64,
}

impl AuthDbRuntime {
    pub(super) fn new(
        path: &Path,
        sync_mode: &str,
        tuning: &AuthSqliteTuning,
        pool_size: usize,
    ) -> Result<Self, DatabaseError> {
        let mut connections = Vec::with_capacity(pool_size);
        for _ in 0..pool_size {
            connections.push(open_connection(path, sync_mode, tuning)?);
        }
        let maintenance_connection =
            open_connection(path, sync_mode, tuning)?;

        Ok(Self {
            primary: Arc::new(ConnectionPool::new(connections)),
            maintenance: Arc::new(ConnectionPool::new(vec![
                maintenance_connection,
            ])),
        })
    }

    pub(super) fn acquire_primary(&self) -> Result<PooledConnection, DatabaseError> {
        self.primary.acquire()
    }

    pub(super) fn acquire_maintenance(
        &self,
    ) -> Result<PooledConnection, DatabaseError> {
        self.maintenance.acquire()
    }

    pub(super) fn recommended_pool_size() -> usize {
        std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(4)
            .clamp(4, 8)
    }
}

impl ConnectionPool {
    fn new(connections: Vec<Connection>) -> Self {
        Self {
            connections: Mutex::new(connections),
            available: Condvar::new(),
        }
    }

    fn acquire(self: &Arc<Self>) -> Result<PooledConnection, DatabaseError> {
        let mut guard = self.connections.lock().map_err(|e| {
            DatabaseError::Connection(format!("DB pool mutex poisoned: {}", e))
        })?;

        while guard.is_empty() {
            guard = self.available.wait(guard).map_err(|e| {
                DatabaseError::Connection(format!(
                    "DB pool wait poisoned: {}",
                    e
                ))
            })?;
        }

        let conn = guard.pop().ok_or_else(|| {
            DatabaseError::Connection("DB pool exhausted".to_string())
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

impl std::ops::Deref for PooledConnection {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        self.conn.as_ref().expect("pooled connection missing")
    }
}

impl std::ops::DerefMut for PooledConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.conn.as_mut().expect("pooled connection missing")
    }
}

impl Drop for PooledConnection {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            self.pool.release(conn);
        }
    }
}

fn open_connection(
    path: &Path,
    sync_mode: &str,
    tuning: &AuthSqliteTuning,
) -> Result<Connection, DatabaseError> {
    let connection = Connection::open(path)
        .map_err(|e| DatabaseError::Connection(e.to_string()))?;

    connection
        .execute_batch(&format!(
            "PRAGMA journal_mode=WAL;
             PRAGMA busy_timeout=5000;
             PRAGMA synchronous={sync_mode};
             PRAGMA wal_autocheckpoint={wal};
             PRAGMA journal_size_limit={jsl};
             PRAGMA temp_store=MEMORY;
             PRAGMA cache_size={cache};
             PRAGMA mmap_size={mmap};
             PRAGMA foreign_keys=ON;
             PRAGMA optimize=0x10002;",
            sync_mode = sync_mode,
            wal = tuning.wal_autocheckpoint_pages,
            jsl = tuning.journal_size_limit_bytes,
            cache = tuning.cache_size_kb,
            mmap = tuning.mmap_size_bytes,
        ))
        .map_err(|e| DatabaseError::Connection(e.to_string()))?;

    Ok(connection)
}

/// Compute SQLite tuning parameters from available RAM.
///
/// Designed for a shared Docker container with 3 co-located SQLite instances
/// plus a libp2p process — total DB cache footprint stays at ~6 % of host RAM.
pub(super) fn auth_tuning_for_ram(ram_mb: u64) -> AuthSqliteTuning {
    let cache_mb = (ram_mb * 2 / 100).clamp(8, 1024);
    let cache_size_kb = -(cache_mb as i64 * 1024);
    let mmap_size_bytes = (cache_mb as i64 / 2).min(128) * 1024 * 1024;
    let wal_autocheckpoint_pages = (cache_mb as i64 * 128).clamp(1_000, 8_000);
    let journal_size_limit_bytes = (wal_autocheckpoint_pages * 4096 * 3)
        .clamp(32 * 1024 * 1024, 256 * 1024 * 1024);

    AuthSqliteTuning {
        wal_autocheckpoint_pages,
        journal_size_limit_bytes,
        cache_size_kb,
        mmap_size_bytes,
    }
}
