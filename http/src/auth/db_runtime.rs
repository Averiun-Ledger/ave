use super::database::DatabaseError;
use ave_actors::rusqlite::Connection;
use std::{
    mem::ManuallyDrop,
    path::Path,
    sync::{Arc, Condvar, Mutex, PoisonError},
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
    // `ManuallyDrop` lets `Drop` move the connection back into the pool
    // without an `Option` whose `None` arm would be a (technically
    // unreachable) panic in `Deref`/`DerefMut`.
    conn: ManuallyDrop<Connection>,
    pool: Arc<ConnectionPool>,
}

#[derive(Clone, Copy)]
pub(super) struct AuthSqliteTuning {
    wal_autocheckpoint_pages: i64,
    journal_size_limit_bytes: i64,
    cache_size_kb: i64,
    mmap_size_bytes: i64,
}

impl AuthSqliteTuning {
    /// Share of the tuning for one connection when `connections`
    /// serve the same base: every connection applies only its slice
    /// of the total cache budget, so the aggregate stays within the
    /// budget computed for the base instead of multiplying it.
    fn for_connections(&self, connections: usize) -> Self {
        let connections = connections.max(1) as i64;
        let total_kb = self.cache_size_kb.saturating_abs();
        Self {
            cache_size_kb: -(total_kb / connections),
            ..*self
        }
    }
}

impl AuthDbRuntime {
    pub(super) fn new(
        path: &Path,
        sync_mode: &str,
        tuning: &AuthSqliteTuning,
        pool_size: usize,
    ) -> Result<Self, DatabaseError> {
        // One cache budget per base, split across pool + maintenance.
        let conn_tuning = tuning.for_connections(pool_size + 1);
        let mut connections = Vec::with_capacity(pool_size);
        for _ in 0..pool_size {
            connections.push(open_connection(path, sync_mode, &conn_tuning)?);
        }
        let maintenance_connection =
            open_connection(path, sync_mode, &conn_tuning)?;

        Ok(Self {
            primary: Arc::new(ConnectionPool::new(connections)),
            maintenance: Arc::new(ConnectionPool::new(vec![
                maintenance_connection,
            ])),
        })
    }

    pub(super) fn acquire_primary(
        &self,
    ) -> Result<PooledConnection, DatabaseError> {
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
    const fn new(connections: Vec<Connection>) -> Self {
        Self {
            connections: Mutex::new(connections),
            available: Condvar::new(),
        }
    }

    fn acquire(self: &Arc<Self>) -> Result<PooledConnection, DatabaseError> {
        // Poison recovery is safe here: the guarded Vec has no invariants a
        // panic could break, and refusing the lock would shrink the pool or
        // hang auth forever.
        let mut guard = self
            .connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner);

        while guard.is_empty() {
            guard = self
                .available
                .wait(guard)
                .unwrap_or_else(PoisonError::into_inner);
        }

        let conn = guard.pop().ok_or_else(|| {
            DatabaseError::Connection("DB pool exhausted".to_string())
        })?;
        drop(guard);

        Ok(PooledConnection {
            conn: ManuallyDrop::new(conn),
            pool: Arc::clone(self),
        })
    }

    fn release(&self, conn: Connection) {
        let mut guard = self
            .connections
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        guard.push(conn);
        drop(guard);
        self.available.notify_one();
    }
}

impl std::ops::Deref for PooledConnection {
    type Target = Connection;

    fn deref(&self) -> &Self::Target {
        &self.conn
    }
}

impl std::ops::DerefMut for PooledConnection {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.conn
    }
}

impl Drop for PooledConnection {
    fn drop(&mut self) {
        // SAFETY: `conn` is taken exactly once here and never used
        // afterwards: `Drop` runs at most once and no code path moves the
        // connection out by value anywhere else.
        let conn = unsafe { ManuallyDrop::take(&mut self.conn) };
        self.pool.release(conn);
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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn pragma_cache_kb(conn: &ave_actors::rusqlite::Connection) -> i64 {
        conn.query_row("PRAGMA cache_size", [], |row| row.get(0))
            .expect("cache_size pragma")
    }

    #[test]
    fn pool_connections_share_one_cache_budget() {
        // 8 GiB host: 2 % is 163 MiB total for the base. Every
        // connection (pool + maintenance) must apply only its slice
        // so the aggregate stays within budget instead of
        // multiplying it.
        let dir = tempdir().expect("tempdir");
        let path = dir.path().join("auth.db");
        let tuning = auth_tuning_for_ram(8192);
        let total_kb = tuning.cache_size_kb.saturating_abs();
        assert_eq!(total_kb, 163 * 1024);
        let pool_size = 4;
        let runtime = AuthDbRuntime::new(&path, "NORMAL", &tuning, pool_size)
            .expect("runtime");

        let per_conn = total_kb / (pool_size as i64 + 1);
        let primary = runtime.primary.connections.lock().expect("primary pool");
        assert_eq!(primary.len(), pool_size);
        for conn in primary.iter() {
            assert_eq!(pragma_cache_kb(conn), -per_conn);
        }
        drop(primary);
        let maintenance = runtime.maintenance.connections.lock().expect("pool");
        assert_eq!(maintenance.len(), 1);
        assert_eq!(pragma_cache_kb(&maintenance[0]), -per_conn);
        assert!(per_conn * (pool_size as i64 + 1) <= total_kb);
    }
}
