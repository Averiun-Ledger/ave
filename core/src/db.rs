//! # Store module.
//!

use crate::config::{AveInternalDBConfig, AveInternalDBFeatureConfig};

#[cfg(feature = "sqlite")]
use ave_actors::SqliteManager;
use ave_actors::{Actor, ActorContext, ActorError, EncryptedKey, MachineSpec};
use ave_actors::{Collection, DbManager, PersistentActor, State, StoreError};
#[cfg(feature = "rocksdb")]
use ave_actors::{RocksDbManager, RocksDbStore};

use async_trait::async_trait;
use borsh::{BorshDeserialize, BorshSerialize};

#[derive(Clone)]
pub enum Database {
    #[cfg(feature = "rocksdb")]
    RocksDb(RocksDbManager),
    #[cfg(feature = "sqlite")]
    SQLite(SqliteManager),
}

impl Database {
    pub fn open(config: &AveInternalDBConfig, spec: Option<MachineSpec>) -> Result<Self, StoreError> {
        match &config.db {
            #[cfg(feature = "rocksdb")]
            AveInternalDBFeatureConfig::Rocksdb { path } => {
                let manager = RocksDbManager::new(path, config.durability, spec)?;
                Ok(Database::RocksDb(manager))
            }
            #[cfg(feature = "sqlite")]
            AveInternalDBFeatureConfig::Sqlite { path } => {
                let manager = SqliteManager::new(path, config.durability, spec)?;
                Ok(Database::SQLite(manager))
            }
        }
    }
}

impl DbManager<DbCollection, DbCollection> for Database {
    fn create_collection(
        &self,
        name: &str,
        prefix: &str,
    ) -> Result<DbCollection, StoreError> {
        match self {
            #[cfg(feature = "rocksdb")]
            Database::RocksDb(manager) => {
                let store = manager.create_collection(name, prefix)?;
                Ok(DbCollection::RocksDb(store))
            }
            #[cfg(feature = "sqlite")]
            Database::SQLite(manager) => {
                let store = manager.create_collection(name, prefix)?;
                Ok(DbCollection::SQLite(store))
            }
        }
    }

    fn create_state(
        &self,
        name: &str,
        prefix: &str,
    ) -> Result<DbCollection, StoreError> {
        match self {
            #[cfg(feature = "rocksdb")]
            Database::RocksDb(manager) => {
                let store = manager.create_state(name, prefix)?;
                Ok(DbCollection::RocksDb(store))
            }
            #[cfg(feature = "sqlite")]
            Database::SQLite(manager) => {
                let store = manager.create_state(name, prefix)?;
                Ok(DbCollection::SQLite(store))
            }
        }
    }
    
    fn stop(self) -> Result<(), StoreError> {
                match self {
            #[cfg(feature = "rocksdb")]
            Database::RocksDb(manager) => {
                manager.stop()
            }
            #[cfg(feature = "sqlite")]
            Database::SQLite(manager) => {
                manager.stop()
            }
        }
    }
}

pub enum DbCollection {
    #[cfg(feature = "rocksdb")]
    RocksDb(RocksDbStore),
    #[cfg(feature = "sqlite")]
    SQLite(ave_actors::SqliteCollection),
}

impl Collection for DbCollection {
    fn name(&self) -> &str {
        match self {
            #[cfg(feature = "rocksdb")]
            DbCollection::RocksDb(store) => Collection::name(store),
            #[cfg(feature = "sqlite")]
            DbCollection::SQLite(store) => Collection::name(store),
        }
    }

    fn get(&self, key: &str) -> Result<Vec<u8>, StoreError> {
        match self {
            #[cfg(feature = "rocksdb")]
            DbCollection::RocksDb(store) => Collection::get(store, key),
            #[cfg(feature = "sqlite")]
            DbCollection::SQLite(store) => Collection::get(store, key),
        }
    }

    fn put(&mut self, key: &str, data: &[u8]) -> Result<(), StoreError> {
        match self {
            #[cfg(feature = "rocksdb")]
            DbCollection::RocksDb(store) => Collection::put(store, key, data),
            #[cfg(feature = "sqlite")]
            DbCollection::SQLite(store) => Collection::put(store, key, data),
        }
    }

    fn del(&mut self, key: &str) -> Result<(), StoreError> {
        match self {
            #[cfg(feature = "rocksdb")]
            DbCollection::RocksDb(store) => Collection::del(store, key),
            #[cfg(feature = "sqlite")]
            DbCollection::SQLite(store) => Collection::del(store, key),
        }
    }

    fn iter<'a>(
        &'a self,
        reverse: bool,
    ) -> Box<dyn Iterator<Item = (String, Vec<u8>)> + 'a> {
        match self {
            #[cfg(feature = "rocksdb")]
            DbCollection::RocksDb(store) => Collection::iter(store, reverse),
            #[cfg(feature = "sqlite")]
            DbCollection::SQLite(store) => Collection::iter(store, reverse),
        }
    }

    fn purge(&mut self) -> Result<(), StoreError> {
        match self {
            #[cfg(feature = "rocksdb")]
            DbCollection::RocksDb(store) => Collection::purge(store),
            #[cfg(feature = "sqlite")]
            DbCollection::SQLite(store) => Collection::purge(store),
        }
    }
    
    fn last(&self) -> Option<(String, Vec<u8>)> {
        match self {
            #[cfg(feature = "rocksdb")]
            DbCollection::RocksDb(store) => Collection::last(store),
            #[cfg(feature = "sqlite")]
            DbCollection::SQLite(store) => Collection::last(store),
        }
    }
}

impl State for DbCollection {
    fn name(&self) -> &str {
        match self {
            #[cfg(feature = "rocksdb")]
            DbCollection::RocksDb(store) => State::name(store),
            #[cfg(feature = "sqlite")]
            DbCollection::SQLite(store) => State::name(store),
        }
    }

    fn get(&self) -> Result<Vec<u8>, StoreError> {
        match self {
            #[cfg(feature = "rocksdb")]
            DbCollection::RocksDb(store) => State::get(store),
            #[cfg(feature = "sqlite")]
            DbCollection::SQLite(store) => State::get(store),
        }
    }

    fn put(&mut self, data: &[u8]) -> Result<(), StoreError> {
        match self {
            #[cfg(feature = "rocksdb")]
            DbCollection::RocksDb(store) => State::put(store, data),
            #[cfg(feature = "sqlite")]
            DbCollection::SQLite(store) => State::put(store, data),
        }
    }

    fn del(&mut self) -> Result<(), StoreError> {
        match self {
            #[cfg(feature = "rocksdb")]
            DbCollection::RocksDb(store) => State::del(store),
            #[cfg(feature = "sqlite")]
            DbCollection::SQLite(store) => State::del(store),
        }
    }

    fn purge(&mut self) -> Result<(), StoreError> {
        match self {
            #[cfg(feature = "rocksdb")]
            DbCollection::RocksDb(store) => State::purge(store),
            #[cfg(feature = "sqlite")]
            DbCollection::SQLite(store) => State::purge(store),
        }
    }
}

#[async_trait]
pub trait Storable: PersistentActor
where
    <Self as Actor>::Event: BorshSerialize + BorshDeserialize,
{
    async fn init_store(
        &mut self,
        name: &str,
        prefix: Option<String>,
        encrypt: bool,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        // Gets database
        let db = match ctx.system().get_helper::<Database>("store").await {
            Some(db) => db,
            None => {
                return Err(ActorError::Helper {
                    name: "store".to_string(),
                    reason: "Not found".to_string(),
                });
            }
        };
        // Encrypted store?
        let encrypt_key = if encrypt {
            if let Some(encrypt_key) = ctx
                .system()
                .get_helper::<EncryptedKey>("encrypted_key")
                .await
            {
                Some(encrypt_key)
            } else {
                return Err(ActorError::Helper {
                    name: "encrypted_key".to_string(),
                    reason: "Not found".to_string(),
                });
            }
        } else {
            None
        };

        // Start store
        self.start_store(name, prefix, ctx, db, encrypt_key).await?;
        Ok(())
    }
}
