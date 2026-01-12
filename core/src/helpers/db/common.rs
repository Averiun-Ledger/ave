use serde::{Deserialize, Serialize};

// Internal database types that are NOT part of the public API
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct SubjectDB {
    pub name: Option<String>,
    pub description: Option<String>,
    pub subject_id: String,
    pub governance_id: String,
    pub genesis_gov_version: u64,
    pub namespace: String,
    pub schema_id: String,
    pub owner: String,
    pub creator: String,
    pub active: bool,
    pub sn: u64,
    pub properties: String,
    pub new_owner: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EventDB {
    pub subject_id: String,
    pub sn: u64,
    pub patch: Option<String>,
    pub error: Option<String>,
    pub event_req: String,
    pub succes: bool,
}