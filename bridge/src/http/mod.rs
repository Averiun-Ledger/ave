use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default)]
pub struct HttpConfig {
    pub http_address: String,
    pub https_address: Option<String>,
    pub https_cert_path: Option<PathBuf>,
    pub https_private_key_path: Option<PathBuf>,
    pub enable_doc: bool,
}

impl Default for HttpConfig {
    fn default() -> Self {
        Self {
            http_address: "0.0.0.0:3000".to_string(),
            https_address: Default::default(),
            https_cert_path: Default::default(),
            https_private_key_path: Default::default(),
            enable_doc: Default::default(),
        }
    }
}

