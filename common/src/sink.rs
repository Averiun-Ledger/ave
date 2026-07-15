//! Sink payloads exported from ledger events.

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{Error, SchemaType};

#[cfg(feature = "typescript")]
use ts_rs::TS;
#[cfg(feature = "openapi")]
use utoipa::ToSchema;

/// Event data sent to external sink consumers.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct DataToSink {
    pub payload: DataToSinkEvent,
    pub public_key: String,
    pub event_request_timestamp: u64,
    pub event_ledger_timestamp: u64,
    pub sink_timestamp: u64,
}

/// Flattened ledger event stored or emitted by sink integrations.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(tag = "event", content = "data", rename_all = "snake_case")]
pub enum DataToSinkEvent {
    Create {
        governance_id: Option<String>,
        subject_id: String,
        owner: String,
        schema_id: SchemaType,
        namespace: String,
        sn: u64,
        gov_version: u64,
        state: Value,
    },
    FactFull {
        governance_id: Option<String>,
        subject_id: String,
        schema_id: SchemaType,
        viewpoints: Vec<String>,
        issuer: String,
        owner: String,
        payload: Value,
        patch: Option<Value>,
        success: bool,
        error: Option<String>,
        sn: u64,
        gov_version: u64,
    },
    FactOpaque {
        governance_id: Option<String>,
        subject_id: String,
        schema_id: SchemaType,
        viewpoints: Vec<String>,
        owner: String,
        success: bool,
        sn: u64,
        gov_version: u64,
    },
    Transfer {
        governance_id: Option<String>,
        subject_id: String,
        schema_id: SchemaType,
        owner: String,
        new_owner: String,
        success: bool,
        error: Option<String>,
        sn: u64,
        gov_version: u64,
    },
    Confirm {
        governance_id: Option<String>,
        subject_id: String,
        schema_id: SchemaType,
        sn: u64,
        patch: Option<Value>,
        success: bool,
        error: Option<String>,
        gov_version: u64,
        name_old_owner: Option<String>,
    },
    Reject {
        governance_id: Option<String>,
        subject_id: String,
        schema_id: SchemaType,
        sn: u64,
        gov_version: u64,
    },
    Eol {
        governance_id: Option<String>,
        subject_id: String,
        schema_id: SchemaType,
        sn: u64,
        gov_version: u64,
    },
}

impl DataToSinkEvent {
    /// Returns `(subject_id, schema_id)` for the event.
    pub fn get_subject_schema(&self) -> (String, String) {
        match self {
            Self::Create {
                subject_id,
                schema_id,
                ..
            }
            | Self::FactFull {
                subject_id,
                schema_id,
                ..
            }
            | Self::FactOpaque {
                subject_id,
                schema_id,
                ..
            }
            | Self::Transfer {
                subject_id,
                schema_id,
                ..
            }
            | Self::Confirm {
                subject_id,
                schema_id,
                ..
            }
            | Self::Reject {
                subject_id,
                schema_id,
                ..
            }
            | Self::Eol {
                subject_id,
                schema_id,
                ..
            } => (subject_id.clone(), schema_id.to_string()),
        }
    }
}

/// Categorisation of sink event types used for routing/filtering.
#[derive(
    Debug, Clone, Serialize, Deserialize, Eq, Ord, PartialEq, PartialOrd,
)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(rename_all = "lowercase")]
pub enum SinkTypes {
    Create,
    Fact,
    Transfer,
    Confirm,
    Reject,
    EOL,
    All,
}

impl std::fmt::Display for SinkTypes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Create => write!(f, "Create"),
            Self::Fact => write!(f, "Fact"),
            Self::Transfer => write!(f, "Transfer"),
            Self::Confirm => write!(f, "Confirm"),
            Self::Reject => write!(f, "Reject"),
            Self::EOL => write!(f, "EOL"),
            Self::All => write!(f, "All"),
        }
    }
}

impl From<&DataToSink> for SinkTypes {
    fn from(value: &DataToSink) -> Self {
        match value.payload {
            DataToSinkEvent::Create { .. } => Self::Create,
            DataToSinkEvent::FactFull { .. }
            | DataToSinkEvent::FactOpaque { .. } => Self::Fact,
            DataToSinkEvent::Transfer { .. } => Self::Transfer,
            DataToSinkEvent::Confirm { .. } => Self::Confirm,
            DataToSinkEvent::Reject { .. } => Self::Reject,
            DataToSinkEvent::Eol { .. } => Self::EOL,
        }
    }
}

impl From<String> for SinkTypes {
    fn from(value: String) -> Self {
        match value.trim() {
            "Create" => Self::Create,
            "Fact" => Self::Fact,
            "Transfer" => Self::Transfer,
            "Confirm" => Self::Confirm,
            "Reject" => Self::Reject,
            "EOL" => Self::EOL,
            _ => Self::All,
        }
    }
}

/// Lightweight event payload sent to sinks when the event type does not match
/// the sink's full-payload filter.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct LightEvent {
    pub subject_id: String,
    pub schema_id: String,
    pub governance_id: Option<String>,
    pub sn: u64,
    pub event_type: SinkTypes,
    pub success: bool,
}

/// Event received by an external HTTP sink.
///
/// A sink may be configured to receive full [`DataToSink`] payloads or
/// lightweight [`LightEvent`] payloads depending on its `events` filter. This
/// untagged enum allows a generic sink endpoint to accept either format without
/// knowing the filter in advance.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(untagged)]
pub enum IncomingSinkEvent {
    Full(Box<DataToSink>),
    Light(LightEvent),
}

impl IncomingSinkEvent {
    /// Returns the subject identifier for the event.
    pub fn subject_id(&self) -> &str {
        match self {
            Self::Full(d) => match &d.payload {
                DataToSinkEvent::Create { subject_id, .. }
                | DataToSinkEvent::FactFull { subject_id, .. }
                | DataToSinkEvent::FactOpaque { subject_id, .. }
                | DataToSinkEvent::Transfer { subject_id, .. }
                | DataToSinkEvent::Confirm { subject_id, .. }
                | DataToSinkEvent::Reject { subject_id, .. }
                | DataToSinkEvent::Eol { subject_id, .. } => subject_id,
            },
            Self::Light(l) => &l.subject_id,
        }
    }

    /// Returns the sequence number for the event.
    pub fn sn(&self) -> u64 {
        match self {
            Self::Full(d) => match &d.payload {
                DataToSinkEvent::Create { sn, .. }
                | DataToSinkEvent::FactFull { sn, .. }
                | DataToSinkEvent::FactOpaque { sn, .. }
                | DataToSinkEvent::Transfer { sn, .. }
                | DataToSinkEvent::Confirm { sn, .. }
                | DataToSinkEvent::Reject { sn, .. }
                | DataToSinkEvent::Eol { sn, .. } => *sn,
            },
            Self::Light(l) => l.sn,
        }
    }

    /// Returns the sink event type category.
    pub fn event_type(&self) -> SinkTypes {
        match self {
            Self::Full(d) => SinkTypes::from(d.as_ref()),
            Self::Light(l) => l.event_type.clone(),
        }
    }
}

impl From<&DataToSink> for LightEvent {
    fn from(data: &DataToSink) -> Self {
        let (subject_id, schema_id) = data.payload.get_subject_schema();
        let (governance_id, sn, event_type, success) = match &data.payload {
            DataToSinkEvent::Create {
                governance_id, sn, ..
            } => (governance_id.clone(), *sn, SinkTypes::Create, true),
            DataToSinkEvent::FactFull {
                governance_id,
                sn,
                success,
                ..
            } => (governance_id.clone(), *sn, SinkTypes::Fact, *success),
            DataToSinkEvent::FactOpaque {
                governance_id,
                sn,
                success,
                ..
            } => (governance_id.clone(), *sn, SinkTypes::Fact, *success),
            DataToSinkEvent::Transfer {
                governance_id,
                sn,
                success,
                ..
            } => (governance_id.clone(), *sn, SinkTypes::Transfer, *success),
            DataToSinkEvent::Confirm {
                governance_id,
                sn,
                success,
                ..
            } => (governance_id.clone(), *sn, SinkTypes::Confirm, *success),
            DataToSinkEvent::Reject {
                governance_id, sn, ..
            } => (governance_id.clone(), *sn, SinkTypes::Reject, true),
            DataToSinkEvent::Eol {
                governance_id, sn, ..
            } => (governance_id.clone(), *sn, SinkTypes::EOL, true),
        };

        Self {
            subject_id,
            schema_id,
            governance_id,
            sn,
            event_type,
            success,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_sink_types_serde_lowercase() {
        let json = serde_json::to_string(&SinkTypes::Fact).unwrap();
        assert_eq!(json, "\"fact\"");
    }

    #[test]
    fn test_get_subject_schema_with_custom_type() {
        // Ensure get_subject_schema correctly serializes SchemaType::Type, not just reserved words.
        let event = DataToSinkEvent::FactFull {
            governance_id: None,
            subject_id: "sub_custom".to_string(),
            schema_id: SchemaType::Type("my_custom_schema".to_string()),
            viewpoints: vec![],
            issuer: "iss".to_string(),
            owner: "owner".to_string(),
            payload: json!({}),
            patch: None,
            success: true,
            error: None,
            sn: 1,
            gov_version: 1,
        };
        assert_eq!(
            event.get_subject_schema(),
            ("sub_custom".to_string(), "my_custom_schema".to_string())
        );
    }

    #[test]
    fn test_data_to_sink_event_serde_with_custom_schema() {
        let event = DataToSinkEvent::FactFull {
            governance_id: None,
            subject_id: "sub2".to_string(),
            schema_id: SchemaType::Type("custom".to_string()),
            viewpoints: vec!["vp1".to_string()],
            issuer: "iss".to_string(),
            owner: "owner2".to_string(),
            payload: json!({"k": "v"}),
            patch: None,
            success: true,
            error: None,
            sn: 1,
            gov_version: 1,
        };
        let json = serde_json::to_string(&event).unwrap();
        let decoded: DataToSinkEvent = serde_json::from_str(&json).unwrap();
        match decoded {
            DataToSinkEvent::FactFull { schema_id, .. } => {
                assert_eq!(schema_id, SchemaType::Type("custom".to_string()));
            }
            other => panic!("expected FactFull, got {:?}", other),
        }
    }

    #[test]
    fn test_data_to_sink_serde_rejects_missing_payload() {
        let json = r#"{
            "public_key": "pk",
            "event_request_timestamp": 100,
            "event_ledger_timestamp": 200,
            "sink_timestamp": 300
        }"#;
        assert!(serde_json::from_str::<DataToSink>(json).is_err());
    }

    fn valid_kafka_config() -> KafkaSinkConfig {
        KafkaSinkConfig {
            bootstrap_servers: "broker1:9092,broker2:9092".to_string(),
            topic: "ave-{{schema-id}}".to_string(),
            ..KafkaSinkConfig::default()
        }
    }

    #[test]
    fn test_kafka_sink_config_validate_ok() {
        assert!(valid_kafka_config().validate().is_ok());
    }

    #[test]
    fn test_kafka_sink_config_validate_requires_bootstrap_servers() {
        let mut cfg = valid_kafka_config();
        cfg.bootstrap_servers.clear();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_kafka_sink_config_validate_requires_topic() {
        let mut cfg = valid_kafka_config();
        cfg.topic.clear();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_kafka_sink_config_validate_rejects_invalid_acks() {
        let mut cfg = valid_kafka_config();
        cfg.acks = "2".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_kafka_sink_config_validate_rejects_invalid_compression() {
        let mut cfg = valid_kafka_config();
        cfg.compression = "brotli".to_string();
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_kafka_sink_config_validate_rejects_zero_timeout() {
        let mut cfg = valid_kafka_config();
        cfg.request_timeout_ms = 0;
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_kafka_security_validate_rejects_invalid_mechanism() {
        let mut cfg = valid_kafka_config();
        cfg.security = KafkaSecurityConfig::SaslSsl {
            mechanism: "GSSAPI".to_string(),
            username: "ave".to_string(),
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_kafka_security_validate_requires_username() {
        let mut cfg = valid_kafka_config();
        cfg.security = KafkaSecurityConfig::SaslPlaintext {
            mechanism: "PLAIN".to_string(),
            username: String::new(),
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_kafka_sink_config_serde_defaults() {
        let cfg: KafkaSinkConfig = serde_json::from_str("{}").unwrap();
        assert_eq!(cfg, KafkaSinkConfig::default());
        assert_eq!(cfg.client_id, "ave-sink");
        assert_eq!(cfg.acks, "all");
        assert_eq!(cfg.compression, "none");
        assert_eq!(cfg.request_timeout_ms, 5_000);
        // The default is incomplete: servers and topic are mandatory.
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn test_kafka_sink_config_serde_full() {
        let json = r#"{
            "bootstrap_servers": "broker:9092",
            "topic": "ave-{{schema-id}}",
            "client_id": "node-1",
            "security": {
                "protocol": "sasl_ssl",
                "mechanism": "SCRAM-SHA-256",
                "username": "ave"
            },
            "acks": "all",
            "compression": "zstd",
            "request_timeout_ms": 3000
        }"#;
        let cfg: KafkaSinkConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.validate().is_ok());
        match cfg.security {
            KafkaSecurityConfig::SaslSsl { mechanism, username } => {
                assert_eq!(mechanism, "SCRAM-SHA-256");
                assert_eq!(username, "ave");
            }
            other => panic!("expected SaslSsl, got {other:?}"),
        }
    }

    #[test]
    fn test_sink_transport_config_serde_kafka_variant() {
        let json = r#"{
            "type": "kafka",
            "bootstrap_servers": "broker:9092",
            "topic": "ave-{{schema-id}}"
        }"#;
        let cfg: SinkTransportConfig = serde_json::from_str(json).unwrap();
        assert!(matches!(cfg, SinkTransportConfig::Kafka(_)));
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn test_sink_auth_config_validate_allows_empty_for_env_api_key() {
        // All fields empty: the API key is injected through
        // `AVE_SINK_APIKEY_{{SERVER}}` at worker startup.
        let auth = SinkAuthConfig {
            auth_url: String::new(),
            username: String::new(),
            api_key: String::new(),
        };
        assert!(auth.validate().is_ok());
    }

    #[test]
    fn test_sink_auth_config_validate_allows_api_key_only() {
        let auth = SinkAuthConfig {
            auth_url: String::new(),
            username: String::new(),
            api_key: "secret".to_owned(),
        };
        assert!(auth.validate().is_ok());
    }

    #[test]
    fn test_sink_auth_config_validate_requires_url_and_username_together() {
        let mut auth = SinkAuthConfig {
            auth_url: "https://auth.example.com/token".to_owned(),
            username: String::new(),
            api_key: String::new(),
        };
        assert!(auth.validate().is_err());
        auth.auth_url = String::new();
        auth.username = "ave".to_owned();
        assert!(auth.validate().is_err());
    }

    #[test]
    fn test_sink_auth_config_api_key_serializes_redacted() {
        let auth = SinkAuthConfig {
            auth_url: String::new(),
            username: String::new(),
            api_key: "super-secret".to_owned(),
        };
        let json = serde_json::to_string(&auth).unwrap();
        assert!(!json.contains("super-secret"));
        assert!(json.contains("***"));
        // Empty keys serialize as empty, not redacted.
        let empty = SinkAuthConfig {
            auth_url: String::new(),
            username: String::new(),
            api_key: String::new(),
        };
        assert!(!serde_json::to_string(&empty).unwrap().contains("***"));
    }

    #[test]
    fn test_http_tls_config_validate_ok() {
        let tls = HttpTlsConfig {
            ca_certificate: "/etc/ssl/ca.pem".to_owned(),
            client_certificate: "/etc/ssl/client.pem".to_owned(),
            client_key: "/etc/ssl/client.key".to_owned(),
            min_tls_version: "1.2".to_owned(),
        };
        assert!(tls.validate().is_ok());
        assert!(HttpTlsConfig::default().validate().is_ok());
    }

    #[test]
    fn test_http_tls_config_validate_requires_cert_and_key_together() {
        let tls = HttpTlsConfig {
            client_certificate: "/etc/ssl/client.pem".to_owned(),
            ..HttpTlsConfig::default()
        };
        assert!(tls.validate().is_err());
        let tls = HttpTlsConfig {
            client_key: "/etc/ssl/client.key".to_owned(),
            ..HttpTlsConfig::default()
        };
        assert!(tls.validate().is_err());
    }

    #[test]
    fn test_http_tls_config_validate_rejects_invalid_min_version() {
        let tls = HttpTlsConfig {
            min_tls_version: "1.1".to_owned(),
            ..HttpTlsConfig::default()
        };
        assert!(tls.validate().is_err());
    }

    #[test]
    fn test_http_sink_config_serde_defaults_tls_and_signature() {
        let cfg: HttpSinkConfig =
            serde_json::from_str(r#"{"url": "https://example.com"}"#).unwrap();
        assert!(cfg.tls.is_none());
        assert!(!cfg.signature);
    }
}

/// Per-sink authentication configuration.
/// When present, the sink requires authentication for delivery and health-check.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct SinkAuthConfig {
    /// OAuth2 / token endpoint URL. Must be set together with `username`.
    pub auth_url: String,
    /// Username for the token endpoint. Must be set together with `auth_url`.
    pub username: String,
    /// API key for Api-Key header authentication (alternative to OAuth2).
    /// May be empty when the key is provided through the environment variable
    /// `AVE_SINK_APIKEY_{{SERVER}}`, which is the recommended option and
    /// takes precedence over this field. Always serialized redacted.
    #[serde(default, serialize_with = "serialize_redacted")]
    pub api_key: String,
}

/// Serializes a secret as `"***"` so it never leaks through API responses.
fn serialize_redacted<S: serde::Serializer>(
    value: &str,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    if value.is_empty() {
        serializer.serialize_str("")
    } else {
        serializer.serialize_str("***")
    }
}

impl SinkAuthConfig {
    pub fn validate(&self) -> Result<(), Error> {
        let url_set = !self.auth_url.is_empty();
        let user_set = !self.username.is_empty();
        if url_set {
            validate_url("auth_url", &self.auth_url)?;
        }
        if url_set != user_set {
            return Err(Error::InvalidConfiguration {
                component: "SinkAuthConfig".to_string(),
                reason: "auth_url and username must be set together for OAuth2"
                    .to_string(),
            });
        }
        Ok(())
    }
}

/// TLS configuration for the HTTP transport.
///
/// Certificates are referenced by filesystem path; the client private key
/// must be PEM-encoded PKCS#8.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(default)]
pub struct HttpTlsConfig {
    /// Path to an additional PEM-encoded root CA certificate to trust
    /// (e.g. a corporate CA doing TLS inspection).
    pub ca_certificate: String,
    /// Path to the PEM-encoded client certificate chain used for mTLS.
    /// Must be set together with `client_key`.
    pub client_certificate: String,
    /// Path to the PEM-encoded PKCS#8 client private key used for mTLS.
    /// Must be set together with `client_certificate`.
    pub client_key: String,
    /// Minimum TLS version accepted: `"1.2"` or `"1.3"`.
    /// Empty uses the TLS library default.
    pub min_tls_version: String,
}

impl HttpTlsConfig {
    pub fn validate(&self) -> Result<(), Error> {
        let cert_set = !self.client_certificate.is_empty();
        let key_set = !self.client_key.is_empty();
        if cert_set != key_set {
            return Err(Error::InvalidConfiguration {
                component: "HttpTlsConfig".to_string(),
                reason:
                    "client_certificate and client_key must be set together (mTLS)"
                        .to_string(),
            });
        }
        if !self.min_tls_version.is_empty()
            && self.min_tls_version != "1.2"
            && self.min_tls_version != "1.3"
        {
            return Err(Error::InvalidConfiguration {
                component: "HttpTlsConfig.min_tls_version".to_string(),
                reason: format!(
                    "must be \"1.2\" or \"1.3\", got {}",
                    self.min_tls_version
                ),
            });
        }
        Ok(())
    }
}

/// HTTP-specific sink configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(default)]
pub struct HttpSinkConfig {
    pub url: String,
    /// Per-sink authentication. When `Some`, the worker will load the
    /// password from the environment variable `AVE_SINK_PASSWORD_{{SERVER}}`
    /// and the API key from `AVE_SINK_APIKEY_{{SERVER}}` (where `{{SERVER}}`
    /// is the sink name upper-cased with non-alphanumeric characters replaced
    /// by `_`).
    pub auth: Option<SinkAuthConfig>,
    pub connect_timeout_ms: u64,
    pub request_timeout_ms: u64,
    pub max_retries: usize,
    pub retry_base_delay_ms: u64,
    /// Optional dedicated health-check URL.
    pub health_check_url: Option<String>,
    pub token_refresh_margin_secs: u64,
    /// TLS customization: additional root CA, mTLS identity, minimum version.
    pub tls: Option<HttpTlsConfig>,
    /// Sign each delivery with the node's Ed25519 identity and send the
    /// signature in the `X-Ave-Signature*` headers.
    pub signature: bool,
}

impl Default for HttpSinkConfig {
    fn default() -> Self {
        Self {
            url: String::new(),
            auth: None,
            connect_timeout_ms: 2_000,
            request_timeout_ms: 5_000,
            max_retries: 2,
            retry_base_delay_ms: 500,
            health_check_url: None,
            token_refresh_margin_secs: 30,
            tls: None,
            signature: false,
        }
    }
}

impl HttpSinkConfig {
    pub fn validate(&self) -> Result<(), Error> {
        validate_url("HttpSinkConfig.url", &self.url)?;
        if let Some(auth) = &self.auth {
            auth.validate().map_err(|e| Error::InvalidConfiguration {
                component: "HttpSinkConfig.auth".to_string(),
                reason: e.to_string(),
            })?;
        }
        require_positive_u64(
            "HttpSinkConfig.connect_timeout_ms",
            self.connect_timeout_ms,
        )?;
        require_positive_u64(
            "HttpSinkConfig.request_timeout_ms",
            self.request_timeout_ms,
        )?;
        if self.request_timeout_ms < self.connect_timeout_ms {
            return Err(Error::InvalidConfiguration {
                component: "HttpSinkConfig.request_timeout_ms".to_string(),
                reason: format!(
                    "must be greater than or equal to connect_timeout_ms ({})",
                    self.connect_timeout_ms
                ),
            });
        }
        require_positive_u64(
            "HttpSinkConfig.max_retries",
            self.max_retries as u64,
        )?;
        require_positive_u64(
            "HttpSinkConfig.retry_base_delay_ms",
            self.retry_base_delay_ms,
        )?;
        if let Some(url) = &self.health_check_url {
            validate_url("HttpSinkConfig.health_check_url", url)?;
        }
        require_positive_u64(
            "HttpSinkConfig.token_refresh_margin_secs",
            self.token_refresh_margin_secs,
        )?;
        if let Some(tls) = &self.tls {
            tls.validate().map_err(|e| Error::InvalidConfiguration {
                component: "HttpSinkConfig.tls".to_string(),
                reason: e.to_string(),
            })?;
        }
        Ok(())
    }
}

/// Security protocol for the Kafka transport.
///
/// SASL passwords are never stored in the configuration: they are read from
/// the environment variable `AVE_SINK_PASSWORD_{{SERVER}}`, following the
/// same convention as the HTTP transport.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(tag = "protocol", rename_all = "snake_case")]
pub enum KafkaSecurityConfig {
    /// No encryption, no authentication.
    #[default]
    Plaintext,
    /// TLS encryption without authentication.
    Ssl,
    /// SASL authentication over a plaintext connection.
    SaslPlaintext {
        /// SASL mechanism: PLAIN, SCRAM-SHA-256 or SCRAM-SHA-512.
        mechanism: String,
        /// SASL username.
        username: String,
    },
    /// SASL authentication over a TLS connection.
    SaslSsl {
        /// SASL mechanism: PLAIN, SCRAM-SHA-256 or SCRAM-SHA-512.
        mechanism: String,
        /// SASL username.
        username: String,
    },
}

impl KafkaSecurityConfig {
    /// SASL mechanisms supported by the builtin librdkafka implementation.
    const MECHANISMS: [&str; 3] = ["PLAIN", "SCRAM-SHA-256", "SCRAM-SHA-512"];

    pub fn validate(&self) -> Result<(), Error> {
        match self {
            Self::Plaintext | Self::Ssl => Ok(()),
            Self::SaslPlaintext { mechanism, username }
            | Self::SaslSsl { mechanism, username } => {
                if !Self::MECHANISMS.contains(&mechanism.as_str()) {
                    return Err(Error::InvalidConfiguration {
                        component: "KafkaSecurityConfig.mechanism".to_string(),
                        reason: format!(
                            "must be one of {}, got {mechanism}",
                            Self::MECHANISMS.join(", ")
                        ),
                    });
                }
                if username.is_empty() {
                    return Err(Error::InvalidConfiguration {
                        component: "KafkaSecurityConfig.username".to_string(),
                        reason: "must not be empty when using SASL".to_string(),
                    });
                }
                Ok(())
            }
        }
    }
}

/// Kafka-specific sink configuration.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(default)]
pub struct KafkaSinkConfig {
    /// Comma-separated list of `host:port` bootstrap brokers.
    pub bootstrap_servers: String,
    /// Topic template; supports the `{{schema-id}}` and `{{subject-id}}`
    /// placeholders. The subject id is always used as the message key, so
    /// per-subject ordering is preserved regardless of the topic layout.
    pub topic: String,
    /// Producer client id (informational).
    pub client_id: String,
    /// Security configuration for the brokers.
    pub security: KafkaSecurityConfig,
    /// Required acknowledgements: "0", "1" or "all".
    pub acks: String,
    /// Compression codec: none, gzip, snappy, lz4 or zstd.
    pub compression: String,
    /// Per-message produce timeout in milliseconds.
    pub request_timeout_ms: u64,
}

impl Default for KafkaSinkConfig {
    fn default() -> Self {
        Self {
            bootstrap_servers: String::new(),
            topic: String::new(),
            client_id: "ave-sink".to_string(),
            security: KafkaSecurityConfig::default(),
            acks: "all".to_string(),
            compression: "none".to_string(),
            request_timeout_ms: 5_000,
        }
    }
}

impl KafkaSinkConfig {
    const ACKS: [&str; 3] = ["0", "1", "all"];
    const COMPRESSION: [&str; 5] = ["none", "gzip", "snappy", "lz4", "zstd"];

    pub fn validate(&self) -> Result<(), Error> {
        if self.bootstrap_servers.is_empty() {
            return Err(Error::InvalidConfiguration {
                component: "KafkaSinkConfig.bootstrap_servers".to_string(),
                reason: "must not be empty".to_string(),
            });
        }
        if self.topic.is_empty() {
            return Err(Error::InvalidConfiguration {
                component: "KafkaSinkConfig.topic".to_string(),
                reason: "must not be empty".to_string(),
            });
        }
        if !Self::ACKS.contains(&self.acks.as_str()) {
            return Err(Error::InvalidConfiguration {
                component: "KafkaSinkConfig.acks".to_string(),
                reason: format!(
                    "must be one of {}, got {}",
                    Self::ACKS.join(", "),
                    self.acks
                ),
            });
        }
        if !Self::COMPRESSION.contains(&self.compression.as_str()) {
            return Err(Error::InvalidConfiguration {
                component: "KafkaSinkConfig.compression".to_string(),
                reason: format!(
                    "must be one of {}, got {}",
                    Self::COMPRESSION.join(", "),
                    self.compression
                ),
            });
        }
        self.security.validate().map_err(|e| {
            Error::InvalidConfiguration {
                component: "KafkaSinkConfig.security".to_string(),
                reason: e.to_string(),
            }
        })?;
        require_positive_u64(
            "KafkaSinkConfig.request_timeout_ms",
            self.request_timeout_ms,
        )?;
        Ok(())
    }
}

/// Transport selected for a sink server. HTTP and Kafka are supported.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SinkTransportConfig {
    Http(HttpSinkConfig),
    Kafka(KafkaSinkConfig),
}

impl Default for SinkTransportConfig {
    fn default() -> Self {
        Self::Http(HttpSinkConfig::default())
    }
}

impl SinkTransportConfig {
    pub fn validate(&self) -> Result<(), Error> {
        match self {
            Self::Http(http) => http.validate(),
            Self::Kafka(kafka) => kafka.validate(),
        }
    }

    /// Transport kind identifier, matching the serde `type` tag
    /// (`"http"`, `"kafka"`).
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Http(_) => "http",
            Self::Kafka(_) => "kafka",
        }
    }
}

fn validate_url(component: &str, value: &str) -> Result<(), Error> {
    if value.is_empty() {
        return Err(Error::InvalidConfiguration {
            component: component.to_string(),
            reason: "must not be empty".to_string(),
        });
    }
    if !value.starts_with("http://") && !value.starts_with("https://") {
        return Err(Error::InvalidConfiguration {
            component: component.to_string(),
            reason: format!("must be an http/https URL, got {value}"),
        });
    }
    Ok(())
}

fn require_positive_u64(component: &str, value: u64) -> Result<(), Error> {
    if value == 0 {
        return Err(Error::InvalidConfiguration {
            component: component.to_string(),
            reason: "must be greater than zero".to_string(),
        });
    }
    Ok(())
}

/// Target of a sink configuration entry.
///
/// Every sink targets a schema. The special schema `"governance"` means the
/// sink receives governance-level events and is handled by the node-level
/// `NodeSinkManager`; in that case `governance_id` must be `None`. For any
/// other schema `governance_id` is mandatory and identifies the governance
/// whose trackers will feed the sink.
#[derive(
    Debug, Clone, Deserialize, Serialize, Eq, PartialEq, PartialOrd, Ord, Hash,
)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum SinkTarget {
    Schema {
        schema_id: String,
        /// Governance to which this sink applies. Must be `None` when
        /// `schema_id` is `"governance"`; mandatory otherwise.
        #[serde(default)]
        governance_id: Option<String>,
    },
}

impl SinkTarget {
    pub fn validate(&self) -> Result<(), Error> {
        match self {
            Self::Schema {
                schema_id,
                governance_id,
            } => {
                if schema_id.is_empty() {
                    return Err(Error::InvalidConfiguration {
                        component: "SinkTarget.Schema.schema_id".to_string(),
                        reason: "must not be empty".to_string(),
                    });
                }
                if schema_id == "governance" {
                    if governance_id.is_some() {
                        return Err(Error::InvalidConfiguration {
                            component: "SinkTarget.Schema.governance_id"
                                .to_string(),
                            reason:
                                "must be None when schema_id is 'governance'"
                                    .to_string(),
                        });
                    }
                } else if governance_id
                    .as_deref()
                    .is_none_or(|id| id.is_empty())
                {
                    return Err(Error::InvalidConfiguration {
                        component: "SinkTarget.Schema.governance_id"
                            .to_string(),
                        reason: "must be set and not empty when schema_id is not 'governance'"
                            .to_string(),
                    });
                }
                Ok(())
            }
        }
    }
}

/// Configuration for a single sink server endpoint.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
#[serde(default)]
pub struct SinkServer {
    pub server: String,
    pub events: BTreeSet<SinkTypes>,
    /// Delivery transport and its specific configuration.
    pub transport: SinkTransportConfig,
    pub batch_size: usize,
    pub sink_worker_idle_timeout_ms: u64,
    pub healthcheck_intervals_secs: Vec<u64>,
    pub max_catch_up_concurrency: usize,
    pub sink_subject_worker_idle_timeout_ms: u64,
    /// Maximum number of recoveries after failure before a sink is considered
    /// "flapping".
    pub max_recoveries_after_failure: u32,
    /// Delay in seconds before the first healthcheck is scheduled after startup.
    pub startup_healthcheck_delay_secs: u64,
}

impl Default for SinkServer {
    fn default() -> Self {
        Self {
            server: String::new(),
            events: BTreeSet::new(),
            transport: SinkTransportConfig::default(),
            batch_size: 100,
            sink_worker_idle_timeout_ms: 10_000,
            healthcheck_intervals_secs: vec![30, 60, 120, 300, 600],
            max_catch_up_concurrency: 2,
            sink_subject_worker_idle_timeout_ms: 2_000,
            max_recoveries_after_failure: 5,
            startup_healthcheck_delay_secs: 1,
        }
    }
}

impl SinkServer {
    pub fn validate(&self) -> Result<(), Error> {
        if self.server.is_empty() {
            return Err(Error::InvalidConfiguration {
                component: "SinkServer.server".to_string(),
                reason: "must not be empty".to_string(),
            });
        }
        if self.events.is_empty() {
            return Err(Error::InvalidConfiguration {
                component: "SinkServer.events".to_string(),
                reason: "must not be empty".to_string(),
            });
        }
        self.transport.validate()?;
        require_positive_u64("SinkServer.batch_size", self.batch_size as u64)?;
        require_positive_u64(
            "SinkServer.sink_worker_idle_timeout_ms",
            self.sink_worker_idle_timeout_ms,
        )?;
        if self.healthcheck_intervals_secs.is_empty() {
            return Err(Error::InvalidConfiguration {
                component: "SinkServer.healthcheck_intervals_secs".to_string(),
                reason: "must not be empty".to_string(),
            });
        }
        for (i, interval) in self.healthcheck_intervals_secs.iter().enumerate()
        {
            require_positive_u64(
                &format!("SinkServer.healthcheck_intervals_secs[{i}]"),
                *interval,
            )?;
        }
        for i in 1..self.healthcheck_intervals_secs.len() {
            if self.healthcheck_intervals_secs[i]
                <= self.healthcheck_intervals_secs[i - 1]
            {
                return Err(Error::InvalidConfiguration {
                    component: "SinkServer.healthcheck_intervals_secs"
                        .to_string(),
                    reason: format!(
                        "must be strictly increasing: healthcheck_intervals_secs[{i}] ({}) <= healthcheck_intervals_secs[{}] ({})",
                        self.healthcheck_intervals_secs[i],
                        i - 1,
                        self.healthcheck_intervals_secs[i - 1],
                    ),
                });
            }
        }
        require_positive_u64(
            "SinkServer.max_catch_up_concurrency",
            self.max_catch_up_concurrency as u64,
        )?;
        require_positive_u64(
            "SinkServer.sink_subject_worker_idle_timeout_ms",
            self.sink_subject_worker_idle_timeout_ms,
        )?;
        require_positive_u64(
            "SinkServer.max_recoveries_after_failure",
            self.max_recoveries_after_failure as u64,
        )?;
        require_positive_u64(
            "SinkServer.startup_healthcheck_delay_secs",
            self.startup_healthcheck_delay_secs,
        )?;
        Ok(())
    }
}

/// A single sink configuration entry: a target plus the list of servers that
/// serve events for that target.
#[derive(Debug, Clone, Deserialize, Serialize, Eq, PartialEq)]
#[cfg_attr(feature = "typescript", derive(TS))]
#[cfg_attr(feature = "typescript", ts(export))]
#[cfg_attr(feature = "openapi", derive(ToSchema))]
pub struct SinkConfigEntry {
    pub target: SinkTarget,
    pub servers: Vec<SinkServer>,
}

impl SinkConfigEntry {
    pub fn validate(&self) -> Result<(), Error> {
        self.target
            .validate()
            .map_err(|e| Error::InvalidConfiguration {
                component: "SinkConfigEntry.target".to_string(),
                reason: e.to_string(),
            })?;

        if self.servers.is_empty() {
            return Err(Error::InvalidConfiguration {
                component: "SinkConfigEntry.servers".to_string(),
                reason: "must not be empty".to_string(),
            });
        }

        let mut seen = std::collections::HashSet::new();
        for (i, server) in self.servers.iter().enumerate() {
            server.validate().map_err(|e| Error::InvalidConfiguration {
                component: format!("SinkConfigEntry.servers[{i}]"),
                reason: e.to_string(),
            })?;
            if !seen.insert(&server.server) {
                return Err(Error::InvalidConfiguration {
                    component: format!("SinkConfigEntry.servers[{i}].server"),
                    reason: format!(
                        "duplicated value '{}' within this sink entry",
                        server.server
                    ),
                });
            }
        }

        Ok(())
    }
}

pub const fn default_sink_worker_idle_timeout_ms() -> u64 {
    10_000
}

pub fn default_sink_healthcheck_intervals_secs() -> Vec<u64> {
    vec![30, 60, 120, 300, 600]
}
