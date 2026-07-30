//! Shared wire contract for every sink transport.
//!
//! Every transport (HTTP, Kafka, future MQTT, gRPC, ...) must use the same
//! header names on the wire and the same canonical payload for version-2
//! signatures, so receivers can implement verification and deduplication
//! once and apply it to any sink. The lowercase form is canonical: HTTP and
//! any other transport must write these names verbatim so the v2 signature
//! contract is unambiguous (RFC 7230 mandates header names are
//! case-insensitive, but fixing the wire case removes ambiguity).
//!
//! Anything in this module is part of the public sink contract — adding a new
//! transport means reusing these names and helpers, not redefining them.

use ave_common::{DataToSink, IncomingSinkEvent, LightEvent, SinkTypes};

use crate::sink::SinkError;
use crate::sink::transport::NodeSigner;

/// Header carrying the Ed25519 signature of the delivery body.
pub const SIGNATURE_HEADER: &str = "x-ave-signature";
/// Header carrying the signature timestamp (nanoseconds since Unix epoch).
pub const SIGNATURE_TIMESTAMP_HEADER: &str = "x-ave-signature-timestamp";
/// Header carrying the signer's public key.
pub const SIGNATURE_PUBLIC_KEY_HEADER: &str = "x-ave-public-key";

/// Header carrying the subject identifier of the delivered event.
pub const SUBJECT_ID_HEADER: &str = "x-ave-subject-id";
/// Header carrying the event sequence number.
pub const SN_HEADER: &str = "x-ave-sn";
/// Header carrying the event type (`create`, `fact`, ...).
pub const EVENT_TYPE_HEADER: &str = "x-ave-event-type";
/// Idempotency header, value `<subject_id>-<sn>` (Stripe convention).
pub const IDEMPOTENCY_KEY_HEADER: &str = "idempotency-key";
/// Header carrying a unique identifier for this delivery attempt.
pub const REQUEST_ID_HEADER: &str = "x-ave-request-id";
/// Header marking a request as a non-persistent sink test delivery.
pub const TEST_HEADER: &str = "x-ave-test";

/// Headers reserved for internal sink use.
///
/// Transports must reject any attempt by user configuration to override
/// them; receivers can rely on them carrying the contract above. The list is
/// lowercase and matches the constants above so a case-insensitive lookup is
/// enough.
pub const SINK_RESERVED_HEADERS: &[&str] = &[
    SIGNATURE_HEADER,
    SIGNATURE_TIMESTAMP_HEADER,
    SIGNATURE_PUBLIC_KEY_HEADER,
    SUBJECT_ID_HEADER,
    SN_HEADER,
    EVENT_TYPE_HEADER,
    IDEMPOTENCY_KEY_HEADER,
    REQUEST_ID_HEADER,
    TEST_HEADER,
];

/// Per-event metadata threaded through the delivery pipeline so every
/// transport can attach the same headers and sign the same canonical
/// content without redefining the struct.
#[derive(Debug, Clone)]
pub struct DeliveryMeta {
    pub subject_id: String,
    pub sn: u64,
    pub event_type: String,
}

impl DeliveryMeta {
    /// Build the delivery metadata of a full event.
    pub fn from_data(data: &DataToSink) -> Self {
        Self {
            subject_id: data.payload.get_subject_schema().0,
            sn: crate::sink::extract_sn(data),
            event_type: SinkTypes::from(data).as_str().to_owned(),
        }
    }

    /// Build the delivery metadata of a light event.
    pub fn from_light(light: &LightEvent) -> Self {
        Self {
            subject_id: light.subject_id.clone(),
            sn: light.sn,
            event_type: light.event_type.as_str().to_owned(),
        }
    }

    /// Idempotency key of the delivery: `<subject_id>-<sn>` (the value of
    /// the [`IDEMPOTENCY_KEY_HEADER`] header).
    pub fn idempotency_key(&self) -> String {
        format!("{}-{}", self.subject_id, self.sn)
    }
}

/// Signature headers for one delivery, computed once per logical event and
/// reused across retries of the same body.
#[derive(Debug, Clone)]
pub struct SignatureHeaders {
    pub signature: String,
    pub timestamp: String,
    pub public_key: String,
}

/// Generate a unique request id for a single delivery attempt. Combines a
/// nanosecond timestamp with a random suffix so collisions are practically
/// impossible without adding a new dependency.
pub fn generate_request_id() -> String {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("{}-{:016x}", nanos, fastrand::u64(..))
}

/// Build the canonical payload to sign.
///
/// Version 1 signs the body only; version 2 prefixes the body with the
/// critical delivery headers in lexicographic order so that tampering with
/// them invalidates the signature.
///
/// `extra_canonical_headers` lets a transport bind transport-level metadata
/// that does not live in `DeliveryMeta` (e.g. HTTP's `content-encoding`
/// when the body is gzip-compressed). They are appended to the header set
/// before sorting, alongside `content-type` and the meta headers.
pub fn canonical_payload(
    payload: &[u8],
    signature_version: u8,
    extra_canonical_headers: &[(&str, &str)],
    meta: Option<&DeliveryMeta>,
) -> Vec<u8> {
    if signature_version != 2 {
        return payload.to_vec();
    }

    let mut headers: Vec<(&str, String)> = Vec::with_capacity(8);
    headers.push(("content-type", "application/json".to_owned()));
    for (name, value) in extra_canonical_headers {
        headers.push((*name, (*value).to_owned()));
    }
    if let Some(meta) = meta {
        headers.push((IDEMPOTENCY_KEY_HEADER, meta.idempotency_key()));
        headers.push((EVENT_TYPE_HEADER, meta.event_type.clone()));
        headers.push((SN_HEADER, meta.sn.to_string()));
        headers.push((SUBJECT_ID_HEADER, meta.subject_id.clone()));
    }

    headers.sort_by_key(|a| a.0.to_lowercase());

    let mut out = Vec::with_capacity(payload.len() + 256);
    for (name, value) in headers {
        out.extend_from_slice(name.to_lowercase().as_bytes());
        out.push(b':');
        out.extend_from_slice(value.as_bytes());
        out.push(b'\n');
    }
    out.extend_from_slice(payload);
    out
}

/// Sign the delivery body with the node identity when a signer is configured.
/// Returns `None` headers when no signer is available, so transports can call
/// this unconditionally.
pub async fn sign_delivery(
    signer: Option<&NodeSigner>,
    payload: &[u8],
    signature_version: u8,
    extra_canonical_headers: &[(&str, &str)],
    meta: Option<&DeliveryMeta>,
) -> Result<Option<SignatureHeaders>, SinkError> {
    let Some(signer) = signer else {
        return Ok(None);
    };
    let canonical = canonical_payload(
        payload,
        signature_version,
        extra_canonical_headers,
        meta,
    );
    let signature = signer.sign(canonical).await?;
    Ok(Some(SignatureHeaders {
        signature: signature.value.to_string(),
        timestamp: signature.timestamp.to_string(),
        public_key: signature.signer.to_string(),
    }))
}

/// Format the environment variable name for a sink's password.
///
/// Format: `AVE_SINK_PASSWORD_{{SERVER_UPPER}}` where non-alphanumeric
/// chars are replaced by `_`. Used by every transport that needs to read a
/// sink password from the environment (HTTP Basic auth, Kafka SASL, ...).
pub fn sink_password_env_var(sink_name: &str) -> String {
    sink_secret_env_var("AVE_SINK_PASSWORD_", sink_name)
}

/// Format the environment variable name for a sink's API key.
/// Format: `AVE_SINK_APIKEY_{{SERVER_UPPER}}`.
pub fn sink_apikey_env_var(sink_name: &str) -> String {
    sink_secret_env_var("AVE_SINK_APIKEY_", sink_name)
}

/// Format the environment variable name for a sink's proxy password.
/// Format: `AVE_SINK_PROXY_PASSWORD_{{SERVER_UPPER}}`.
pub fn sink_proxy_password_env_var(sink_name: &str) -> String {
    sink_secret_env_var("AVE_SINK_PROXY_PASSWORD_", sink_name)
}

/// Load a required secret from an environment variable, failing with a
/// uniform `ClientBuild` error when it is unset or empty. `purpose` is the
/// feature that needs the secret (`"SASL"`, `"OAuth2"`, ...).
pub fn load_required_secret(
    sink_name: &str,
    env_var: &str,
    purpose: &str,
) -> Result<String, SinkError> {
    let secret = std::env::var(env_var).unwrap_or_default();
    if secret.is_empty() {
        return Err(SinkError::ClientBuild(format!(
            "{purpose} configured for sink '{sink_name}' but password environment variable {env_var} is not set"
        )));
    }
    Ok(secret)
}

/// The non-persistent test payload sent by `SinkTransport::test` on every
/// transport, so receivers can recognize sink checks by content as well as
/// by the [`TEST_HEADER`] header.
pub fn test_delivery_payload() -> serde_json::Value {
    serde_json::json!({"test": true})
}

/// Whether `name` collides with a header reserved for internal sink use
/// (case-insensitive comparison against [`SINK_RESERVED_HEADERS`]).
pub fn is_sink_reserved_header(name: &str) -> bool {
    SINK_RESERVED_HEADERS
        .iter()
        .any(|reserved| name.eq_ignore_ascii_case(reserved))
}

/// Serialize a delivery payload to JSON, mapping a failure to a permanent
/// (non-retryable) `SinkError::Delivery`. Shared by every transport so the
/// error contract is identical.
pub fn serialize_json_payload<T: serde::Serialize + ?Sized>(
    value: &T,
) -> Result<Vec<u8>, SinkError> {
    serde_json::to_vec(value).map_err(|e| SinkError::Delivery {
        message: format!("JSON serialization failed: {e}"),
        retryable: false,
        retry_after_ms: None,
    })
}

/// Map the result of a single delivery attempt to the result label of the
/// `core_sink_request_duration_seconds` metric. Shared by every transport so
/// the label set cannot diverge.
pub const fn sink_result_label(result: &Result<(), SinkError>) -> &'static str {
    match result {
        Ok(()) => "success",
        Err(SinkError::Auth { .. }) => "auth",
        Err(SinkError::Delivery {
            retryable: true, ..
        }) => "transient",
        Err(SinkError::Shutdown) => "shutdown",
        Err(_) => "permanent",
    }
}

/// Run a single delivery attempt recording its duration.
///
/// The duration goes to the shared `core_sink_request_duration_seconds`
/// metric, labeled with [`sink_result_label`]. Every transport times its
/// attempts through this wrapper so the metric cannot diverge (or be
/// forgotten).
pub async fn timed_sink_request<F, Fut>(
    sink_name: &str,
    attempt: F,
) -> Result<(), SinkError>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = Result<(), SinkError>>,
{
    let start = std::time::Instant::now();
    let result = attempt().await;
    if let Some(metrics) = crate::metrics::try_core_metrics() {
        metrics.observe_sink_request_duration(
            sink_name,
            sink_result_label(&result),
            start.elapsed(),
        );
    }
    result
}

/// Group a batch of events by event type.
///
/// Grouping only applies when the transport's address template routes by
/// type (`{{event-type}}`); otherwise a single group carries the whole
/// batch. Group order follows first appearance so a homogeneous batch
/// produces one message, and the relative order inside each group is
/// preserved.
pub fn group_events_by_type(
    events: Vec<IncomingSinkEvent>,
    route_by_type: bool,
) -> Vec<(String, Vec<IncomingSinkEvent>)> {
    let Some(first) = events.first() else {
        return Vec::new();
    };
    if !route_by_type {
        return vec![(first.event_type().as_str().to_owned(), events)];
    }
    let mut groups: Vec<(String, Vec<IncomingSinkEvent>)> = Vec::new();
    for event in events {
        let event_type = event.event_type().as_str().to_owned();
        match groups.iter_mut().find(|(t, _)| *t == event_type) {
            Some((_, group)) => group.push(event),
            None => groups.push((event_type, vec![event])),
        }
    }
    groups
}

/// Schema id of the first event of a batch group. Every event of a group
/// shares the schema (they come from the same subject), so the first one
/// defines it.
pub fn batch_group_schema_id(first: &IncomingSinkEvent) -> String {
    match first {
        IncomingSinkEvent::Full(data) => data.payload.get_subject_schema().1,
        IncomingSinkEvent::Light(light) => light.schema_id.clone(),
    }
}

fn sink_secret_env_var(prefix: &str, sink_name: &str) -> String {
    format!(
        "{prefix}{}",
        sink_name
            .chars()
            .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
            .collect::<String>()
            .to_ascii_uppercase()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta() -> DeliveryMeta {
        DeliveryMeta {
            subject_id: "subject-1".to_owned(),
            sn: 42,
            event_type: "create".to_owned(),
        }
    }

    #[test]
    fn delivery_meta_constructors_and_idempotency_key() {
        let data = DataToSink {
            payload: ave_common::DataToSinkEvent::Create {
                governance_id: None,
                subject_id: "subject-9".to_owned(),
                owner: "owner".to_owned(),
                schema_id: ave_common::SchemaType::Type("schema".to_owned()),
                namespace: String::new(),
                sn: 7,
                gov_version: 1,
                state: serde_json::json!({}),
            },
            public_key: "pk".to_owned(),
            event_request_timestamp: 1,
            event_ledger_timestamp: 2,
            sink_timestamp: 3,
        };
        let meta = DeliveryMeta::from_data(&data);
        assert_eq!(meta.subject_id, "subject-9");
        assert_eq!(meta.sn, 7);
        assert_eq!(meta.event_type, "create");
        assert_eq!(meta.idempotency_key(), "subject-9-7");

        let light = LightEvent {
            subject_id: "subject-3".to_owned(),
            schema_id: "schema".to_owned(),
            governance_id: None,
            sn: 5,
            event_type: SinkTypes::Fact,
            success: true,
        };
        let meta = DeliveryMeta::from_light(&light);
        assert_eq!(meta.subject_id, "subject-3");
        assert_eq!(meta.sn, 5);
        assert_eq!(meta.event_type, "fact");
        assert_eq!(meta.idempotency_key(), "subject-3-5");
    }

    #[test]
    fn canonical_payload_v1_returns_body_verbatim() {
        let payload = b"plain body";
        assert_eq!(canonical_payload(payload, 1, &[], None), payload.to_vec());
    }

    #[test]
    fn canonical_payload_v2_sorts_headers_lowercase_and_appends_body() {
        let payload = b"payload body";
        let text = String::from_utf8_lossy(&canonical_payload(
            payload,
            2,
            &[("content-encoding", "gzip")],
            Some(&meta()),
        ))
        .into_owned();

        let expected_prefix = "content-encoding:gzip\n\
                               content-type:application/json\n\
                               idempotency-key:subject-1-42\n\
                               x-ave-event-type:create\n\
                               x-ave-sn:42\n\
                               x-ave-subject-id:subject-1\n";
        assert!(
            text.starts_with(expected_prefix),
            "canonical payload must start with sorted headers, got: {text}"
        );
        assert!(
            text.ends_with("payload body"),
            "canonical payload must end with the body"
        );
    }

    #[test]
    fn canonical_payload_v2_without_meta_omits_event_headers() {
        let payload = b"x";
        let text =
            String::from_utf8_lossy(&canonical_payload(payload, 2, &[], None))
                .into_owned();
        assert_eq!(text, "content-type:application/json\nx");
    }

    #[test]
    fn canonical_payload_v2_extra_headers_are_sorted_alongside_meta() {
        // Extras with names that sort before and after the meta entries
        // must end up interleaved by lowercase name, proving the contract.
        let payload = b"y";
        let text = String::from_utf8_lossy(&canonical_payload(
            payload,
            2,
            &[("x-extra", "1"), ("a-extra", "2")],
            Some(&meta()),
        ))
        .into_owned();
        assert_eq!(
            text,
            "a-extra:2\n\
             content-type:application/json\n\
             idempotency-key:subject-1-42\n\
             x-ave-event-type:create\n\
             x-ave-sn:42\n\
             x-ave-subject-id:subject-1\n\
             x-extra:1\n\
             y"
        );
    }

    fn light_event(sn: u64, event_type: ave_common::SinkTypes) -> ave_common::LightEvent {
        ave_common::LightEvent {
            subject_id: format!("subject-{sn}"),
            schema_id: "schema".to_owned(),
            governance_id: None,
            sn,
            event_type,
            success: true,
        }
    }

    #[test]
    fn is_sink_reserved_header_matches_case_insensitively() {
        for name in ["x-ave-sn", "X-Ave-SN", "Idempotency-Key", "X-AVE-TEST"] {
            assert!(is_sink_reserved_header(name), "{name} must be reserved");
        }
        for name in ["x-custom", "x-ave", "x-ave-sniper"] {
            assert!(
                !is_sink_reserved_header(name),
                "{name} must not be reserved"
            );
        }
    }

    #[test]
    fn sink_result_label_covers_the_whole_taxonomy() {
        assert_eq!(sink_result_label(&Ok(())), "success");
        assert_eq!(
            sink_result_label(&Err(SinkError::Auth {
                message: String::new(),
                retry_after_ms: None,
            })),
            "auth"
        );
        assert_eq!(
            sink_result_label(&Err(SinkError::Delivery {
                message: String::new(),
                retryable: true,
                retry_after_ms: None,
            })),
            "transient"
        );
        assert_eq!(
            sink_result_label(&Err(SinkError::Delivery {
                message: String::new(),
                retryable: false,
                retry_after_ms: None,
            })),
            "permanent"
        );
        assert_eq!(sink_result_label(&Err(SinkError::Shutdown)), "shutdown");
        assert_eq!(
            sink_result_label(&Err(SinkError::Rejected {
                message: String::new(),
            })),
            "permanent"
        );
        assert_eq!(
            sink_result_label(&Err(SinkError::ClientBuild(String::new()))),
            "permanent"
        );
    }

    #[test]
    fn group_events_by_type_empty_batch_produces_no_groups() {
        assert!(group_events_by_type(Vec::new(), false).is_empty());
        assert!(group_events_by_type(Vec::new(), true).is_empty());
    }

    #[test]
    fn env_var_helpers_normalize_the_sink_name() {
        assert_eq!(
            sink_password_env_var("my-sink.1"),
            "AVE_SINK_PASSWORD_MY_SINK_1"
        );
        assert_eq!(
            sink_apikey_env_var("my-sink.1"),
            "AVE_SINK_APIKEY_MY_SINK_1"
        );
        assert_eq!(
            sink_proxy_password_env_var("My Sink"),
            "AVE_SINK_PROXY_PASSWORD_MY_SINK"
        );
    }

    #[test]
    fn load_required_secret_fails_with_uniform_message_when_unset() {
        // Guaranteed-unset variable: the success path is covered end-to-end
        // by the SASL / proxy / OAuth2 integration tests.
        let env_var = format!("AVE_TEST_UNSET_{:016x}", fastrand::u64(..));
        let Err(err) = load_required_secret("my-sink", &env_var, "SASL")
        else {
            panic!("an unset secret must fail");
        };
        let SinkError::ClientBuild(message) = err else {
            panic!("expected ClientBuild error");
        };
        assert_eq!(
            message,
            format!(
                "SASL configured for sink 'my-sink' but password environment variable {env_var} is not set"
            )
        );
    }

    #[test]
    fn test_delivery_payload_is_the_shared_contract() {
        assert_eq!(test_delivery_payload(), serde_json::json!({"test": true}));
    }

    #[test]
    fn batch_group_schema_id_reads_full_and_light_events() {
        let data = DataToSink {
            payload: ave_common::DataToSinkEvent::Create {
                governance_id: None,
                subject_id: "subject-9".to_owned(),
                owner: "owner".to_owned(),
                schema_id: ave_common::SchemaType::Type("full-schema".to_owned()),
                namespace: String::new(),
                sn: 0,
                gov_version: 1,
                state: serde_json::json!({}),
            },
            public_key: "pk".to_owned(),
            event_request_timestamp: 1,
            event_ledger_timestamp: 2,
            sink_timestamp: 3,
        };
        let full = IncomingSinkEvent::Full(std::sync::Arc::new(data));
        assert_eq!(batch_group_schema_id(&full), "full-schema");

        let light = IncomingSinkEvent::Light(LightEvent {
            subject_id: "subject-3".to_owned(),
            schema_id: "light-schema".to_owned(),
            governance_id: None,
            sn: 1,
            event_type: SinkTypes::Fact,
            success: true,
        });
        assert_eq!(batch_group_schema_id(&light), "light-schema");
    }

    #[tokio::test]
    async fn timed_sink_request_propagates_the_result_intact() {
        let ok = timed_sink_request("unit-sink", || async { Ok(()) }).await;
        assert!(ok.is_ok());

        let err = timed_sink_request("unit-sink", || async {
            Err(SinkError::Rejected {
                message: "boom".to_owned(),
            })
        })
        .await;
        assert!(matches!(err, Err(SinkError::Rejected { .. })));
    }

    #[test]
    fn serialize_json_payload_success_and_permanent_error() {        let payload =
            serialize_json_payload(&serde_json::json!({"a": 1})).expect("payload serializes");
        assert_eq!(payload, br#"{"a":1}"#.to_vec());

        // Maps with non-string keys cannot be serialized to JSON.
        let mut invalid = std::collections::HashMap::new();
        invalid.insert(vec![1_u8, 2], 3_i32);
        let Err(err) = serialize_json_payload(&invalid) else {
            panic!("non-string keys must fail to serialize");
        };
        assert!(
            matches!(
                err,
                SinkError::Delivery {
                    retryable: false,
                    ..
                }
            ),
            "serialization failure must be a permanent delivery error: {err:?}"
        );
    }

    #[test]
    fn group_events_by_type_without_routing_keeps_single_group() {
        let events = vec![
            IncomingSinkEvent::Light(light_event(1, ave_common::SinkTypes::Create)),
            IncomingSinkEvent::Light(light_event(2, ave_common::SinkTypes::Fact)),
        ];
        let groups = group_events_by_type(events, false);
        assert_eq!(groups.len(), 1);
        // The group carries the type of the first event and the whole batch.
        assert_eq!(groups[0].0, "create");
        assert_eq!(groups[0].1.len(), 2);
    }

    #[test]
    fn group_events_by_type_routes_preserving_order() {
        let events = vec![
            IncomingSinkEvent::Light(light_event(1, ave_common::SinkTypes::Fact)),
            IncomingSinkEvent::Light(light_event(2, ave_common::SinkTypes::Create)),
            IncomingSinkEvent::Light(light_event(3, ave_common::SinkTypes::Fact)),
        ];
        let groups = group_events_by_type(events, true);
        assert_eq!(groups.len(), 2);
        // First-appearance order: fact group first, then create.
        assert_eq!(groups[0].0, "fact");
        assert_eq!(groups[0].1.len(), 2);
        assert_eq!(groups[1].0, "create");
        assert_eq!(groups[1].1.len(), 1);
        // Relative order inside the group is preserved.
        let IncomingSinkEvent::Light(first) = &groups[0].1[0] else {
            panic!("light event expected");
        };
        let IncomingSinkEvent::Light(second) = &groups[0].1[1] else {
            panic!("light event expected");
        };
        assert_eq!(first.sn, 1);
        assert_eq!(second.sn, 3);
    }
}
