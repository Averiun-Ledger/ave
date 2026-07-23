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

/// Headers reserved for internal sink use. Transports must reject any
/// attempt by user configuration to override them; receivers can rely on
/// them carrying the contract above. The list is lowercase and matches the
/// constants above so a case-insensitive lookup is enough.
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

/// Build the canonical payload to sign. Version 1 signs the body only;
/// version 2 prefixes the body with the critical delivery headers in
/// lexicographic order so that tampering with them invalidates the
/// signature.
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
        headers.push((
            IDEMPOTENCY_KEY_HEADER,
            format!("{}-{}", meta.subject_id, meta.sn),
        ));
        headers.push((EVENT_TYPE_HEADER, meta.event_type.clone()));
        headers.push((SN_HEADER, meta.sn.to_string()));
        headers.push((SUBJECT_ID_HEADER, meta.subject_id.clone()));
    }

    headers.sort_by(|a, b| a.0.to_lowercase().cmp(&b.0.to_lowercase()));

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
/// Format: `AVE_SINK_PASSWORD_{{SERVER_UPPER}}` where non-alphanumeric
/// chars are replaced by `_`. Used by every transport that needs to read a
/// sink password from the environment (HTTP Basic auth, Kafka SASL, ...).
pub fn sink_password_env_var(sink_name: &str) -> String {
    sink_secret_env_var("AVE_SINK_PASSWORD_", sink_name)
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
    fn canonical_payload_v1_returns_body_verbatim() {
        let payload = b"plain body";
        assert_eq!(
            canonical_payload(payload, 1, &[], None),
            payload.to_vec()
        );
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
        let text = String::from_utf8_lossy(&canonical_payload(payload, 2, &[], None))
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
}

