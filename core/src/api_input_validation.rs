//! Input validation helpers for the public `Api` surface.
//!
//! These helpers are intentionally small, name the failing field explicitly and
//! return `crate::error::Error` so callers can bail out early with a clear
//! message. They are used at the boundary of `Api` methods, before any actor or
//! database call is made.

use std::str::FromStr;

use ave_common::bridge::request::{
    AbortsQuery, EventsQuery, SinkEventsQuery, SinkReplayRequest, SinksQuery,
};
use ave_common::identity::DigestIdentifier;
use ave_common::request::EventRequest;
use ave_common::schematype::SchemaType;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::error::Error;

/// Maximum number of events a single sink replay/query page may request.
/// Keeps a malicious or misconfigured client from forcing unbounded reads.
const MAX_SINK_EVENTS_LIMIT: u64 = 1000;

/// Rejects `0` with a message that names the field.
pub fn require_positive_u64(name: &str, value: u64) -> Result<(), Error> {
    if value == 0 {
        Err(Error::InvalidQueryParams(format!(
            "{name} must be greater than zero, got 0"
        )))
    } else {
        Ok(())
    }
}

/// Rejects an empty [`DigestIdentifier`] used as a subject id.
pub fn validate_subject_id(subject_id: &DigestIdentifier) -> Result<(), Error> {
    if subject_id.is_empty() {
        Err(Error::InvalidSubjectId(
            "subject_id must not be empty".to_owned(),
        ))
    } else {
        Ok(())
    }
}

/// Rejects an empty [`DigestIdentifier`] used as a governance id.
pub fn validate_governance_id(
    governance_id: &DigestIdentifier,
) -> Result<(), Error> {
    if governance_id.is_empty() {
        Err(Error::InvalidSubjectId(
            "governance_id must not be empty".to_owned(),
        ))
    } else {
        Ok(())
    }
}

/// Rejects an empty [`DigestIdentifier`] used as a request id.
pub fn validate_request_id(request_id: &DigestIdentifier) -> Result<(), Error> {
    if request_id.is_empty() {
        Err(Error::InvalidSubjectId(
            "request_id must not be empty".to_owned(),
        ))
    } else {
        Ok(())
    }
}

/// Rejects empty strings with a message that names the field.
pub fn require_non_empty_str(name: &str, value: &str) -> Result<(), Error> {
    if value.is_empty() {
        Err(Error::InvalidQueryParams(format!(
            "{name} must not be empty"
        )))
    } else {
        Ok(())
    }
}

/// Parses and validates a `request_id` string used in ledger queries.
///
/// When present it must be non-empty and parseable as a [`DigestIdentifier`].
/// The parsed value is returned so callers can decide whether to use the
/// normalized identifier or the original string.
pub fn parse_request_id(request_id: &str) -> Result<DigestIdentifier, Error> {
    require_non_empty_str("request_id", request_id)?;
    DigestIdentifier::from_str(request_id).map_err(|e| {
        Error::InvalidQueryParams(format!("request_id is invalid: {e}"))
    })
}

/// Validates pagination and time-range fields of an [`EventsQuery`].
pub fn validate_events_query(query: &EventsQuery) -> Result<(), Error> {
    if let Some(quantity) = query.quantity {
        require_positive_u64("quantity", quantity)?;
    }
    for (name, value) in [
        ("event_request_ts_from", &query.event_request_ts_from),
        ("event_request_ts_to", &query.event_request_ts_to),
        ("event_ledger_ts_from", &query.event_ledger_ts_from),
        ("event_ledger_ts_to", &query.event_ledger_ts_to),
        ("sink_ts_from", &query.sink_ts_from),
        ("sink_ts_to", &query.sink_ts_to),
    ] {
        if let Some(value) = value {
            require_iso8601(name, value)?;
        }
    }
    // Page numbering starts at 0, so no positive-only check is needed.
    Ok(())
}

/// Rejects timestamps that are not well-formed ISO 8601 (RFC 3339).
fn require_iso8601(name: &str, value: &str) -> Result<(), Error> {
    OffsetDateTime::parse(value, &Rfc3339).map_err(|e| {
        Error::InvalidQueryParams(format!(
            "{name} is not a valid ISO 8601 timestamp: {e}"
        ))
    })?;
    Ok(())
}

/// Validates range and limit fields of a [`SinkEventsQuery`].
pub fn validate_sink_events_query(
    query: &SinkEventsQuery,
) -> Result<(), Error> {
    if let Some(limit) = query.limit
        && limit == 0
    {
        return Err(Error::InvalidQueryParams(
            "Replay limit must be greater than zero".to_owned(),
        ));
    }
    if let Some(limit) = query.limit
        && limit > MAX_SINK_EVENTS_LIMIT
    {
        return Err(Error::InvalidQueryParams(format!(
            "Replay limit must not exceed {MAX_SINK_EVENTS_LIMIT}"
        )));
    }
    if let (Some(from_sn), Some(to_sn)) = (query.from_sn, query.to_sn)
        && from_sn > to_sn
    {
        return Err(Error::InvalidQueryParams(
            "Replay range requires from_sn <= to_sn".to_owned(),
        ));
    }
    Ok(())
}

/// Validates pagination fields of an [`AbortsQuery`].
pub fn validate_aborts_query(query: &AbortsQuery) -> Result<(), Error> {
    if let Some(request_id) = query.request_id.as_deref() {
        parse_request_id(request_id)?;
    }
    if let Some(quantity) = query.quantity {
        require_positive_u64("quantity", quantity)?;
    }
    // Page numbering starts at 0, so no positive-only check is needed.
    Ok(())
}

/// Validates filters of a [`SinksQuery`].
pub fn validate_sinks_query(query: &SinksQuery) -> Result<(), Error> {
    if let Some(target) = &query.target
        && target != "governance"
        && target != "schema"
    {
        return Err(Error::InvalidQueryParams(format!(
            "target must be \"governance\" or \"schema\", got \"{target}\""
        )));
    }
    if let Some(schema_id) = &query.schema_id {
        require_non_empty_str("schema_id", schema_id)?;
    }
    if let Some(governance_id) = &query.governance_id {
        require_non_empty_str("governance_id", governance_id)?;
    }
    Ok(())
}

/// Validates a manual sink replay request.
pub fn validate_sink_replay_request(
    request: &SinkReplayRequest,
) -> Result<(), Error> {
    if request.requests.is_empty() {
        return Err(Error::InvalidQueryParams(
            "requests must not be empty".to_owned(),
        ));
    }
    for item in &request.requests {
        require_non_empty_str("sink", &item.sink)?;
        require_non_empty_str("subject_id", &item.subject_id)?;
        DigestIdentifier::from_str(&item.subject_id).map_err(|e| {
            Error::InvalidQueryParams(format!("subject_id is invalid: {e}"))
        })?;
    }
    Ok(())
}

/// Validates an [`EventRequest`] before it enters the ledger pipeline.
pub fn validate_event_request(request: &EventRequest) -> Result<(), Error> {
    match request {
        EventRequest::Create(create) => {
            if !create.schema_id.is_valid_in_request() {
                return Err(Error::InvalidEventRequest(
                    "schema_id is not valid in request".to_owned(),
                ));
            }
            let is_governance =
                matches!(create.schema_id, SchemaType::Governance);
            if is_governance {
                if !create.governance_id.is_empty() {
                    return Err(Error::InvalidSubjectId(
                        "governance_id must be empty for governance creation"
                            .to_owned(),
                    ));
                }
                if !create.namespace.is_empty() {
                    return Err(Error::InvalidEventRequest(
                        "namespace must be empty for governance creation"
                            .to_owned(),
                    ));
                }
            } else if create.governance_id.is_empty() {
                return Err(Error::InvalidSubjectId(
                    "governance_id must not be empty".to_owned(),
                ));
            }
        }
        EventRequest::Fact(fact) => {
            if fact.subject_id.is_empty() {
                return Err(Error::InvalidSubjectId(
                    "subject_id must not be empty".to_owned(),
                ));
            }
        }
        EventRequest::Transfer(transfer) => {
            if transfer.subject_id.is_empty() {
                return Err(Error::InvalidSubjectId(
                    "subject_id must not be empty".to_owned(),
                ));
            }
            if transfer.new_owner.is_empty() {
                return Err(Error::InvalidEventRequest(
                    "new_owner must not be empty".to_owned(),
                ));
            }
        }
        EventRequest::Confirm(confirm) => {
            if confirm.subject_id.is_empty() {
                return Err(Error::InvalidSubjectId(
                    "subject_id must not be empty".to_owned(),
                ));
            }
        }
        EventRequest::Reject(reject) => {
            if reject.subject_id.is_empty() {
                return Err(Error::InvalidSubjectId(
                    "subject_id must not be empty".to_owned(),
                ));
            }
        }
        EventRequest::EOL(eol) => {
            if eol.subject_id.is_empty() {
                return Err(Error::InvalidSubjectId(
                    "subject_id must not be empty".to_owned(),
                ));
            }
        }
    }
    Ok(())
}
