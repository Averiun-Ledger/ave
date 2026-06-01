//! Sink-related data models for core subjects.

use ave_actors::Event;
use ave_common::{DataToSink, DataToSinkEvent};
use ave_common::response::SubjectDB;
use serde::{Deserialize, Serialize};

use crate::model::event::Ledger;

/// Event type emitted by the `SinkData` actor.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SinkDataEvent {
    Event(Box<DataToSink>),
    State(Box<SubjectDB>),
}

/// Unified sink event for `Governance` and `Tracker` actors.
///
/// Combines raw ledger events with enriched sink-data events so that
/// subscribers can choose which stream they are interested in.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SubjectSinkEvent {
    Ledger(Box<Ledger>),
    SinkData(SinkDataEvent),
}

impl Event for SubjectSinkEvent {}

/// Categorisation of sink event types used for routing/filtering.
#[derive(
    Debug, Clone, Serialize, Deserialize, Eq, Ord, PartialEq, PartialOrd,
)]
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
