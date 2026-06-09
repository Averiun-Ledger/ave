//! Sink-related data models for core subjects.

use ave_actors::Event;
use ave_common::response::SubjectDB;
use serde::{Deserialize, Serialize};

use crate::model::event::Ledger;

/// Event type emitted by `Governance` and `Tracker` via `publish_all` for `InternalDB` consumption.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SinkDataEvent {
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
