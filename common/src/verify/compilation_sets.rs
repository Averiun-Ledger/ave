//! Compilation-set decisions shared by the node and the off-chain
//! verification tool: which schemas a governance fact compiles.

use crate::{SchemaType, ValueWrapper, governance::GovernanceEvent};

use std::collections::BTreeSet;

/// Schemas whose contract must go through the compilation phase for this
/// governance fact payload.
///
/// Every added schema plus every change with a
/// new contract or a new initial value. `None` when the payload is not a
/// valid governance event — evaluation will fail the event instead.
pub fn schemas_to_compile(
    payload: &ValueWrapper,
) -> Option<BTreeSet<SchemaType>> {
    let event: GovernanceEvent =
        serde_json::from_value(payload.0.clone()).ok()?;

    let mut schemas = BTreeSet::new();
    if let Some(schemas_event) = &event.schemas {
        if let Some(add) = &schemas_event.add {
            schemas.extend(add.iter().map(|schema| schema.id.clone()));
        }
        if let Some(change) = &schemas_event.change {
            schemas.extend(
                change
                    .iter()
                    .filter(|schema| {
                        schema.new_contract.is_some()
                            || schema.new_initial_value.is_some()
                    })
                    .map(|schema| schema.actual_id.clone()),
            );
        }
    }

    Some(schemas)
}

/// Full compilation set for a governance fact against the committed
/// governance state.
///
/// The payload set above, plus — when the event
/// changes the toolchain pin — every existing schema, recompiled under
/// the new pin with fresh evidence (a pin switch never reuses old-pin's
/// builds). `None` exactly when `schemas_to_compile` is `None`.
///
/// An unknown pin short-circuits to the empty set: no node can build
/// it, so compiling would reboot forever without ever reaching the
/// evaluation that deterministically rejects it. The registry is
/// global, hence manager and validators take the identical decision
/// here, by construction.
pub fn compilation_set(
    payload: &ValueWrapper,
    pre: &super::governance::GovernanceData,
) -> Option<BTreeSet<SchemaType>> {
    let mut schemas = schemas_to_compile(payload)?;
    let event: GovernanceEvent =
        serde_json::from_value(payload.0.clone()).ok()?;
    if let Some(new_pin) = event.toolchain.as_ref()
        && crate::governance::toolchain_info(new_pin).is_none()
    {
        return Some(BTreeSet::new());
    }
    if event
        .toolchain
        .as_ref()
        .is_some_and(|new_pin| *new_pin != pre.toolchain)
    {
        schemas.extend(pre.schemas.keys().cloned());
        // Removed schemas leave with the event: building them would
        // waste work and anchor bytes nobody can ever serve.
        if let Some(remove) = event
            .schemas
            .as_ref()
            .and_then(|schemas| schemas.remove.as_ref())
        {
            for removed in remove {
                schemas.remove(removed);
            }
        }
    }
    Some(schemas)
}

/// Whether a governance fact enters the compilation phase.
///
/// The schema set above is non-empty, or it is a bare switch to a
/// KNOWN pin with nothing to build. The bare switch is a capacity
/// vote — compilers attest by voting, not by building — so a pin
/// can never commit
/// without a builder quorum behind it. Unknown pins return false here
/// (evaluation rejects them); same-pin no-ops too (rejected as
/// no-ops). Manager and validators share this decision, so they can
/// never disagree on whether evidence must exist.
pub fn needs_compilation_evidence(
    payload: &ValueWrapper,
    pre: &super::governance::GovernanceData,
) -> bool {
    if compilation_set(payload, pre).is_some_and(|schemas| !schemas.is_empty())
    {
        return true;
    }
    serde_json::from_value::<GovernanceEvent>(payload.0.clone())
        .ok()
        .and_then(|event| event.toolchain)
        .is_some_and(|new_pin| {
            new_pin != pre.toolchain
                && crate::governance::toolchain_info(&new_pin).is_some()
        })
}
