//! Governance-fact contract sources shared by the node and the
//! off-chain verification tool.

use crate::{SchemaType, ValueWrapper, governance::GovernanceEvent};

/// Contract sources coming in a governance fact payload, paired with
/// their schema id.
///
/// Every added schema plus every change with a new
/// contract. These are the only contracts the compilation phase stages —
/// unchanged contracts reuse the official artifact. Returns an empty vec
/// when the payload is not a valid governance event.
pub fn payload_contract_sources(
    payload: &ValueWrapper,
) -> Vec<(SchemaType, String)> {
    let mut sources = Vec::new();
    let Ok(event) =
        serde_json::from_value::<GovernanceEvent>(payload.0.clone())
    else {
        return sources;
    };

    if let Some(schemas_event) = event.schemas {
        if let Some(add) = schemas_event.add {
            sources.extend(
                add.into_iter().map(|schema| (schema.id, schema.contract)),
            );
        }
        if let Some(change) = schemas_event.change {
            sources.extend(change.into_iter().filter_map(|schema| {
                schema
                    .new_contract
                    .map(|contract| (schema.actual_id, contract))
            }));
        }
    }

    sources
}
