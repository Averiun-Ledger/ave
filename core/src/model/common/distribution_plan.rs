use std::collections::HashMap;

use ave_common::{
    identity::PublicKey,
    request::EventRequest,
    schematype::ReservedWords,
};

use crate::{
    governance::{
        data::GovernanceData,
        model::{RoleTypes, WitnessesData},
    },
    request::types::{DistributionPlanEntry, DistributionPlanMode},
    subject::Metadata,
};

fn merge_distribution_mode(
    current: DistributionPlanMode,
    next: DistributionPlanMode,
) -> DistributionPlanMode {
    match (current, next) {
        (DistributionPlanMode::Clear, ..)
        | (DistributionPlanMode::Opaque, DistributionPlanMode::Clear) => {
            DistributionPlanMode::Clear
        }
        (DistributionPlanMode::Opaque, DistributionPlanMode::Opaque) => {
            DistributionPlanMode::Opaque
        }
    }
}

fn upsert_distribution_plan(
    plan: &mut HashMap<PublicKey, DistributionPlanMode>,
    node: PublicKey,
    mode: DistributionPlanMode,
) {
    plan.entry(node)
        .and_modify(|current| {
            *current =
                merge_distribution_mode(current.clone(), mode.clone());
        })
        .or_insert(mode);
}

fn tracker_fact_mode_for_witness(
    governance_data: &GovernanceData,
    metadata: &Metadata,
    witness: &PublicKey,
    viewpoints: &std::collections::BTreeSet<String>,
) -> DistributionPlanMode {
    if metadata.owner == *witness
        || metadata.new_owner.as_ref().is_some_and(|x| x == witness)
    {
        return DistributionPlanMode::Clear;
    }

    let Some(witness_name) = governance_data
        .members
        .iter()
        .find(|(_, key)| *key == witness)
        .map(|(name, _)| name.clone())
    else {
        return DistributionPlanMode::Opaque;
    };

    let Some(owner_name) = governance_data
        .members
        .iter()
        .find(|(_, key)| *key == &metadata.owner)
        .map(|(name, _)| name.clone())
    else {
        return DistributionPlanMode::Opaque;
    };

    let Some(roles_schema) = governance_data.roles_schema.get(&metadata.schema_id) else {
        return DistributionPlanMode::Opaque;
    };

    let Some(role_creator) = roles_schema
        .creator
        .get(&ave_common::governance::RoleCreator::create(
            &owner_name,
            metadata.namespace.clone(),
        ))
    else {
        return DistributionPlanMode::Opaque;
    };

    let is_generic_witness = roles_schema.hash_this_rol(
        RoleTypes::Witness,
        metadata.namespace.clone(),
        &witness_name,
    ) || governance_data.roles_tracker_schemas.hash_this_rol(
        RoleTypes::Witness,
        metadata.namespace.clone(),
        &witness_name,
    );

    let allows_clear = role_creator.witnesses.iter().any(|creator_witness| {
        let applies = creator_witness.name == witness_name
            || (creator_witness.name == ReservedWords::Witnesses.to_string()
                && is_generic_witness);

        if !applies {
            return false;
        }

        creator_witness.viewpoints.is_empty()
            || creator_witness
                .viewpoints
                .contains(&ReservedWords::AllViewpoints.to_string())
            || viewpoints.is_empty()
            || viewpoints.is_subset(&creator_witness.viewpoints)
    });

    if allows_clear {
        DistributionPlanMode::Clear
    } else {
        DistributionPlanMode::Opaque
    }
}

pub fn build_tracker_event_distribution_plan(
    governance_data: &GovernanceData,
    event_request: &EventRequest,
    metadata: &Metadata,
    protocols_success: bool,
) -> Result<Vec<DistributionPlanEntry>, String> {
    let mut plan: HashMap<PublicKey, DistributionPlanMode> = HashMap::new();

    match event_request {
        EventRequest::Fact(fact_request) => {
            let witnesses = governance_data
                .get_witnesses(WitnessesData::Schema {
                    creator: metadata.owner.clone(),
                    schema_id: metadata.schema_id.clone(),
                    namespace: metadata.namespace.clone(),
                })
                .map_err(|e| e.to_string())?;

            for witness in witnesses {
                let mode = tracker_fact_mode_for_witness(
                    governance_data,
                    metadata,
                    &witness,
                    &fact_request.viewpoints,
                );

                upsert_distribution_plan(&mut plan, witness, mode);
            }
        }
        EventRequest::Transfer(transfer_request) => {
            let witnesses = governance_data
                .get_witnesses(WitnessesData::Schema {
                    creator: metadata.owner.clone(),
                    schema_id: metadata.schema_id.clone(),
                    namespace: metadata.namespace.clone(),
                })
                .map_err(|e| e.to_string())?;

            for witness in witnesses {
                upsert_distribution_plan(
                    &mut plan,
                    witness,
                    DistributionPlanMode::Clear,
                );
            }

            if protocols_success {
                upsert_distribution_plan(
                    &mut plan,
                    transfer_request.new_owner.clone(),
                    DistributionPlanMode::Clear,
                );
            }
        }
        EventRequest::Confirm(..) | EventRequest::Reject(..) => {
            let new_owner = metadata
                .new_owner
                .clone()
                .ok_or_else(|| {
                    "Tracker confirm/reject without new_owner".to_owned()
                })?;

            let witnesses = governance_data
                .get_witnesses(WitnessesData::Schema {
                    creator: new_owner.clone(),
                    schema_id: metadata.schema_id.clone(),
                    namespace: metadata.namespace.clone(),
                })
                .map_err(|e| e.to_string())?;

            for witness in witnesses {
                upsert_distribution_plan(
                    &mut plan,
                    witness,
                    DistributionPlanMode::Clear,
                );
            }

            if protocols_success {
                upsert_distribution_plan(
                    &mut plan,
                    metadata.owner.clone(),
                    DistributionPlanMode::Clear,
                );
            }
        }
        _ => {
            let witnesses = governance_data
                .get_witnesses(WitnessesData::Schema {
                    creator: metadata.owner.clone(),
                    schema_id: metadata.schema_id.clone(),
                    namespace: metadata.namespace.clone(),
                })
                .map_err(|e| e.to_string())?;

            for witness in witnesses {
                upsert_distribution_plan(
                    &mut plan,
                    witness,
                    DistributionPlanMode::Clear,
                );
            }
        }
    }

    Ok(plan
        .into_iter()
        .map(|(node, mode)| DistributionPlanEntry { node, mode })
        .collect())
}
