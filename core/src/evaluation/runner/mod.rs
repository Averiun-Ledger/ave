use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
    time::Instant,
};

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, Message,
    NotPersistentActor, Response,
};
use ave_common::{
    Namespace, SchemaType, ValueWrapper, identity::PublicKey,
    schematype::ReservedWords,
};
use borsh::{BorshDeserialize, to_vec};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::RwLock;
use tracing::{Span, debug, error, info_span};
use types::{ContractResult, RunnerResult};
use wasmtime::{Module, Store};

use crate::{
    evaluation::runner::{error::RunnerError, types::EvaluateInfo},
    governance::{
        data::GovernanceData,
        events::{
            GovernanceEvent, MemberEvent, PoliciesEvent, RolesEvent,
            SchemasEvent,
        },
        model::{HashThisRole, RoleTypes, Schema},
    },
    model::common::contract::{
        MAX_FUEL, MemoryManager, WasmLimits, WasmRuntime, generate_linker,
    },
    metrics::try_core_metrics,
};

type AddRemoveChangeSchema = (
    HashSet<SchemaType>,
    HashSet<SchemaType>,
    HashSet<SchemaType>,
);

pub mod error;
pub mod types;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Runner;

impl Runner {
    async fn execute_contract(
        ctx: &ActorContext<Self>,
        data: &EvaluateInfo,
        is_owner: bool,
    ) -> Result<(RunnerResult, Vec<SchemaType>), RunnerError> {
        match data {
            EvaluateInfo::GovFact { payload, state } => {
                Self::execute_fact_gov(state.clone(), payload).await
            }
            EvaluateInfo::GovTransfer { new_owner, state } => {
                Self::execute_transfer_gov(state, new_owner)
            }
            EvaluateInfo::GovConfirm {
                new_owner,
                old_owner_name,
                state,
            } => Self::execute_confirm_gov(
                state.clone(),
                old_owner_name.clone(),
                new_owner,
            ),
            EvaluateInfo::TrackerSchemasFact {
                contract,
                init_state,
                state,
                payload,
            } => {
                Self::execute_fact_not_gov(
                    ctx, state, init_state, payload, contract, is_owner,
                )
                .await
            }
            EvaluateInfo::TrackerSchemasTransfer {
                governance_data,
                new_owner,
                old_owner,
                namespace,
                schema_id,
            } => Self::execute_transfer_not_gov(
                governance_data,
                new_owner,
                old_owner,
                namespace.clone(),
                schema_id,
            ),
        }
    }

    fn execute_transfer_not_gov(
        governance: &GovernanceData,
        new_owner: &PublicKey,
        old_owner: &PublicKey,
        namespace: Namespace,
        schema_id: &SchemaType,
    ) -> Result<(RunnerResult, Vec<SchemaType>), RunnerError> {
        if new_owner.is_empty() {
            return Err(RunnerError::InvalidEvent {
                location: "execute_transfer_not_gov",
                kind: error::InvalidEventKind::Empty {
                    what: "new owner PublicKey".to_owned(),
                },
            });
        }

        if new_owner == old_owner {
            return Err(RunnerError::InvalidEvent {
                location: "execute_transfer_not_gov",
                kind: error::InvalidEventKind::SameValue {
                    what: "new owner (same as current owner)".to_owned(),
                },
            });
        }

        if !governance.is_member(new_owner) {
            return Err(RunnerError::InvalidEvent {
                location: "execute_transfer_not_gov",
                kind: error::InvalidEventKind::NotMember {
                    who: format!("new owner {}", new_owner),
                },
            });
        }

        if !governance.has_this_role(HashThisRole::Schema {
            who: new_owner.clone(),
            role: RoleTypes::Creator,
            schema_id: schema_id.to_owned(),
            namespace: namespace.clone(),
        }) {
            return Err(RunnerError::InvalidEvent {
                location: "execute_transfer_not_gov",
                kind: error::InvalidEventKind::MissingRole {
                    who: new_owner.to_string(),
                    role: "Creator".to_owned(),
                    context: format!(
                        "schema {} with namespace {}",
                        schema_id, namespace
                    ),
                },
            });
        }

        Ok((
            RunnerResult {
                approval_required: false,
                final_state: ValueWrapper(json!([])),
            },
            vec![],
        ))
    }

    fn execute_transfer_gov(
        governance: &GovernanceData,
        new_owner: &PublicKey,
    ) -> Result<(RunnerResult, Vec<SchemaType>), RunnerError> {
        if new_owner.is_empty() {
            return Err(RunnerError::InvalidEvent {
                location: "execute_transfer_gov",
                kind: error::InvalidEventKind::Empty {
                    what: "new owner PublicKey".to_owned(),
                },
            });
        }

        let Some(owner_key) =
            governance.members.get(&ReservedWords::Owner.to_string())
        else {
            return Err(RunnerError::InvalidEvent {
                location: "execute_transfer_gov",
                kind: error::InvalidEventKind::NotFound {
                    what: "member".to_owned(),
                    id: ReservedWords::Owner.to_string(),
                },
            });
        };

        if owner_key == new_owner {
            return Err(RunnerError::InvalidEvent {
                location: "execute_transfer_gov",
                kind: error::InvalidEventKind::SameValue {
                    what: "new owner (same as current owner)".to_owned(),
                },
            });
        }

        if !governance.is_member(new_owner) {
            return Err(RunnerError::InvalidEvent {
                location: "execute_transfer_gov",
                kind: error::InvalidEventKind::NotMember {
                    who: format!("new owner {}", new_owner),
                },
            });
        }

        Ok((
            RunnerResult {
                approval_required: false,
                final_state: ValueWrapper(json!([])),
            },
            vec![],
        ))
    }

    fn execute_confirm_gov(
        mut governance: GovernanceData,
        old_owner_name: Option<String>,
        new_owner: &PublicKey,
    ) -> Result<(RunnerResult, Vec<SchemaType>), RunnerError> {
        if new_owner.is_empty() {
            return Err(RunnerError::InvalidEvent {
                location: "execute_confirm_gov",
                kind: error::InvalidEventKind::Empty {
                    what: "new owner PublicKey".to_owned(),
                },
            });
        }

        let Some(old_owner_key) = governance
            .members
            .get(&ReservedWords::Owner.to_string())
            .cloned()
        else {
            return Err(RunnerError::InvalidEvent {
                location: "execute_confirm_gov",
                kind: error::InvalidEventKind::NotFound {
                    what: "member".to_owned(),
                    id: ReservedWords::Owner.to_string(),
                },
            });
        };

        let Some(new_owner_member) = governance
            .members
            .iter()
            .find(|x| x.1 == new_owner)
            .map(|x| x.0)
            .cloned()
        else {
            return Err(RunnerError::InvalidEvent {
                location: "execute_confirm_gov",
                kind: error::InvalidEventKind::NotMember {
                    who: format!("new owner {}", new_owner),
                },
            });
        };

        governance
            .members
            .insert(ReservedWords::Owner.to_string(), new_owner.clone());
        governance.members.remove(&new_owner_member);

        governance.update_name_role(new_owner_member);

        if let Some(old_owner_name) = old_owner_name {
            if old_owner_name != old_owner_name.trim() {
                return Err(RunnerError::InvalidEvent {
                    location: "execute_confirm_gov",
                    kind: error::InvalidEventKind::InvalidValue {
                        field: "new name for old owner".to_owned(),
                        reason: "cannot have leading or trailing whitespace"
                            .to_owned(),
                    },
                });
            }

            if old_owner_name.is_empty() {
                return Err(RunnerError::InvalidEvent {
                    location: "execute_confirm_gov",
                    kind: error::InvalidEventKind::Empty {
                        what: "new name for old owner".to_owned(),
                    },
                });
            }

            if old_owner_name.len() > 100 {
                return Err(RunnerError::InvalidEvent {
                    location: "execute_confirm_gov",
                    kind: error::InvalidEventKind::InvalidSize {
                        field: "old owner new name".to_owned(),
                        actual: old_owner_name.len(),
                        max: 100,
                    },
                });
            }

            if old_owner_name == ReservedWords::Any.to_string()
                || old_owner_name == ReservedWords::Witnesses.to_string()
                || old_owner_name == ReservedWords::Owner.to_string()
            {
                return Err(RunnerError::InvalidEvent {
                    location: "execute_confirm_gov",
                    kind: error::InvalidEventKind::ReservedWord {
                        field: "old owner new name".to_owned(),
                        value: old_owner_name,
                    },
                });
            }

            if governance
                .members
                .insert(old_owner_name.clone(), old_owner_key)
                .is_some()
            {
                return Err(RunnerError::InvalidEvent {
                    location: "execute_confirm_gov",
                    kind: error::InvalidEventKind::AlreadyExists {
                        what: "member".to_owned(),
                        id: old_owner_name,
                    },
                });
            }

            governance.roles_gov.witness.insert(old_owner_name);
        }

        let mod_governance = governance.to_value_wrapper();

        Ok((
            RunnerResult {
                final_state: mod_governance,
                approval_required: false,
            },
            vec![],
        ))
    }

    async fn execute_fact_not_gov(
        ctx: &ActorContext<Self>,
        state: &ValueWrapper,
        init_state: &ValueWrapper,
        payload: &ValueWrapper,
        contract_name: &str,
        is_owner: bool,
    ) -> Result<(RunnerResult, Vec<SchemaType>), RunnerError> {
        let Some(wasm_runtime) = ctx
            .system()
            .get_helper::<Arc<WasmRuntime>>("wasm_runtime")
            .await
        else {
            return Err(RunnerError::MissingHelper {
                name: "wasm_runtime",
            });
        };

        let Some(contracts) = ctx
            .system()
            .get_helper::<Arc<RwLock<HashMap<String, Arc<Module>>>>>("contracts")
            .await
        else {
            return Err(RunnerError::MissingHelper { name: "contracts" });
        };

        let module = {
            let contracts = contracts.read().await;
            let Some(module) = contracts.get(contract_name) else {
                return Err(RunnerError::ContractNotFound {
                    name: contract_name.to_owned(),
                });
            };
            let result = module.clone();
            drop(contracts);
            result
        };

        let (context, state_ptr, init_state_ptr, event_ptr) =
            Self::generate_context(
                state,
                init_state,
                payload,
                &wasm_runtime.limits,
            )?;

        let mut store = Store::new(&wasm_runtime.engine, context);

        // Limit WASM linear memory and table growth to prevent resource exhaustion.
        store.limiter(|data| &mut data.store_limits);

        store
            .set_fuel(MAX_FUEL)
            .map_err(|e| RunnerError::WasmError {
                operation: "set fuel",
                details: e.to_string(),
            })?;

        let linker = generate_linker(&wasm_runtime.engine)?;

        let instance =
            linker.instantiate(&mut store, &module).map_err(|e| {
                RunnerError::WasmError {
                    operation: "instantiate",
                    details: e.to_string(),
                }
            })?;

        let contract_entrypoint = instance
            .get_typed_func::<(u32, u32, u32, u32), u32>(
                &mut store,
                "main_function",
            )
            .map_err(|e| RunnerError::WasmError {
                operation: "get entrypoint main_function",
                details: e.to_string(),
            })?;

        let result_ptr = contract_entrypoint
            .call(
                &mut store,
                (
                    state_ptr,
                    init_state_ptr,
                    event_ptr,
                    if is_owner { 1 } else { 0 },
                ),
            )
            .map_err(|e| RunnerError::WasmError {
                operation: "call entrypoint",
                details: e.to_string(),
            })?;

        let result = Self::get_result(&store, result_ptr)?;
        Ok((
            RunnerResult {
                approval_required: false,
                final_state: result.final_state,
            },
            vec![],
        ))
    }

    async fn execute_fact_gov(
        mut governance: GovernanceData,
        event: &ValueWrapper,
    ) -> Result<(RunnerResult, Vec<SchemaType>), RunnerError> {
        let event: GovernanceEvent = serde_json::from_value(event.0.clone())
            .map_err(|e| RunnerError::InvalidEvent {
                location: "execute_fact_gov",
                kind: error::InvalidEventKind::Other {
                    msg: format!(
                        "failed to deserialize GovernanceEvent: {}",
                        e
                    ),
                },
            })?;

        if event.is_empty() {
            return Err(RunnerError::InvalidEvent {
                location: "execute_fact_gov",
                kind: error::InvalidEventKind::Empty {
                    what: "GovernanceEvent".to_owned(),
                },
            });
        }

        if let Some(member_event) = event.members {
            let remove = Self::check_members(&member_event, &mut governance)?;
            if !remove.is_empty() {
                governance.remove_member_role(&remove);
            }
        }

        let add_change_schemas = if let Some(schema_event) = event.schemas {
            let (add_schemas, remove_schemas, change_schemas) =
                Self::apply_schemas(&schema_event, &mut governance)?;
            governance.remove_schema(remove_schemas);
            governance.add_schema(add_schemas.clone());

            add_schemas
                .union(&change_schemas)
                .cloned()
                .collect::<Vec<SchemaType>>()
        } else {
            vec![]
        };

        if let Some(roles_event) = event.roles {
            Self::check_roles(roles_event, &mut governance)?;
        }

        if let Some(policies_event) = event.policies {
            Self::check_policies(policies_event, &mut governance)?;
        }

        if !governance.check_basic_gov() {
            return Err(RunnerError::InvalidEvent {
                location: "execute_fact_gov",
                kind: error::InvalidEventKind::CannotModify {
                    what: "governance owner basic roles".to_owned(),
                    reason: "these roles are protected".to_owned(),
                },
            });
        }

        let mod_governance = governance.to_value_wrapper();

        Ok((
            RunnerResult {
                final_state: mod_governance,
                approval_required: true,
            },
            add_change_schemas,
        ))
    }

    fn check_policies(
        policies_event: PoliciesEvent,
        governance: &mut GovernanceData,
    ) -> Result<(), RunnerError> {
        if policies_event.is_empty() {
            return Err(RunnerError::InvalidEvent {
                location: "check_policies",
                kind: error::InvalidEventKind::Empty {
                    what: "PoliciesEvent".to_owned(),
                },
            });
        }

        if let Some(gov) = policies_event.governance {
            if gov.change.is_empty() {
                return Err(RunnerError::InvalidEvent {
                    location: "check_policies",
                    kind: error::InvalidEventKind::Empty {
                        what: "GovPolicieEvent change".to_owned(),
                    },
                });
            }

            let mut new_policies = governance.policies_gov.clone();

            if let Some(approve) = gov.change.approve {
                approve.check_values().map_err(|e| {
                    RunnerError::InvalidEvent {
                        location: "check_policies",
                        kind: error::InvalidEventKind::InvalidQuorum {
                            context: "governance approve policy".to_owned(),
                            details: e,
                        },
                    }
                })?;
                if approve == new_policies.approve {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_policies",
                        kind: error::InvalidEventKind::SameValue {
                            what: "governance approve policy".to_owned(),
                        },
                    });
                }
                new_policies.approve = approve;
            }

            if let Some(evaluate) = gov.change.evaluate {
                evaluate.check_values().map_err(|e| {
                    RunnerError::InvalidEvent {
                        location: "check_policies",
                        kind: error::InvalidEventKind::InvalidQuorum {
                            context: "governance evaluate policy".to_owned(),
                            details: e,
                        },
                    }
                })?;
                if evaluate == new_policies.evaluate {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_policies",
                        kind: error::InvalidEventKind::SameValue {
                            what: "governance evaluate policy".to_owned(),
                        },
                    });
                }
                new_policies.evaluate = evaluate;
            }

            if let Some(validate) = gov.change.validate {
                validate.check_values().map_err(|e| {
                    RunnerError::InvalidEvent {
                        location: "check_policies",
                        kind: error::InvalidEventKind::InvalidQuorum {
                            context: "governance validate policy".to_owned(),
                            details: e,
                        },
                    }
                })?;
                if validate == new_policies.validate {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_policies",
                        kind: error::InvalidEventKind::SameValue {
                            what: "governance validate policy".to_owned(),
                        },
                    });
                }
                new_policies.validate = validate;
            }

            governance.policies_gov = new_policies;
        }

        if let Some(schemas) = policies_event.schema {
            if schemas.is_empty() {
                return Err(RunnerError::InvalidEvent {
                    location: "check_policies",
                    kind: error::InvalidEventKind::Empty {
                        what: "SchemaIdPolicie vec".to_owned(),
                    },
                });
            }

            let mut new_policies = governance.policies_schema.clone();
            let mut seen_schema_ids: HashSet<SchemaType> = HashSet::new();

            for schema in schemas {
                if !seen_schema_ids.insert(schema.schema_id.clone()) {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_policies",
                        kind: error::InvalidEventKind::Duplicate {
                            what: "schema".to_owned(),
                            id: schema.schema_id.to_string(),
                        },
                    });
                }

                if schema.is_empty() {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_policies",
                        kind: error::InvalidEventKind::Empty {
                            what: "SchemaIdPolicie".to_owned(),
                        },
                    });
                }

                let Some(policies_schema) =
                    new_policies.get_mut(&schema.schema_id)
                else {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_policies",
                        kind: error::InvalidEventKind::NotSchema {
                            id: schema.schema_id.to_string(),
                        },
                    });
                };

                if schema.change.is_empty() {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_policies",
                        kind: error::InvalidEventKind::Empty {
                            what: "SchemaIdPolicie change".to_owned(),
                        },
                    });
                }

                if let Some(evaluate) = schema.change.evaluate {
                    evaluate.check_values().map_err(|e| {
                        RunnerError::InvalidEvent {
                            location: "check_policies",
                            kind: error::InvalidEventKind::InvalidQuorum {
                                context: format!(
                                    "schema {} evaluate policy",
                                    schema.schema_id
                                ),
                                details: e,
                            },
                        }
                    })?;
                    if evaluate == policies_schema.evaluate {
                        return Err(RunnerError::InvalidEvent {
                            location: "check_policies",
                            kind: error::InvalidEventKind::SameValue {
                                what: format!(
                                    "schema {} evaluate policy",
                                    schema.schema_id
                                ),
                            },
                        });
                    }
                    policies_schema.evaluate = evaluate;
                }

                if let Some(validate) = schema.change.validate {
                    validate.check_values().map_err(|e| {
                        RunnerError::InvalidEvent {
                            location: "check_policies",
                            kind: error::InvalidEventKind::InvalidQuorum {
                                context: format!(
                                    "schema {} validate policy",
                                    schema.schema_id
                                ),
                                details: e,
                            },
                        }
                    })?;
                    if validate == policies_schema.validate {
                        return Err(RunnerError::InvalidEvent {
                            location: "check_policies",
                            kind: error::InvalidEventKind::SameValue {
                                what: format!(
                                    "schema {} validate policy",
                                    schema.schema_id
                                ),
                            },
                        });
                    }
                    policies_schema.validate = validate;
                }
            }

            governance.policies_schema = new_policies;
        }

        Ok(())
    }

    fn check_roles(
        roles_event: RolesEvent,
        governance: &mut GovernanceData,
    ) -> Result<(), RunnerError> {
        if roles_event.is_empty() {
            return Err(RunnerError::InvalidEvent {
                location: "check_roles",
                kind: error::InvalidEventKind::Empty {
                    what: "RolesEvent".to_owned(),
                },
            });
        }

        if let Some(gov) = roles_event.governance {
            if gov.is_empty() {
                return Err(RunnerError::InvalidEvent {
                    location: "check_roles",
                    kind: error::InvalidEventKind::Empty {
                        what: "GovRoleEvent".to_owned(),
                    },
                });
            }

            let mut new_roles = governance.roles_gov.clone();

            gov.check_data(governance, &mut new_roles)?;

            governance.roles_gov = new_roles;
        }

        if let Some(schemas) = roles_event.schema {
            if schemas.is_empty() {
                return Err(RunnerError::InvalidEvent {
                    location: "check_roles",
                    kind: error::InvalidEventKind::Empty {
                        what: "SchemaIdRole vec".to_owned(),
                    },
                });
            }

            let mut new_roles = governance.roles_schema.clone();
            let mut seen_schema_ids: HashSet<SchemaType> = HashSet::new();

            for schema in schemas {
                if !seen_schema_ids.insert(schema.schema_id.clone()) {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_roles",
                        kind: error::InvalidEventKind::Duplicate {
                            what: "schema".to_owned(),
                            id: schema.schema_id.to_string(),
                        },
                    });
                }

                if schema.is_empty() {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_roles",
                        kind: error::InvalidEventKind::Empty {
                            what: "SchemaIdRole".to_owned(),
                        },
                    });
                }

                let Some(roles_schema) = new_roles.get_mut(&schema.schema_id)
                else {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_roles",
                        kind: error::InvalidEventKind::NotSchema {
                            id: schema.schema_id.to_string(),
                        },
                    });
                };

                schema.check_data(
                    governance,
                    roles_schema,
                    &schema.schema_id,
                )?;
            }

            governance.roles_schema = new_roles;
        }

        if let Some(tracker_schemas) = roles_event.tracker_schemas {
            if tracker_schemas.is_empty() {
                return Err(RunnerError::InvalidEvent {
                    location: "check_roles",
                    kind: error::InvalidEventKind::Empty {
                        what: "TrackerSchemasRoleEvent".to_owned(),
                    },
                });
            }

            let new_roles = governance.roles_tracker_schemas.clone();

            let new_roles = tracker_schemas.check_data(
                governance,
                new_roles,
                &SchemaType::TrackerSchemas,
            )?;

            governance.roles_tracker_schemas = new_roles;
        }

        Ok(())
    }

    fn apply_schemas(
        schema_event: &SchemasEvent,
        governance: &mut GovernanceData,
    ) -> Result<AddRemoveChangeSchema, RunnerError> {
        if schema_event.is_empty() {
            return Err(RunnerError::InvalidEvent {
                location: "check_schemas",
                kind: error::InvalidEventKind::Empty {
                    what: "SchemasEvent".to_owned(),
                },
            });
        }

        if let (Some(add), Some(remove)) =
            (&schema_event.add, &schema_event.remove)
        {
            let add_ids: HashSet<&SchemaType> =
                add.iter().map(|s| &s.id).collect();
            for r in remove {
                if add_ids.contains(r) {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_schemas",
                        kind: error::InvalidEventKind::CannotModify {
                            what: r.to_string(),
                            reason: "cannot add and remove the same schema in the same event"
                                .to_owned(),
                        },
                    });
                }
            }
        }

        if let (Some(add), Some(change)) =
            (&schema_event.add, &schema_event.change)
        {
            let add_ids: HashSet<&SchemaType> =
                add.iter().map(|s| &s.id).collect();
            for c in change {
                if add_ids.contains(&c.actual_id) {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_schemas",
                        kind: error::InvalidEventKind::CannotModify {
                            what: c.actual_id.to_string(),
                            reason: "cannot add and change the same schema in the same event"
                                .to_owned(),
                        },
                    });
                }
            }
        }

        let mut remove_schemas = HashSet::new();
        let mut add_schemas = HashSet::new();
        let mut change_schemas = HashSet::new();

        let mut new_schemas = governance.schemas.clone();

        if let Some(add) = schema_event.add.clone() {
            if add.is_empty() {
                return Err(RunnerError::InvalidEvent {
                    location: "check_schemas",
                    kind: error::InvalidEventKind::Empty {
                        what: "SchemaAdd vec".to_owned(),
                    },
                });
            }

            for new_schema in add {
                if !new_schema.id.is_valid() {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_schemas",
                        kind: error::InvalidEventKind::Empty {
                            what: "schema id".to_owned(),
                        },
                    });
                }

                let id_str = new_schema.id.to_string();
                if id_str != id_str.trim() {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_schemas",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: "schema id".to_owned(),
                            reason:
                                "cannot have leading or trailing whitespace"
                                    .to_owned(),
                        },
                    });
                }

                if new_schema.id.len() > 100 {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_schemas",
                        kind: error::InvalidEventKind::InvalidSize {
                            field: "schema id".to_owned(),
                            actual: new_schema.id.len(),
                            max: 100,
                        },
                    });
                }

                if new_schema.id == SchemaType::TrackerSchemas {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_schemas",
                        kind: error::InvalidEventKind::ReservedWord {
                            field: "schema id".to_owned(),
                            value: ReservedWords::TrackerSchemas.to_string(),
                        },
                    });
                }

                if new_schema.id == SchemaType::Governance {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_schemas",
                        kind: error::InvalidEventKind::ReservedWord {
                            field: "schema id".to_owned(),
                            value: ReservedWords::Governance.to_string(),
                        },
                    });
                }

                if new_schema.contract.is_empty() {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_schemas",
                        kind: error::InvalidEventKind::Empty {
                            what: format!(
                                "contract for schema {}",
                                new_schema.id
                            ),
                        },
                    });
                }

                if new_schema.contract.contains(' ') {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_schemas",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: format!(
                                "contract for schema {}",
                                new_schema.id
                            ),
                            reason: "cannot contain blank spaces".to_owned(),
                        },
                    });
                }

                if new_schemas
                    .insert(
                        new_schema.id.clone(),
                        Schema {
                            initial_value: ValueWrapper(
                                new_schema.initial_value,
                            ),
                            contract: new_schema.contract,
                        },
                    )
                    .is_some()
                {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_schemas",
                        kind: error::InvalidEventKind::AlreadyExists {
                            what: "schema".to_owned(),
                            id: new_schema.id.to_string(),
                        },
                    });
                }

                add_schemas.insert(new_schema.id);
            }
        }

        if let Some(remove) = schema_event.remove.clone() {
            if remove.is_empty() {
                return Err(RunnerError::InvalidEvent {
                    location: "check_schemas",
                    kind: error::InvalidEventKind::Empty {
                        what: "remove schema vec".to_owned(),
                    },
                });
            }

            for remove_schema in &remove {
                if !remove_schema.is_valid() {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_schemas",
                        kind: error::InvalidEventKind::Empty {
                            what: "schema id to remove".to_owned(),
                        },
                    });
                }

                if new_schemas.remove(remove_schema).is_none() {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_schemas",
                        kind: error::InvalidEventKind::CannotRemove {
                            what: remove_schema.to_string(),
                            reason: "not a schema".to_owned(),
                        },
                    });
                }
            }

            remove_schemas = remove;
        }

        if let Some(change) = schema_event.change.clone() {
            if change.is_empty() {
                return Err(RunnerError::InvalidEvent {
                    location: "check_schemas",
                    kind: error::InvalidEventKind::Empty {
                        what: "SchemaChange vec".to_owned(),
                    },
                });
            }

            let mut seen_change_ids: HashSet<SchemaType> = HashSet::new();

            for change_schema in change {
                if !seen_change_ids.insert(change_schema.actual_id.clone()) {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_schemas",
                        kind: error::InvalidEventKind::Duplicate {
                            what: "schema in change".to_owned(),
                            id: change_schema.actual_id.to_string(),
                        },
                    });
                }

                if change_schema.is_empty() {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_schemas",
                        kind: error::InvalidEventKind::Empty {
                            what: format!(
                                "change data for schema {}",
                                change_schema.actual_id
                            ),
                        },
                    });
                }

                let Some(schema_data) =
                    new_schemas.get_mut(&change_schema.actual_id)
                else {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_schemas",
                        kind: error::InvalidEventKind::NotSchema {
                            id: change_schema.actual_id.to_string(),
                        },
                    });
                };

                if let Some(new_contract) = change_schema.new_contract {
                    if new_contract.is_empty() {
                        return Err(RunnerError::InvalidEvent {
                            location: "check_schemas",
                            kind: error::InvalidEventKind::Empty {
                                what: format!(
                                    "new contract for schema {}",
                                    change_schema.actual_id
                                ),
                            },
                        });
                    }

                    if new_contract.contains(' ') {
                        return Err(RunnerError::InvalidEvent {
                            location: "check_schemas",
                            kind: error::InvalidEventKind::InvalidValue {
                                field: format!(
                                    "new contract for schema {}",
                                    change_schema.actual_id
                                ),
                                reason: "cannot contain blank spaces"
                                    .to_owned(),
                            },
                        });
                    }

                    if new_contract == schema_data.contract {
                        return Err(RunnerError::InvalidEvent {
                            location: "check_schemas",
                            kind: error::InvalidEventKind::SameValue {
                                what: format!(
                                    "contract for schema {}",
                                    change_schema.actual_id
                                ),
                            },
                        });
                    }

                    schema_data.contract = new_contract;
                }

                if let Some(init_value) = change_schema.new_initial_value {
                    if init_value == schema_data.initial_value.0 {
                        return Err(RunnerError::InvalidEvent {
                            location: "check_schemas",
                            kind: error::InvalidEventKind::SameValue {
                                what: format!(
                                    "initial_value for schema {}",
                                    change_schema.actual_id
                                ),
                            },
                        });
                    }

                    schema_data.initial_value = ValueWrapper(init_value);
                }

                change_schemas.insert(change_schema.actual_id);
            }
        }

        governance.schemas = new_schemas;
        Ok((add_schemas, remove_schemas, change_schemas))
    }

    fn check_members(
        member_event: &MemberEvent,
        governance: &mut GovernanceData,
    ) -> Result<Vec<String>, RunnerError> {
        if member_event.is_empty() {
            return Err(RunnerError::InvalidEvent {
                location: "check_members",
                kind: error::InvalidEventKind::Empty {
                    what: "MemberEvent".to_owned(),
                },
            });
        }

        if let (Some(add), Some(remove)) =
            (&member_event.add, &member_event.remove)
        {
            let add_names: HashSet<String> =
                add.iter().map(|m| m.name.trim().to_owned()).collect();
            for r in remove {
                if add_names.contains(r.as_str()) {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_members",
                        kind: error::InvalidEventKind::CannotModify {
                            what: r.clone(),
                            reason: "cannot add and remove the same member in the same event".to_owned(),
                        },
                    });
                }
            }
        }

        let mut new_members = governance.members.clone();

        if let Some(add) = member_event.add.clone() {
            if add.is_empty() {
                return Err(RunnerError::InvalidEvent {
                    location: "check_members",
                    kind: error::InvalidEventKind::Empty {
                        what: "NewMember vec".to_owned(),
                    },
                });
            }

            for new_member in add {
                if new_member.name != new_member.name.trim() {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_members",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: "member name".to_owned(),
                            reason:
                                "cannot have leading or trailing whitespace"
                                    .to_owned(),
                        },
                    });
                }

                if new_member.name.is_empty() {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_members",
                        kind: error::InvalidEventKind::Empty {
                            what: "member name".to_owned(),
                        },
                    });
                }

                if new_member.name.len() > 100 {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_members",
                        kind: error::InvalidEventKind::InvalidSize {
                            field: "member name".to_owned(),
                            actual: new_member.name.len(),
                            max: 100,
                        },
                    });
                }

                if new_member.name == ReservedWords::Any.to_string() {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_members",
                        kind: error::InvalidEventKind::ReservedWord {
                            field: "member name".to_owned(),
                            value: ReservedWords::Any.to_string(),
                        },
                    });
                }

                if new_member.name == ReservedWords::Witnesses.to_string() {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_members",
                        kind: error::InvalidEventKind::ReservedWord {
                            field: "member name".to_owned(),
                            value: ReservedWords::Witnesses.to_string(),
                        },
                    });
                }

                if new_member.name == ReservedWords::Owner.to_string() {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_members",
                        kind: error::InvalidEventKind::ReservedWord {
                            field: "member name".to_owned(),
                            value: ReservedWords::Owner.to_string(),
                        },
                    });
                }

                if new_member.key.is_empty() {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_members",
                        kind: error::InvalidEventKind::Empty {
                            what: format!("key for member {}", new_member.name),
                        },
                    });
                }

                if new_members
                    .insert(new_member.name.clone(), new_member.key)
                    .is_some()
                {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_members",
                        kind: error::InvalidEventKind::AlreadyExists {
                            what: "member".to_owned(),
                            id: new_member.name,
                        },
                    });
                }
            }
        }

        let remove_members = if let Some(remove) = member_event.remove.clone() {
            if remove.is_empty() {
                return Err(RunnerError::InvalidEvent {
                    location: "check_members",
                    kind: error::InvalidEventKind::Empty {
                        what: "remove member vec".to_owned(),
                    },
                });
            }

            for remove_member in remove.clone() {
                if remove_member != remove_member.trim() {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_members",
                        kind: error::InvalidEventKind::InvalidValue {
                            field: "member name to remove".to_owned(),
                            reason:
                                "cannot have leading or trailing whitespace"
                                    .to_owned(),
                        },
                    });
                }

                if remove_member.is_empty() {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_members",
                        kind: error::InvalidEventKind::Empty {
                            what: "member name to remove".to_owned(),
                        },
                    });
                }

                if remove_member == ReservedWords::Owner.to_string() {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_members",
                        kind: error::InvalidEventKind::CannotRemove {
                            what: ReservedWords::Owner.to_string(),
                            reason: "governance owner cannot be removed"
                                .to_owned(),
                        },
                    });
                }

                if new_members.remove(&remove_member).is_none() {
                    return Err(RunnerError::InvalidEvent {
                        location: "check_members",
                        kind: error::InvalidEventKind::CannotRemove {
                            what: remove_member,
                            reason: "not a member".to_owned(),
                        },
                    });
                }
            }

            remove.iter().cloned().collect::<Vec<String>>()
        } else {
            vec![]
        };

        let members_name: HashSet<String> =
            new_members.keys().cloned().collect();
        let members_value: HashSet<PublicKey> =
            new_members.values().cloned().collect();

        if new_members.contains_key(&ReservedWords::Any.to_string()) {
            return Err(RunnerError::InvalidEvent {
                location: "check_members",
                kind: error::InvalidEventKind::ReservedWord {
                    field: "member name".to_owned(),
                    value: ReservedWords::Any.to_string(),
                },
            });
        }

        if new_members.contains_key(&ReservedWords::Witnesses.to_string()) {
            return Err(RunnerError::InvalidEvent {
                location: "check_members",
                kind: error::InvalidEventKind::ReservedWord {
                    field: "member name".to_owned(),
                    value: ReservedWords::Witnesses.to_string(),
                },
            });
        }

        if members_name.len() != members_value.len() {
            return Err(RunnerError::InvalidEvent {
                location: "check_members",
                kind: error::InvalidEventKind::Duplicate {
                    what: "member key".to_owned(),
                    id: "multiple members share the same key".to_owned(),
                },
            });
        }

        governance.members = new_members;

        Ok(remove_members)
    }

    fn generate_context(
        state: &ValueWrapper,
        init_state: &ValueWrapper,
        event: &ValueWrapper,
        limits: &WasmLimits,
    ) -> Result<(MemoryManager, u32, u32, u32), RunnerError> {
        let mut context = MemoryManager::from_limits(limits);

        let state_bytes =
            to_vec(&state).map_err(|e| RunnerError::SerializationError {
                context: "serialize state",
                details: e.to_string(),
            })?;
        let state_ptr = context.add_data_raw(&state_bytes)?;

        let init_state_bytes = to_vec(&init_state).map_err(|e| {
            RunnerError::SerializationError {
                context: "serialize init_state",
                details: e.to_string(),
            }
        })?;
        let init_state_ptr = context.add_data_raw(&init_state_bytes)?;

        let event_bytes =
            to_vec(&event).map_err(|e| RunnerError::SerializationError {
                context: "serialize event",
                details: e.to_string(),
            })?;
        let event_ptr = context.add_data_raw(&event_bytes)?;

        Ok((
            context,
            state_ptr as u32,
            init_state_ptr as u32,
            event_ptr as u32,
        ))
    }

    fn get_result(
        store: &Store<MemoryManager>,
        pointer: u32,
    ) -> Result<ContractResult, RunnerError> {
        let bytes = store.data().read_data(pointer as usize)?;

        let contract_result: ContractResult =
            BorshDeserialize::try_from_slice(bytes).map_err(|e| {
                RunnerError::SerializationError {
                    context: "deserialize ContractResult",
                    details: e.to_string(),
                }
            })?;

        if contract_result.success {
            Ok(contract_result)
        } else {
            Err(RunnerError::ContractFailed {
                details: format!(
                    "Contract execution in running was not successful: {}",
                    contract_result.error
                ),
            })
        }
    }
}

#[derive(Debug, Clone)]
pub struct RunnerMessage {
    pub data: EvaluateInfo,
    pub is_owner: bool,
}

impl Message for RunnerMessage {}

#[derive(Debug, Clone)]
pub enum RunnerResponse {
    Ok {
        result: RunnerResult,
        compilations: Vec<SchemaType>,
    },
    Error(RunnerError),
}

impl Response for RunnerResponse {}

#[async_trait]
impl Actor for Runner {
    type Event = ();
    type Message = RunnerMessage;
    type Response = RunnerResponse;

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("Runner"),
            |parent_span| info_span!(parent: parent_span, "Runner"),
        )
    }
}

impl NotPersistentActor for Runner {}

#[async_trait]
impl Handler<Self> for Runner {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: RunnerMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<RunnerResponse, ActorError> {
        let started_at = Instant::now();
        match Self::execute_contract(ctx, &msg.data, msg.is_owner).await {
            Ok((result, compilations)) => {
                if let Some(metrics) = try_core_metrics() {
                    metrics.observe_contract_execution(
                        "success",
                        started_at.elapsed(),
                    );
                }
                debug!(
                    msg_type = "Execute",
                    approval_required = result.approval_required,
                    compilations_count = compilations.len(),
                    is_owner = msg.is_owner,
                    "Contract executed successfully"
                );
                Ok(RunnerResponse::Ok {
                    result,
                    compilations,
                })
            }
            Err(e) => {
                if let Some(metrics) = try_core_metrics() {
                    metrics.observe_contract_execution(
                        "error",
                        started_at.elapsed(),
                    );
                }
                error!(
                    msg_type = "Execute",
                    error = %e,
                    is_owner = msg.is_owner,
                    "Contract execution failed"
                );
                Ok(RunnerResponse::Error(e))
            }
        }
    }
}
