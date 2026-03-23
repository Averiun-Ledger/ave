use std::path::PathBuf;

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, Message,
    NotPersistentActor,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{Span, debug, error, info_span};

use ave_common::identity::{DigestIdentifier, HashAlgorithm, hash_borsh};

use super::{CompilerResponse, CompilerSupport};
use crate::metrics::try_core_metrics;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ContractCompiler {
    contract: DigestIdentifier,
    hash: HashAlgorithm,
}

impl ContractCompiler {
    pub fn new(hash: HashAlgorithm) -> Self {
        Self {
            contract: DigestIdentifier::default(),
            hash,
        }
    }
}

#[derive(Debug, Clone)]
pub enum ContractCompilerMessage {
    Compile {
        contract: String,
        contract_name: String,
        initial_value: Value,
        contract_path: PathBuf,
    },
}

impl Message for ContractCompilerMessage {}

impl NotPersistentActor for ContractCompiler {}

#[async_trait]
impl Actor for ContractCompiler {
    type Event = ();
    type Message = ContractCompilerMessage;
    type Response = CompilerResponse;

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("ContractCompiler", id),
            |parent_span| {
                info_span!(parent: parent_span, "ContractCompiler", id)
            },
        )
    }
}

#[async_trait]
impl Handler<Self> for ContractCompiler {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: ContractCompilerMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<CompilerResponse, ActorError> {
        match msg {
            ContractCompilerMessage::Compile {
                contract,
                contract_name,
                initial_value,
                contract_path,
            } => {
                let contract_hash =
                    match hash_borsh(&*self.hash.hasher(), &contract) {
                        Ok(hash) => hash,
                        Err(e) => {
                            error!(
                                msg_type = "Compile",
                                error = %e,
                                "Failed to hash contract"
                            );
                            return Err(ActorError::FunctionalCritical {
                                description: format!(
                                    "Can not hash contract: {}",
                                    e
                                ),
                            });
                        }
                    };

                if contract_hash != self.contract {
                    let (module, metadata) =
                        match CompilerSupport::compile_or_load_registered(
                            self.hash,
                            ctx,
                            &contract_name,
                            &contract,
                            &contract_path,
                            initial_value,
                        )
                        .await
                    {
                        Ok(result) => result,
                        Err(e) => {
                            error!(
                                msg_type = "Compile",
                                error = %e,
                                contract_name = %contract_name,
                                path = %contract_path.display(),
                                "Contract compilation or validation failed"
                            );
                            return Ok(CompilerResponse::Error(e));
                        }
                    };

                    {
                        let contracts =
                            CompilerSupport::contracts_helper(ctx).await?;
                        let mut contracts = contracts.write().await;
                        contracts.insert(contract_name.clone(), module);
                    }

                    self.contract = metadata.contract_hash.clone();

                    debug!(
                        msg_type = "Compile",
                        contract_name = %contract_name,
                        contract_hash = %metadata.contract_hash,
                        "Contract compiled and validated successfully"
                    );
                } else {
                    if let Some(metrics) = try_core_metrics() {
                        metrics.observe_contract_prepare(
                            "registered",
                            "skipped",
                            std::time::Duration::default(),
                        );
                    }
                    debug!(
                        msg_type = "Compile",
                        contract_name = %contract_name,
                        "Contract already compiled, skipping"
                    );
                }

                Ok(CompilerResponse::Ok)
            }
        }
    }
}
