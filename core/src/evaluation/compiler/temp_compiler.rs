use std::time::Instant;

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, Message,
    NotPersistentActor,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tracing::{Span, error, info_span};

use ave_common::ValueWrapper;

use super::{CompilerResponse, CompilerSupport};
use crate::metrics::try_core_metrics;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TempCompiler;

#[derive(Debug, Clone)]
pub enum TempCompilerMessage {
    Compile {
        contract: String,
        contract_name: String,
        initial_value: Value,
    },
}

impl Message for TempCompilerMessage {}

impl NotPersistentActor for TempCompiler {}

#[async_trait]
impl Actor for TempCompiler {
    type Event = ();
    type Message = TempCompilerMessage;
    type Response = CompilerResponse;
    type SinkEvent = ();
    type ChildError = ActorError;
    type ChildFault = ActorError;

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("TempCompiler"),
            |parent_span| info_span!(parent: parent_span, "TempCompiler"),
        )
    }
}

#[async_trait]
impl Handler<Self> for TempCompiler {
    async fn handle_message(
        &mut self,
        _: ActorPath,
        msg: TempCompilerMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<CompilerResponse, ActorError> {
        match msg {
            TempCompilerMessage::Compile {
                contract,
                contract_name,
                initial_value,
            } => {
                let started_at = Instant::now();

                // The node never compiles locally: the wasm comes from the
                // compiler service and is precompiled and validated
                // (init_check) in memory. Nothing touches the disk and
                // nothing is persisted: the artifact is discarded after
                // validation.
                let result = async {
                    ave_compiler::validate_source_base64(&contract)?;
                    let contract_runtime =
                        CompilerSupport::contract_runtime(ctx).await?;
                    let client = CompilerSupport::compiler_client(ctx).await?;
                    let outcome = client.compile(&contract).await?;
                    let (_, module) = ave_compiler::precompile_module(
                        &contract_runtime,
                        &outcome.wasm,
                    )?;
                    ave_compiler::validate_module(
                        &contract_runtime,
                        &module,
                        ValueWrapper(initial_value),
                    )?;
                    Ok::<(), super::error::CompilerError>(())
                }
                .await;

                if let Err(e) = result {
                    if let Some(metrics) = try_core_metrics() {
                        metrics.observe_contract_prepare(
                            "temporary",
                            "error",
                            started_at.elapsed(),
                        );
                    }
                    error!(
                        msg_type = "Compile",
                        error = %e,
                        contract_name = %contract_name,
                        "Temporary contract compilation or validation failed"
                    );
                    return Ok(CompilerResponse::Error(e));
                }

                if let Some(metrics) = try_core_metrics() {
                    metrics.observe_contract_prepare(
                        "temporary",
                        "recompiled",
                        started_at.elapsed(),
                    );
                }

                Ok(CompilerResponse::Ok)
            }
        }
    }
}
