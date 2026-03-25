use std::path::PathBuf;
use std::time::Instant;

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, Message,
    NotPersistentActor,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tokio::fs;
use tracing::{Span, error, info_span};

use ave_common::identity::HashAlgorithm;

use super::{CompilerResponse, CompilerSupport};
use crate::metrics::try_core_metrics;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TempCompiler {
    hash: HashAlgorithm,
}

impl TempCompiler {
    pub const fn new(hash: HashAlgorithm) -> Self {
        Self { hash }
    }
}

#[derive(Debug, Clone)]
pub enum TempCompilerMessage {
    Compile {
        contract: String,
        contract_name: String,
        initial_value: Value,
        contract_path: PathBuf,
    },
}

impl Message for TempCompilerMessage {}

impl NotPersistentActor for TempCompiler {}

#[async_trait]
impl Actor for TempCompiler {
    type Event = ();
    type Message = TempCompilerMessage;
    type Response = CompilerResponse;

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("TempCompiler", id),
            |parent_span| info_span!(parent: parent_span, "TempCompiler", id),
        )
    }
}

#[async_trait]
impl Handler<Self> for TempCompiler {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: TempCompilerMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<CompilerResponse, ActorError> {
        match msg {
            TempCompilerMessage::Compile {
                contract,
                contract_name,
                initial_value,
                contract_path,
            } => {
                let started_at = Instant::now();
                let _ = fs::remove_dir_all(&contract_path).await;
                if let Err(e) = CompilerSupport::compile_fresh(
                    self.hash,
                    ctx,
                    &contract,
                    &contract_path,
                    initial_value,
                )
                .await
                {
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
                        path = %contract_path.display(),
                        "Temporary contract compilation or validation failed"
                    );
                    let _ = fs::remove_dir_all(&contract_path).await;
                    return Ok(CompilerResponse::Error(e));
                }

                if let Some(metrics) = try_core_metrics() {
                    metrics.observe_contract_prepare(
                        "temporary",
                        "recompiled",
                        started_at.elapsed(),
                    );
                }

                if let Err(e) = fs::remove_dir_all(&contract_path).await {
                    error!(
                        msg_type = "Compile",
                        error = %e,
                        path = %contract_path.display(),
                        "Failed to remove temporal contract directory"
                    );
                }

                Ok(CompilerResponse::Ok)
            }
        }
    }
}
