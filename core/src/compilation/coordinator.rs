use std::{sync::Arc, time::Duration};

use crate::{
    helpers::network::{NetworkMessage, service::NetworkSender},
    model::{common::crash_system, network::RetryNetwork},
};

use crate::helpers::network::ActorMessage;

use async_trait::async_trait;
use ave_common::identity::{HashAlgorithm, PublicKey, Signed, hash_borsh};

use ave_network::ComunicateInfo;

use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, IntervalStrategy,
    Message, NotPersistentActor, RetryActor, RetryMessage, Strategy,
};

use tracing::{Span, debug, error, info_span, warn};

use super::{
    Compilation, CompilationMessage, request::CompilationReq,
    response::CompilationRes,
};

/// Deadline for the final result once a compiler has ACKed the request
/// (`CompilationRes::Working`): compiling a large contract legitimately
/// exceeds the ACK retry budget, so after the ACK the request is no
/// longer resent and the result is awaited up to this limit. When it
/// fires, the compiler is dropped as a timeout — exactly like an
/// exhausted ACK retry.
#[cfg(any(test, feature = "test"))]
const RESULT_DEADLINE: Duration = Duration::from_secs(300);
/// Deadline for the final result once a compiler has ACKed the request
/// (`CompilationRes::Working`): compiling a large contract legitimately
/// exceeds the ACK retry budget, so after the ACK the request is no
/// longer resent and the result is awaited up to this limit. When it
/// fires, the compiler is dropped as a timeout — exactly like an
/// exhausted ACK retry.
#[cfg(not(any(test, feature = "test")))]
const RESULT_DEADLINE: Duration = Duration::from_secs(600);

/// A struct representing a CompileCoordinator actor.
#[derive(Clone, Debug)]
pub struct CompileCoordinator {
    node_key: PublicKey,
    request_id: String,
    version: u64,
    network: Arc<NetworkSender>,
    hash: HashAlgorithm,
    /// The compiler ACKed the request (`CompilationRes::Working`): the
    /// request retry is cancelled and the final result is awaited under
    /// `RESULT_DEADLINE`.
    acked: bool,
}

impl CompileCoordinator {
    pub const fn new(
        node_key: PublicKey,
        request_id: String,
        version: u64,
        network: Arc<NetworkSender>,
        hash: HashAlgorithm,
    ) -> Self {
        Self {
            node_key,
            request_id,
            version,
            network,
            hash,
            acked: false,
        }
    }

    fn verify_result_response(
        &self,
        result: &super::response::CompilationResult,
        result_hash: &ave_common::identity::DigestIdentifier,
        result_hash_signature: &ave_common::identity::Signature,
    ) -> Result<(), ActorError> {
        let hash = hash_borsh(&*self.hash.hasher(), result).map_err(|e| {
            error!(
                msg_type = "NetworkResponse",
                error = %e,
                "Failed to create compilation result hash"
            );

            ActorError::Functional {
                description: format!("Can not verify signature: {}", e),
            }
        })?;

        if &hash != result_hash {
            error!(
                msg_type = "NetworkResponse",
                result_hash = %result_hash,
                generated_hash = %hash,
                "Result hash is invalid"
            );

            return Err(ActorError::Functional {
                description: "Result hash is invalid".to_string(),
            });
        }

        result_hash_signature.verify(result_hash).map_err(|e| {
            error!(
                msg_type = "NetworkResponse",
                error = %e,
                "Failed to verify compilation result hash signature"
            );

            ActorError::Functional {
                description: format!("Can not verify signature: {}", e),
            }
        })?;

        if result_hash_signature.signer != self.node_key {
            error!(
                msg_type = "NetworkResponse",
                expected_signer = %self.node_key,
                actual_signer = %result_hash_signature.signer,
                "Compilation result hash signature signer mismatch"
            );

            return Err(ActorError::Functional {
                description:
                    "Compilation result hash signature signer mismatch"
                        .to_string(),
            });
        }

        Ok(())
    }

    /// The compiler never answered in time — the ACK retry was
    /// exhausted, or the result deadline fired after a
    /// `CompilationRes::Working` ACK: report it as a timeout so the
    /// compilation phase drops it and replaces it from the pending
    /// pool. If the phase was already torn down, the timeout is moot
    /// and dropped.
    async fn notify_timeout(&self, ctx: &ActorContext<Self>) {
        match ctx.get_parent::<Compilation>().await {
            Ok(compilation_actor) => {
                if let Err(e) = compilation_actor
                    .tell(CompilationMessage::Response {
                        compilation_res: CompilationRes::TimeOut,
                        sender: self.node_key.clone(),
                    })
                    .await
                {
                    // The phase was torn down while this timeout
                    // was in flight: it is moot, drop it.
                    debug!(
                        error = %e,
                        "Compilation actor gone, dropping timeout response"
                    );
                } else {
                    debug!(
                        request_id = %self.request_id,
                        version = self.version,
                        "Timeout response sent to compilation actor"
                    );
                }
            }
            Err(e) => {
                // Same teardown race: the phase actor is gone.
                debug!(
                    error = %e,
                    path = %ctx.path().parent(),
                    "Compilation actor not found, dropping timeout response"
                );
            }
        }
    }
}

#[derive(Debug, Clone)]
pub enum CompileCoordinatorMessage {
    EndRetry,
    /// The result deadline fired after a `CompilationRes::Working` ACK:
    /// the compiler accepted the job but never delivered the result.
    ResultDeadline,
    NetworkCompilation {
        compilation_req: Box<Signed<CompilationReq>>,
        node_key: PublicKey,
    },
    NetworkResponse {
        compilation_res: Box<CompilationRes>,
        request_id: String,
        version: u64,
        sender: PublicKey,
    },
}

impl Message for CompileCoordinatorMessage {}

#[async_trait]
impl Actor for CompileCoordinator {
    type Event = ();
    type Message = CompileCoordinatorMessage;
    type Response = ();
    type SinkEvent = ();
    type ChildError = ActorError;
    type ChildFault = ActorError;

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("CompileCoordinator", id),
            |parent_span| info_span!(parent: parent_span, "CompileCoordinator", id),
        )
    }
}

impl NotPersistentActor for CompileCoordinator {}

#[async_trait]
impl Handler<Self> for CompileCoordinator {
    async fn handle_message(
        &mut self,
        _: ActorPath,
        msg: CompileCoordinatorMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        match msg {
            CompileCoordinatorMessage::EndRetry => {
                // The retry actor reports cycle completion also on an
                // explicit `End` — which is exactly how the `Working`
                // ACK cancels it. That notification is expected: the
                // result deadline governs the wait from now on.
                if self.acked {
                    debug!(
                        node_key = %self.node_key,
                        request_id = %self.request_id,
                        version = self.version,
                        "Retry ended by working ACK, awaiting result"
                    );
                    return Ok(());
                }

                warn!(
                    node_key = %self.node_key,
                    request_id = %self.request_id,
                    version = self.version,
                    "Retry exhausted, notifying parent and stopping"
                );

                self.notify_timeout(ctx).await;

                ctx.stop(None).await;
            }
            CompileCoordinatorMessage::ResultDeadline => {
                warn!(
                    node_key = %self.node_key,
                    request_id = %self.request_id,
                    version = self.version,
                    "Result deadline fired after working ACK, notifying parent and stopping"
                );

                self.notify_timeout(ctx).await;

                ctx.stop(None).await;
            }
            CompileCoordinatorMessage::NetworkCompilation {
                compilation_req,
                node_key,
            } => {
                // The compilation phase only exists for governance facts.
                let receiver_actor = format!(
                    "/user/node/subject_manager/{}/compiler",
                    compilation_req.content().governance_id
                );

                // Fire the event that starts the retries.
                let message = NetworkMessage {
                    info: ComunicateInfo {
                        request_id: self.request_id.clone(),
                        version: self.version,
                        receiver: node_key.clone(),
                        receiver_actor,
                    },
                    message: ActorMessage::CompilationReq {
                        req: compilation_req,
                    },
                };

                let target = RetryNetwork::new(self.network.clone());

                #[cfg(any(test, feature = "test"))]
                let strategy = Strategy::Interval(IntervalStrategy::new(
                    1,
                    Duration::from_secs(5),
                ));
                #[cfg(not(any(test, feature = "test")))]
                let strategy = Strategy::Interval(IntervalStrategy::new(
                    3,
                    Duration::from_secs(60),
                ));

                let retry_actor = RetryActor::new_with_parent_message::<Self>(
                    target,
                    message,
                    strategy,
                    CompileCoordinatorMessage::EndRetry,
                );

                let retry = match ctx
                    .create_child::<RetryActor<RetryNetwork>, _>(
                        "retry",
                        retry_actor,
                    )
                    .await
                {
                    Ok(retry) => retry,
                    Err(e) => {
                        error!(
                            msg_type = "NetworkCompilation",
                            error = %e,
                            "Failed to create retry actor"
                        );
                        return Err(crash_system(ctx, e).await);
                    }
                };

                if let Err(e) = retry.tell(RetryMessage::Retry).await {
                    error!(
                        msg_type = "NetworkCompilation",
                        error = %e,
                        "Failed to send retry message to retry actor"
                    );
                    return Err(crash_system(ctx, e).await);
                };

                debug!(
                    msg_type = "NetworkCompilation",
                    request_id = %self.request_id,
                    version = self.version,
                    node_key = %node_key,
                    "Compilation request sent to network with retry"
                );
            }
            CompileCoordinatorMessage::NetworkResponse {
                compilation_res,
                request_id,
                version,
                sender,
            } => {
                if request_id == self.request_id && version == self.version {
                    if self.node_key != sender {
                        // A forged or misrouted response: report the
                        // compiler as timed out so the phase drops and
                        // replaces it at once instead of burning the
                        // slot until the result deadline.
                        warn!(
                            msg_type = "NetworkResponse",
                            expected_node = %self.node_key,
                            network_sender = %sender,
                            "Compilation response sender mismatch, dropping compiler"
                        );
                        self.notify_timeout(ctx).await;
                        ctx.stop(None).await;
                        return Ok(());
                    }

                    // Working ACK: the compiler accepted the job. Stop
                    // resending the request and await the final result
                    // under the result deadline — it carries no verdict,
                    // so it is never forwarded to the compilation actor.
                    if matches!(&*compilation_res, CompilationRes::Working) {
                        if self.acked {
                            // A duplicate ACK (a request retry was
                            // already in flight when the first one
                            // arrived): harmless, ignore it.
                            debug!(
                                msg_type = "NetworkResponse",
                                sender = %sender,
                                "Duplicate working ACK ignored"
                            );
                            return Ok(());
                        }
                        self.acked = true;

                        if let Ok(retry) = ctx
                            .get_child::<RetryActor<RetryNetwork>>("retry")
                            .await
                            && let Err(e) = retry.tell(RetryMessage::End).await
                        {
                            warn!(
                                msg_type = "NetworkResponse",
                                error = %e,
                                "Failed to end retry actor after working ACK"
                            );
                        }

                        if let Err(e) = ctx.schedule_once(
                            RESULT_DEADLINE,
                            CompileCoordinatorMessage::ResultDeadline,
                        ) {
                            error!(
                                msg_type = "NetworkResponse",
                                error = %e,
                                "Failed to schedule the result deadline"
                            );
                            return Err(crash_system(ctx, e).await);
                        }

                        debug!(
                            msg_type = "NetworkResponse",
                            request_id = %request_id,
                            version = version,
                            sender = %sender,
                            "Working ACK received, retry stopped, awaiting result"
                        );

                        return Ok(());
                    }

                    if let CompilationRes::Response {
                        result,
                        result_hash,
                        result_hash_signature,
                    } = &*compilation_res
                        && let Err(e) = self.verify_result_response(
                            result,
                            result_hash,
                            result_hash_signature,
                        )
                    {
                        // Unverifiable result (bad hash or signature):
                        // same failover as a timeout — the phase drops
                        // and replaces the compiler at once.
                        warn!(
                            msg_type = "NetworkResponse",
                            error = %e,
                            sender = %sender,
                            "Unverifiable compilation result, dropping compiler"
                        );
                        self.notify_timeout(ctx).await;
                        ctx.stop(None).await;
                        return Ok(());
                    }

                    // Compilation actor.
                    match ctx.get_parent::<Compilation>().await {
                        Ok(compilation_actor) => {
                            if let Err(e) = compilation_actor
                                .tell(CompilationMessage::Response {
                                    compilation_res: *compilation_res,
                                    sender: self.node_key.clone(),
                                })
                                .await
                            {
                                // The phase was torn down while this
                                // response was in flight: it is moot,
                                // drop it.
                                debug!(
                                    msg_type = "NetworkResponse",
                                    error = %e,
                                    "Compilation actor gone, dropping response"
                                );
                            }
                        }
                        Err(e) => {
                            // Same teardown race: the phase actor is gone.
                            debug!(
                                msg_type = "NetworkResponse",
                                error = %e,
                                path = %ctx.path().parent(),
                                "Compilation actor not found, dropping response"
                            );
                        }
                    }

                    'retry: {
                        let Ok(retry) = ctx
                            .get_child::<RetryActor<RetryNetwork>>("retry")
                            .await
                        else {
                            debug!(
                                msg_type = "NetworkResponse",
                                sender = %sender,
                                "Retry actor not found while closing compilation coordinator"
                            );
                            // It does not matter here: stopping this
                            // actor stops the child.
                            break 'retry;
                        };

                        if let Err(e) = retry.tell(RetryMessage::End).await {
                            warn!(
                                msg_type = "NetworkResponse",
                                error = %e,
                                "Failed to end retry actor"
                            );
                            // It does not matter here: stopping this
                            // actor stops the child.
                            break 'retry;
                        };
                    }

                    debug!(
                        msg_type = "NetworkResponse",
                        request_id = %self.request_id,
                        version = self.version,
                        sender = %sender,
                        "Compilation response processed successfully"
                    );

                    ctx.stop(None).await;
                } else {
                    warn!(
                        msg_type = "NetworkResponse",
                        expected_request_id = %self.request_id,
                        expected_version = self.version,
                        received_request_id = %request_id,
                        received_version = version,
                        "Response with mismatched request id or version"
                    );
                }
            }
        }

        Ok(())
    }
}

#[cfg(all(test, feature = "test"))]
mod tests {
    use super::*;

    use crate::{
        governance::{data::GovernanceData, model::Quorum},
        helpers::network::test_faults::TestFaultRegistry,
        system::tests::create_system,
    };

    use ave_common::{
        ValueWrapper,
        identity::{DigestIdentifier, KeyPair, keys::Ed25519Signer},
        request::{EventRequest, FactRequest},
    };

    use ave_actors::{ActorRef, SystemRef};
    use ave_network::CommandHelper;

    use std::{
        collections::{BTreeSet, HashSet},
        sync::Mutex,
    };

    use tempfile::TempDir;
    use test_log::test;
    use tokio::{
        sync::mpsc,
        task::JoinHandle,
        time::{sleep, timeout},
    };

    /// A compilation phase actor (root, no request manager) with a
    /// single remote compiler: creating the phase spawns the coordinator
    /// child, whose retry cycle sends the request over the network.
    struct PhaseHarness {
        system: SystemRef,
        runner: JoinHandle<()>,
        // Held for ownership only: dropping it would delete the
        // tempdirs early.
        _dirs: Vec<TempDir>,
        rx: mpsc::Receiver<CommandHelper<NetworkMessage>>,
        coordinator: ActorRef<CompileCoordinator>,
        coordinator_path: ActorPath,
        retry_path: ActorPath,
        request_id: DigestIdentifier,
        version: u64,
        compiler_key: PublicKey,
    }

    async fn setup() -> PhaseHarness {
        let (system, runner, dirs) = create_system().await;

        let (command_sender, mut command_receiver) = mpsc::channel(16);
        let network = Arc::new(NetworkSender::new(
            command_sender.clone(),
            Arc::new(Mutex::new(TestFaultRegistry::new(command_sender))),
        ));

        let our_keys = KeyPair::Ed25519(Ed25519Signer::generate().unwrap());
        let compiler_keys =
            KeyPair::Ed25519(Ed25519Signer::generate().unwrap());
        let compiler_key = compiler_keys.public_key();
        let governance_id = DigestIdentifier::default();

        let event_request = EventRequest::Fact(FactRequest {
            subject_id: governance_id.clone(),
            payload: ValueWrapper(serde_json::json!({})),
            viewpoints: BTreeSet::new(),
        });
        let signed_event = Signed::new(event_request, &our_keys).unwrap();
        let signed_req = Signed::new(
            CompilationReq {
                event_request: signed_event,
                governance_id,
                sn: 0,
                gov_version: 0,
            },
            &our_keys,
        )
        .unwrap();

        let compilation = system
            .create_root_actor(
                "compilation",
                Compilation::new(
                    Arc::new(our_keys.public_key()),
                    signed_req,
                    Quorum::Majority,
                    GovernanceData::default(),
                    HashAlgorithm::Blake3,
                    network,
                ),
            )
            .await
            .unwrap();

        let request_id =
            hash_borsh(&*HashAlgorithm::Blake3.hasher(), &"request-1").unwrap();
        let version = 7;
        compilation
            .tell(CompilationMessage::Create {
                request_id: request_id.clone(),
                version,
                signers: HashSet::from([compiler_key.clone()]),
            })
            .await
            .unwrap();

        // The first send of the retry cycle confirms that the
        // coordinator child and its retry actor are up.
        let command = timeout(Duration::from_secs(5), command_receiver.recv())
            .await
            .expect("the compilation request was not sent")
            .expect("network channel closed");
        let CommandHelper::SendMessage { message, .. } = command else {
            panic!("expected an outbound send command");
        };
        assert!(
            matches!(message.message, ActorMessage::CompilationReq { .. }),
            "the coordinator must send the compilation request"
        );
        assert_eq!(message.info.receiver, compiler_key);
        assert_eq!(message.info.request_id, request_id.to_string());
        assert_eq!(message.info.version, version);

        let coordinator_path =
            ActorPath::from(format!("/user/compilation/{}", compiler_key));
        let retry_path = ActorPath::from(format!("{}/retry", coordinator_path));
        let coordinator = system
            .get_actor::<CompileCoordinator>(&coordinator_path)
            .await
            .unwrap();
        system
            .get_actor::<RetryActor<RetryNetwork>>(&retry_path)
            .await
            .expect("the retry actor must exist before the ACK");

        PhaseHarness {
            system,
            runner,
            _dirs: dirs,
            rx: command_receiver,
            coordinator,
            coordinator_path,
            retry_path,
            request_id,
            version,
            compiler_key,
        }
    }

    /// The working ACK cancels the request retry and the coordinator
    /// keeps awaiting the final result under the result deadline: no
    /// timeout is reported, the ACK is never forwarded to the phase
    /// actor, and a duplicate ACK is ignored.
    #[test(tokio::test)]
    async fn working_ack_cancels_retry_and_is_never_counted() {
        let PhaseHarness {
            system,
            runner,
            _dirs: _,
            rx: mut command_receiver,
            coordinator,
            coordinator_path,
            retry_path,
            request_id,
            version,
            compiler_key,
        } = setup().await;

        let working = || CompileCoordinatorMessage::NetworkResponse {
            compilation_res: Box::new(CompilationRes::Working),
            request_id: request_id.to_string(),
            version,
            sender: compiler_key.clone(),
        };

        coordinator.tell(working()).await.unwrap();

        // The request retry is cancelled: no more resends.
        timeout(Duration::from_secs(5), async {
            loop {
                if system
                    .get_actor::<RetryActor<RetryNetwork>>(&retry_path)
                    .await
                    .is_err()
                {
                    break;
                }
                sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the request retry was not cancelled after the ACK");

        // The coordinator keeps awaiting the final result: it stays
        // alive and reports no timeout to the phase actor.
        sleep(Duration::from_millis(300)).await;
        assert!(
            system
                .get_actor::<CompileCoordinator>(&coordinator_path)
                .await
                .is_ok(),
            "the coordinator must await the final result after the ACK"
        );
        assert!(command_receiver.try_recv().is_err());

        // A duplicate ACK (a request retry was already in flight when
        // the first one arrived) is ignored: same coordinator, no
        // resend, no timeout.
        coordinator.tell(working()).await.unwrap();
        sleep(Duration::from_millis(200)).await;
        assert!(
            system
                .get_actor::<CompileCoordinator>(&coordinator_path)
                .await
                .is_ok(),
            "a duplicate working ACK must be ignored"
        );
        assert!(command_receiver.try_recv().is_err());

        // The ACKs were never forwarded nor counted: the compiler is
        // still registered, so the result deadline reports its timeout
        // to the phase actor — which counts it and, with an empty
        // compiler set, must reboot the request. A parentless phase
        // actor cannot reboot, so the counted timeout brings the system
        // down; an uncounted one would not.
        coordinator
            .tell(CompileCoordinatorMessage::ResultDeadline)
            .await
            .unwrap();
        timeout(Duration::from_secs(5), coordinator.closed())
            .await
            .expect("the coordinator did not stop after the deadline");
        timeout(Duration::from_secs(15), runner)
            .await
            .expect("the phase actor did not count the deadline timeout")
            .unwrap();
    }

    /// The result deadline acts as a normal timeout — the same failover
    /// as an exhausted ACK retry (both arms notify the phase actor with
    /// `CompilationRes::TimeOut` and stop the coordinator).
    #[test(tokio::test)]
    async fn result_deadline_reports_timeout_and_stops() {
        let PhaseHarness {
            runner, coordinator, ..
        } = setup().await;

        coordinator
            .tell(CompileCoordinatorMessage::ResultDeadline)
            .await
            .unwrap();

        timeout(Duration::from_secs(5), coordinator.closed())
            .await
            .expect("the coordinator did not stop after the deadline");
        timeout(Duration::from_secs(15), runner)
            .await
            .expect("the phase actor did not receive the timeout")
            .unwrap();
    }
}
