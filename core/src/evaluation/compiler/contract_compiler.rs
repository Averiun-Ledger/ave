use std::collections::{BTreeSet, HashSet, VecDeque};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Handler, Message,
    NotPersistentActor, TimerKey,
};
use serde_json::Value;
use tracing::{Span, debug, error, info_span, warn};

use ave_common::SchemaType;
use ave_common::identity::{
    DigestIdentifier, HashAlgorithm, PublicKey, hash_borsh,
};
use ave_network::ComunicateInfo;

use super::{
    CompilerResponse, CompilerSupport, SERVING_CACHE_TTL, ServingCacheEntry,
    error::CompilerError, is_local_fatal_compiler_error,
};
use crate::compilation::artifact::{
    ArtifactData, ArtifactFetchResult, ArtifactProbeResult,
};
use crate::governance::contract_register::{
    ContractRegister, ContractRegisterMessage, ContractRegisterResponse,
};
use crate::governance::{Governance, GovernanceMessage};
use crate::helpers::network::{
    ActorMessage, NetworkMessage, service::NetworkSender,
};
use crate::metrics::try_core_metrics;
use crate::model::common::{
    GovVersionSync, crash_system, gov_version_sync, take_random_signers,
};
use crate::sink::retry_delay_ms;

/// Response timeout of a single artifact request attempt.
#[cfg(any(test, feature = "test"))]
const FETCH_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);
/// Response timeout of a single artifact request attempt.
#[cfg(not(any(test, feature = "test")))]
const FETCH_RESPONSE_TIMEOUT: Duration = Duration::from_secs(10);

/// Response timeout of a light availability probe batch: the probe
/// only asks who can serve, slow peers are simply skipped.
#[cfg(any(test, feature = "test"))]
const PROBE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(2);
/// Response timeout of a light availability probe batch: the probe
/// only asks who can serve, slow peers are simply skipped.
#[cfg(not(any(test, feature = "test")))]
const PROBE_RESPONSE_TIMEOUT: Duration = Duration::from_secs(5);

/// Peers probed at a time (the `take_random_signers` batch pattern of
/// the protocol rounds): after a contract change every evaluator needs
/// the artifact at once, and batching spreads the herd over the
/// compiler set instead of sweeping it.
const PROBE_BATCH_SIZE: usize = 3;

/// Total budget waiting for a busy batch to finish compiling before
/// moving to the next one. Very generous: compilations take seconds,
/// not minutes.
#[cfg(any(test, feature = "test"))]
const BUSY_TOTAL_BUDGET: Duration = Duration::from_secs(60);
/// Total budget waiting for a busy batch to finish compiling before
/// moving to the next one. Very generous: compilations take seconds,
/// not minutes.
#[cfg(not(any(test, feature = "test")))]
const BUSY_TOTAL_BUDGET: Duration = Duration::from_secs(180);

/// Wait between re-probes to the same busy batch, stepped: compilations
/// are not instant, give them room.
#[cfg(any(test, feature = "test"))]
fn busy_retry_delay(_attempt: usize) -> Duration {
    Duration::from_secs(1)
}
/// Wait between re-probes to the same busy batch, stepped: compilations
/// are not instant, give them room.
#[cfg(not(any(test, feature = "test")))]
fn busy_retry_delay(attempt: usize) -> Duration {
    match attempt {
        1..=5 => Duration::from_secs(3),
        6..=10 => Duration::from_secs(5),
        _ => Duration::from_secs(10),
    }
}

/// Timeoff between exhausted fetch cycles. Non-aggressive: the
/// artifact is needed for sure, so the cycle never gives up — the
/// timeoff is what keeps the retry cheap.
#[cfg(any(test, feature = "test"))]
const TIMEOFF_BASE_MS: u64 = 1_000;
/// Timeoff between exhausted fetch cycles. Non-aggressive: the
/// artifact is needed for sure, so the cycle never gives up — the
/// timeoff is what keeps the retry cheap.
#[cfg(not(any(test, feature = "test")))]
const TIMEOFF_BASE_MS: u64 = 5_000;

#[cfg(any(test, feature = "test"))]
const TIMEOFF_MAX_MS: u64 = 5_000;
#[cfg(not(any(test, feature = "test")))]
const TIMEOFF_MAX_MS: u64 = 60_000;

#[derive(Debug)]
pub struct ContractCompiler {
    contract: DigestIdentifier,
    hash: HashAlgorithm,
    our_key: Arc<PublicKey>,
    next_nonce: u64,
    /// This node's governance version and the artifact whitelists, kept
    /// in memory and refreshed by `Reconcile` — no per-operation lookups
    /// against the governance actor. The governance compilers are plan A
    /// fetch targets only (they compile their artifacts, they never
    /// request them); the evaluators of this schema (schema-level and
    /// tracker-schemas roles — namespaces only balance the load, the
    /// artifact bytes are the same for all) validate incoming requests
    /// when serving and are the plan B fetch targets.
    gov_version: u64,
    compilers: BTreeSet<PublicKey>,
    evaluators: BTreeSet<PublicKey>,
    /// While the governance applies an update (promoting and refreshing
    /// artifacts) nothing is served: between versions there is no good
    /// answer.
    serving_blocked: bool,
    /// The official artifact recently served to other nodes (plan B
    /// serving): same serving cache policy as the compile worker, but a
    /// single entry — this actor only serves its own schema. Cleared
    /// whenever the module is evicted (the artifact is changing).
    serving_cache: Option<ServingCacheEntry>,
    fetch: Option<FetchState>,
}

/// An in-flight artifact fetch: message-driven (no blocked ask awaiting
/// the network). Light probe batches discover who can serve at our
/// governance version, the bytes come from the first one that answered,
/// busy batches (compiling) are waited on with a stepped schedule, and
/// an exhausted cycle triggers a manual governance update and a
/// non-aggressive timeoff — the artifact is needed for sure, so the
/// cycle never gives up.
#[derive(Debug)]
struct FetchState {
    contract: String,
    contract_hash: DigestIdentifier,
    contract_name: String,
    initial_value: Value,
    contract_path: PathBuf,
    gov_id: DigestIdentifier,
    schema_id: SchemaType,
    /// Ledger anchor: the received bytes are verified against it.
    wasm_hash: DigestIdentifier,
    phase: FetchPhase,
    /// Nonce of the in-flight probe round or artifact request.
    nonce: u64,
    timer: Option<TimerKey>,
    started_at: Instant,
    /// Exhausted cycles so far: paces the timeoff backoff.
    cycles: usize,
}

/// A probe batch and everything it produced: who has not answered, who
/// can serve, who is busy compiling, and the candidates left for the
/// next batches.
#[derive(Debug, Default)]
struct ProbeRound {
    plan_b: bool,
    /// Batch members that have not answered yet.
    pending: HashSet<PublicKey>,
    /// Batch members that answered `CanServe`: the failover list.
    can_serve: VecDeque<PublicKey>,
    /// Batch members that answered `Busy` (compiling): re-probed after
    /// the stepped wait — after a contract change every compiler is
    /// busy at once, so moving to another batch is pointless.
    busy: HashSet<PublicKey>,
    /// Candidates not tried yet (the next batches).
    untried: Vec<PublicKey>,
    /// Peers whose fetch attempt already failed this round: never
    /// re-probed nor re-admitted as failover candidates.
    failed: HashSet<PublicKey>,
    /// Re-probes sent to the busy batch (steps the wait).
    busy_attempts: usize,
    /// When the busy waiting of this batch started (total budget).
    busy_started: Option<Instant>,
}

#[derive(Debug)]
enum FetchPhase {
    /// Light probes in flight: who can serve at our version?
    Probe(ProbeRound),
    /// Fetching the bytes from a peer that answered the probe.
    Fetch {
        round: ProbeRound,
        peer: PublicKey,
        /// Nonce of the probe round that found this peer: late answers
        /// still feed the round (failover, busy, pending).
        probe_nonce: u64,
    },
    /// Waiting to re-probe the same busy batch.
    BusyWait(ProbeRound),
    /// Waiting between cycles (non-aggressive timeoff).
    Timeoff,
}

impl ContractCompiler {
    pub fn new(hash: HashAlgorithm, our_key: Arc<PublicKey>) -> Self {
        Self {
            contract: DigestIdentifier::default(),
            hash,
            our_key,
            next_nonce: 0,
            gov_version: 0,
            compilers: BTreeSet::new(),
            evaluators: BTreeSet::new(),
            serving_blocked: false,
            serving_cache: None,
            fetch: None,
        }
    }

    fn register_path(ctx: &ActorContext<Self>) -> ActorPath {
        ActorPath::from(format!("{}/contract_register", ctx.path().parent()))
    }

    fn network<A>(
        ctx: &ActorContext<A>,
    ) -> Result<Arc<NetworkSender>, ActorError>
    where
        A: Actor,
    {
        ctx.system()
            .get_helper::<Arc<NetworkSender>>("network")
            .ok_or_else(|| ActorError::Helper {
                name: "network".to_owned(),
                reason: "Not found".to_owned(),
            })
    }

    fn cancel_fetch_timer(&mut self, ctx: &ActorContext<Self>) {
        if let Some(fetch) = &mut self.fetch
            && let Some(key) = fetch.timer.take()
        {
            ctx.cancel_timer(key);
        }
    }

    fn allocate_nonce(&mut self) -> u64 {
        let nonce = self.next_nonce;
        self.next_nonce += 1;
        nonce
    }

    /// Whether any evaluator can be asked for the artifact (plan B).
    fn has_evaluator_targets(&self) -> bool {
        self.evaluators.iter().any(|peer| peer != &*self.our_key)
    }

    /// The serving path of a peer for this fetch: compilers serve from
    /// the governance compile worker, evaluators (plan B) from the
    /// per-schema contract compiler.
    fn peer_path(fetch: &FetchState, plan_b: bool) -> String {
        if plan_b {
            format!(
                "/user/node/subject_manager/{}/{}_contract_compiler",
                fetch.gov_id, fetch.schema_id
            )
        } else {
            format!("/user/node/subject_manager/{}/compiler", fetch.gov_id)
        }
    }

    /// Starts a probe set (compilers, or the schema evaluators as plan
    /// B): candidates are batched at random and probed batch by batch.
    async fn start_probe_set(
        &mut self,
        ctx: &mut ActorContext<Self>,
        plan_b: bool,
    ) -> Result<(), ActorError> {
        let candidates: HashSet<PublicKey> = if plan_b {
            self.evaluators.clone()
        } else {
            self.compilers.clone()
        }
        .into_iter()
        .filter(|peer| peer != &*self.our_key)
        .collect();

        if candidates.is_empty() {
            // No one to ask in this set: plan B over the evaluators, or
            // an exhausted cycle (boxed — direct async recursion).
            if !plan_b && self.has_evaluator_targets() {
                return Box::pin(self.start_probe_set(ctx, true)).await;
            }
            return self.cycle_exhausted(ctx).await;
        }

        let (batch, untried) =
            take_random_signers(candidates, PROBE_BATCH_SIZE);
        self.probe_batch(
            ctx,
            ProbeRound {
                plan_b,
                pending: batch.into_iter().collect(),
                can_serve: VecDeque::new(),
                busy: HashSet::new(),
                untried: untried.into_iter().collect(),
                failed: HashSet::new(),
                busy_attempts: 0,
                busy_started: None,
            },
        )
        .await
    }

    /// Sends the probe to every member of the batch and arms the round
    /// timeout.
    async fn probe_batch(
        &mut self,
        ctx: &mut ActorContext<Self>,
        round: ProbeRound,
    ) -> Result<(), ActorError> {
        let Some((gov_id, schema_id, contract_name)) =
            self.fetch.as_ref().map(|fetch| {
                (
                    fetch.gov_id.clone(),
                    fetch.schema_id.clone(),
                    fetch.contract_name.clone(),
                )
            })
        else {
            return Ok(());
        };

        let plan_b = round.plan_b;
        let batch_size = round.pending.len();
        let nonce = self.allocate_nonce();
        let network = Self::network(ctx)?;
        for peer in &round.pending {
            let target_path = match self.fetch.as_ref() {
                Some(fetch) => Self::peer_path(fetch, plan_b),
                None => return Ok(()),
            };
            // A send failure would leave the probes half-sent with no
            // live timer: local infrastructure failure, fail loud.
            if let Err(e) = network
                .send_command(ave_network::CommandHelper::SendMessage {
                    message: NetworkMessage {
                        info: ComunicateInfo {
                            receiver: peer.clone(),
                            request_id: String::default(),
                            version: 0,
                            receiver_actor: target_path,
                        },
                        message: ActorMessage::ArtifactProbeReq {
                            subject_id: gov_id.clone(),
                            schema_id: schema_id.clone(),
                            gov_version: self.gov_version,
                            request_nonce: nonce,
                            receiver_actor: ctx.path().to_string(),
                        },
                    },
                })
                .await
            {
                return Err(crash_system(ctx, e).await);
            }
        }

        // One live timer per fetch: cancel the previous phase's timer
        // before arming the round timeout.
        self.cancel_fetch_timer(ctx);
        let key = match ctx.schedule_once(
            PROBE_RESPONSE_TIMEOUT,
            ContractCompilerMessage::ProbeTimeout {
                request_nonce: nonce,
            },
        ) {
            Ok(key) => key,
            Err(e) => return Err(crash_system(ctx, e).await),
        };

        let Some(fetch) = &mut self.fetch else {
            return Ok(());
        };
        fetch.nonce = nonce;
        fetch.timer = Some(key);
        fetch.phase = FetchPhase::Probe(round);

        debug!(
            msg_type = "Fetch",
            contract_name = %contract_name,
            plan_b,
            batch_size,
            "Artifact probe batch sent"
        );

        Ok(())
    }

    /// Re-probes the busy members of the batch after the stepped wait.
    async fn reprobe_busy(
        &mut self,
        ctx: &mut ActorContext<Self>,
        mut round: ProbeRound,
    ) -> Result<(), ActorError> {
        round.pending = std::mem::take(&mut round.busy);
        round.busy_attempts += 1;
        self.probe_batch(ctx, round).await
    }

    /// The probe round closed (timeout or every member answered):
    /// fetch from the first `CanServe`, wait for the busy ones, or move
    /// to the next batch.
    async fn resolve_probe_round(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let Some(fetch) = &mut self.fetch else {
            return Ok(());
        };
        let FetchPhase::Probe(round) = &mut fetch.phase else {
            return Ok(());
        };

        if let Some(peer) = round.can_serve.pop_front() {
            let round = std::mem::take(round);
            return self.start_fetch_from(ctx, round, peer).await;
        }

        if !round.busy.is_empty() {
            let round = std::mem::take(round);
            return self.wait_busy_batch(ctx, round).await;
        }

        let round = std::mem::take(round);
        self.next_batch(ctx, round).await
    }

    /// Resumes a probe round whose answers are still in flight, with a
    /// fresh timeout.
    async fn resume_probe(
        &mut self,
        ctx: &mut ActorContext<Self>,
        probe_nonce: u64,
        round: ProbeRound,
    ) -> Result<(), ActorError> {
        // One live timer per fetch: cancel the failed attempt's timer
        // before arming the resumed round timeout.
        self.cancel_fetch_timer(ctx);
        let key = match ctx.schedule_once(
            PROBE_RESPONSE_TIMEOUT,
            ContractCompilerMessage::ProbeTimeout {
                request_nonce: probe_nonce,
            },
        ) {
            Ok(key) => key,
            Err(e) => return Err(crash_system(ctx, e).await),
        };

        let Some(fetch) = &mut self.fetch else {
            return Ok(());
        };
        fetch.nonce = probe_nonce;
        fetch.timer = Some(key);
        fetch.phase = FetchPhase::Probe(round);

        Ok(())
    }

    /// Waits for a busy batch (stepped delay), or gives up on it when
    /// the total budget is spent.
    async fn wait_busy_batch(
        &mut self,
        ctx: &mut ActorContext<Self>,
        mut round: ProbeRound,
    ) -> Result<(), ActorError> {
        if round.busy_started.is_none() {
            round.busy_started = Some(Instant::now());
        }
        let budget_spent = round
            .busy_started
            .is_some_and(|started| started.elapsed() >= BUSY_TOTAL_BUDGET);
        if budget_spent {
            debug!(
                msg_type = "Fetch",
                "Busy batch budget exhausted, moving to the next batch"
            );
            return self.next_batch(ctx, round).await;
        }

        let delay = busy_retry_delay(round.busy_attempts + 1);
        let Some(nonce) = self.fetch.as_ref().map(|fetch| fetch.nonce)
        else {
            return Ok(());
        };
        // One live timer per fetch: cancel the probe round's timeout
        // before arming the busy wait.
        self.cancel_fetch_timer(ctx);
        let key = match ctx.schedule_once(
            delay,
            ContractCompilerMessage::BusyRetry {
                request_nonce: nonce,
            },
        ) {
            Ok(key) => key,
            Err(e) => return Err(crash_system(ctx, e).await),
        };
        let Some(fetch) = &mut self.fetch else {
            return Ok(());
        };
        fetch.timer = Some(key);
        fetch.phase = FetchPhase::BusyWait(round);

        debug!(
            msg_type = "Fetch",
            contract_name = %fetch.contract_name,
            delay_ms = delay.as_millis(),
            "Probe batch is busy compiling; re-probing after the wait"
        );

        Ok(())
    }

    /// Moves to the next batch of the set, or to the next phase when
    /// the set is exhausted.
    async fn next_batch(
        &mut self,
        ctx: &mut ActorContext<Self>,
        round: ProbeRound,
    ) -> Result<(), ActorError> {
        if round.untried.is_empty() {
            return self.advance_set(ctx, round.plan_b).await;
        }

        let untried: HashSet<PublicKey> = round.untried.into_iter().collect();
        let (batch, rest) = take_random_signers(untried, PROBE_BATCH_SIZE);
        self.probe_batch(
            ctx,
            ProbeRound {
                plan_b: round.plan_b,
                pending: batch.into_iter().collect(),
                can_serve: VecDeque::new(),
                busy: HashSet::new(),
                untried: rest.into_iter().collect(),
                failed: HashSet::new(),
                busy_attempts: 0,
                busy_started: None,
            },
        )
        .await
    }

    /// Moves to the next phase: plan B over the schema evaluators, or
    /// an exhausted cycle (manual governance update + timeoff).
    async fn advance_set(
        &mut self,
        ctx: &mut ActorContext<Self>,
        plan_b: bool,
    ) -> Result<(), ActorError> {
        if !plan_b && self.has_evaluator_targets() {
            return self.start_probe_set(ctx, true).await;
        }

        self.cycle_exhausted(ctx).await
    }

    /// Starts the artifact request to a peer that answered the probe,
    /// re-sending the current governance version in case it changed
    /// since the probe.
    async fn start_fetch_from(
        &mut self,
        ctx: &mut ActorContext<Self>,
        round: ProbeRound,
        peer: PublicKey,
    ) -> Result<(), ActorError> {
        let Some((gov_id, schema_id, contract_name)) =
            self.fetch.as_ref().map(|fetch| {
                (
                    fetch.gov_id.clone(),
                    fetch.schema_id.clone(),
                    fetch.contract_name.clone(),
                )
            })
        else {
            return Ok(());
        };

        let plan_b = round.plan_b;
        let nonce = self.allocate_nonce();
        let target_path = match self.fetch.as_ref() {
            Some(fetch) => Self::peer_path(fetch, plan_b),
            None => return Ok(()),
        };

        let network = Self::network(ctx)?;
        // A send failure would leave the fetch with no live timer:
        // local infrastructure failure, fail loud.
        if let Err(e) = network
            .send_command(ave_network::CommandHelper::SendMessage {
                message: NetworkMessage {
                    info: ComunicateInfo {
                        receiver: peer.clone(),
                        request_id: String::default(),
                        version: 0,
                        receiver_actor: target_path,
                    },
                    message: ActorMessage::ArtifactReq {
                        subject_id: gov_id,
                        schema_id,
                        gov_version: self.gov_version,
                        request_nonce: nonce,
                        receiver_actor: ctx.path().to_string(),
                    },
                },
            })
            .await
        {
            return Err(crash_system(ctx, e).await);
        }

        // One live timer per fetch: cancel the probe round's timeout
        // before arming the fetch timeout — a stale ProbeTimeout could
        // close a later resumed round reusing the same nonce.
        self.cancel_fetch_timer(ctx);
        let key = match ctx.schedule_once(
            FETCH_RESPONSE_TIMEOUT,
            ContractCompilerMessage::FetchTimeout {
                request_nonce: nonce,
            },
        ) {
            Ok(key) => key,
            Err(e) => return Err(crash_system(ctx, e).await),
        };

        let Some(fetch) = &mut self.fetch else {
            return Ok(());
        };
        let probe_nonce = fetch.nonce;
        fetch.nonce = nonce;
        fetch.timer = Some(key);
        fetch.phase = FetchPhase::Fetch {
            round,
            peer: peer.clone(),
            probe_nonce,
        };

        debug!(
            msg_type = "Fetch",
            contract_name = %contract_name,
            peer = %peer,
            plan_b,
            "Artifact request sent"
        );

        Ok(())
    }

    /// The current fetch attempt failed: failover peer, probe answers
    /// still in flight, the busy batch, the next batch, or an exhausted
    /// cycle. A burned peer is never re-probed nor re-admitted as a
    /// failover candidate for the rest of the round; a `Busy` answer
    /// mid-fetch is NOT a failure (the peer joined the busy set and is
    /// re-probed as such).
    async fn attempt_failed(
        &mut self,
        ctx: &mut ActorContext<Self>,
        error: Option<String>,
        burn_peer: bool,
    ) -> Result<(), ActorError> {
        let Some(fetch) = &mut self.fetch else {
            return Ok(());
        };

        if let Some(error) = error {
            warn!(
                msg_type = "Fetch",
                contract_name = %fetch.contract_name,
                error = %error,
                "Artifact fetch attempt failed, trying next option"
            );
        }

        let FetchPhase::Fetch {
            round, peer, probe_nonce,
        } = &mut fetch.phase
        else {
            return Ok(());
        };
        let probe_nonce = *probe_nonce;

        if burn_peer {
            round.pending.remove(peer);
            round.busy.remove(peer);
            round.can_serve.retain(|candidate| candidate != peer);
            round.failed.insert(peer.clone());
        }

        if let Some(peer) = round.can_serve.pop_front() {
            let round = std::mem::take(round);
            return self.start_fetch_from(ctx, round, peer).await;
        }

        // Probe answers still in flight: resume the round with a fresh
        // timeout instead of giving up.
        if !round.pending.is_empty() {
            let round = std::mem::take(round);
            return self.resume_probe(ctx, probe_nonce, round).await;
        }

        // Batch members compiling: wait for them.
        if !round.busy.is_empty() {
            let round = std::mem::take(round);
            return self.wait_busy_batch(ctx, round).await;
        }

        let round = std::mem::take(round);
        self.next_batch(ctx, round).await
    }

    /// Nobody could serve the artifact at our version. Maybe this node
    /// is so outdated that it is asking nodes that no longer serve it:
    /// force a manual governance update (the applied events re-trigger
    /// the fetch) and wait a non-aggressive timeoff before the next
    /// cycle. The artifact is needed for sure — the cycle never gives
    /// up.
    async fn cycle_exhausted(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        // The parent is expected to exist and accept messages: a failure
        // here is local infrastructure, fail loud.
        let governance = match ctx.get_parent::<Governance>().await {
            Ok(governance) => governance,
            Err(e) => return Err(crash_system(ctx, e).await),
        };
        if let Err(e) = governance.tell(GovernanceMessage::TriggerGovUpdate).await
        {
            return Err(crash_system(ctx, e).await);
        }

        let Some(fetch) = &mut self.fetch else {
            return Ok(());
        };
        fetch.phase = FetchPhase::Timeoff;
        fetch.cycles += 1;
        let cycles = fetch.cycles;
        let contract_name = fetch.contract_name.clone();
        let delay =
            retry_delay_ms(TIMEOFF_BASE_MS, TIMEOFF_MAX_MS, cycles, None);

        // One live timer per fetch: cancel the exhausted cycle's timer
        // before arming the timeoff.
        self.cancel_fetch_timer(ctx);
        let key = match ctx.schedule_once(
            Duration::from_millis(delay),
            ContractCompilerMessage::CycleStart { cycle: cycles },
        ) {
            Ok(key) => key,
            Err(e) => return Err(crash_system(ctx, e).await),
        };

        let Some(fetch) = &mut self.fetch else {
            return Ok(());
        };
        fetch.timer = Some(key);

        debug!(
            msg_type = "Fetch",
            contract_name = %contract_name,
            cycles,
            delay_ms = delay,
            "Fetch cycle exhausted; governance update triggered, next cycle after timeoff"
        );

        Ok(())
    }

    /// Drops the in-memory module of the contract: serving evaluations
    /// with a stale contract would diverge from the network.
    async fn evict_module(
        ctx: &ActorContext<Self>,
        contract_name: &str,
    ) -> Result<(), ActorError> {
        let contracts = CompilerSupport::contracts_helper(ctx).await?;
        contracts.write().await.remove(contract_name);
        Ok(())
    }

    /// Serves the official artifact to another node (plan B), from the
    /// serving cache while the entry is fresh and from disk otherwise —
    /// filling the cache and scheduling its expiry on a miss. Same
    /// policy as the compile worker: the cache exists for the fetch
    /// burst after a contract change and must not live forever.
    async fn serve_artifact(
        &mut self,
        ctx: &mut ActorContext<Self>,
        contract_name: &str,
    ) -> Result<Option<ArtifactData>, ActorError> {
        if let Some(entry) = &self.serving_cache
            && entry.filled_at.elapsed() < SERVING_CACHE_TTL
        {
            return Ok(Some(entry.artifact.clone()));
        }

        let Some(artifact) = CompilerSupport::serve_official_artifact(
            ctx,
            contract_name,
            &Self::register_path(ctx),
        )
        .await
        else {
            return Ok(None);
        };

        let filled_at = Instant::now();
        // The expiry is scheduled before filling: a scheduling failure
        // leaves no entry behind, so the RAM is never held forever.
        ctx.schedule_once(
            SERVING_CACHE_TTL,
            ContractCompilerMessage::EvictServingCache { filled_at },
        )?;

        self.serving_cache = Some(ServingCacheEntry {
            artifact: artifact.clone(),
            filled_at,
        });

        Ok(Some(artifact))
    }

    /// Terminal handling of a fetch error: fatal local problems (disk,
    /// register, helpers, engine) bring the node down controlled, like
    /// the compile path; anything else ends the fetch — the next
    /// governance event or restart tries again.
    async fn fetch_failed(
        &mut self,
        ctx: &mut ActorContext<Self>,
        error: CompilerError,
    ) -> Result<(), ActorError> {
        if is_local_fatal_compiler_error(&error) {
            return Err(crash_system(
                ctx,
                ActorError::FunctionalCritical {
                    description: format!(
                        "Can not register fetched contract artifact: {}",
                        error
                    ),
                },
            )
            .await);
        }

        let contract_name =
            self.fetch.as_ref().map(|fetch| fetch.contract_name.clone());
        error!(
            msg_type = "Fetch",
            error = %error,
            "Contract artifact fetch failed"
        );
        self.fetch = None;
        if let Some(contract_name) = contract_name {
            Self::evict_module(ctx, &contract_name).await?;
            self.serving_cache = None;
        }
        Ok(())
    }

    /// Whitelist and version negotiation of an incoming artifact
    /// probe/request, in the `EvaluationSchema` order: legitimate
    /// requester first (silent reject otherwise), then the blocked
    /// update window, then the governance version.
    fn artifact_gate(
        &self,
        ctx: &ActorContext<Self>,
        msg_type: &'static str,
        subject_id: &DigestIdentifier,
        schema_id: &SchemaType,
        gov_version: u64,
        sender: &PublicKey,
    ) -> ArtifactGate {
        if subject_id.to_string() != ctx.path().parent().key() {
            warn!(
                msg_type,
                sender = %sender,
                received_governance_id = %subject_id,
                "Invalid governance_id in artifact request"
            );
            return ArtifactGate::Reject;
        }

        if ctx.path().key() != format!("{}_contract_compiler", schema_id) {
            warn!(
                msg_type,
                sender = %sender,
                schema_id = ?schema_id,
                "Invalid schema_id in artifact request"
            );
            return ArtifactGate::Reject;
        }

        // Only evaluators of the schema may request artifacts:
        // compilers compile their artifacts locally and never fetch —
        // even a compiler is rejected.
        if !self.evaluators.contains(sender) {
            warn!(
                msg_type,
                sender = %sender,
                "Artifact request from a node that is not an evaluator of the schema"
            );
            return ArtifactGate::Reject;
        }

        // Updating our own artifacts: after a contract change every
        // compiler is busy at once — tell the requester to wait for us
        // instead of pointlessly moving to another compiler.
        if self.serving_blocked {
            return ArtifactGate::Busy;
        }

        match gov_version_sync(self.gov_version, gov_version) {
            // This node is behind the request's governance version and
            // can not have the artifact: try another peer.
            GovVersionSync::NodeBehind => ArtifactGate::NotServed,
            // The requester is behind: it must sync and retry.
            GovVersionSync::RequesterBehind => ArtifactGate::Outdated,
            GovVersionSync::Current => ArtifactGate::Allowed,
        }
    }

    async fn send_artifact_message(
        &self,
        ctx: &mut ActorContext<Self>,
        msg_type: &'static str,
        info: ComunicateInfo,
        sender: PublicKey,
        receiver_actor: String,
        message: ActorMessage,
    ) -> Result<(), ActorError> {
        let new_info = ComunicateInfo {
            receiver: sender,
            request_id: info.request_id.clone(),
            version: info.version,
            receiver_actor,
        };

        let network = Self::network(ctx)?;
        if let Err(e) = network
            .send_command(ave_network::CommandHelper::SendMessage {
                message: NetworkMessage {
                    info: new_info,
                    message,
                },
            })
            .await
        {
            error!(
                msg_type,
                error = %e,
                "Failed to send artifact response to network"
            );
            return Err(crash_system(ctx, e).await);
        }

        Ok(())
    }
}

/// Gate of an incoming artifact probe/request (see
/// `ContractCompiler::artifact_gate`).
enum ArtifactGate {
    /// Whitelist and version negotiation passed: the request can be
    /// served.
    Allowed,
    /// Answer `NotServed`: this node is itself behind — the requester
    /// tries another peer.
    NotServed,
    /// Answer `Busy`: this node is applying an update — the requester
    /// waits and retries us, every compiler is busy at once.
    Busy,
    /// Answer `Outdated`: the requester is behind and must sync.
    Outdated,
    /// Silent reject (bad governance or schema, or non-whitelisted
    /// sender), like the `EvaluationSchema` rejects.
    Reject,
}

#[derive(Debug, Clone)]
pub enum ContractCompilerAction {
    Compile {
        contract: String,
        contract_name: String,
        initial_value: Value,
        contract_path: PathBuf,
    },
    /// Fetches the official artifact from the network instead of
    /// compiling: this node evaluates the schema but has no compiler
    /// role. The received bytes are verified against the compilation
    /// evidence anchored in this node's own ledger.
    Fetch {
        contract: String,
        contract_name: String,
        initial_value: Value,
        contract_path: PathBuf,
        gov_id: DigestIdentifier,
        schema_id: SchemaType,
    },
}

#[derive(Debug, Clone)]
pub enum ContractCompilerMessage {
    /// Applies the governance snapshot used by this actor, then prepares
    /// the schema from that same snapshot.
    Reconcile {
        gov_version: u64,
        compilers: BTreeSet<PublicKey>,
        evaluators: BTreeSet<PublicKey>,
        action: ContractCompilerAction,
    },
    /// The governance is applying an update (promoting and refreshing
    /// artifacts): serving is blocked until it finishes — between
    /// versions there is no good answer.
    ServingBlocked {
        blocked: bool,
    },
    /// Light availability probe from another node (plan B serving).
    ArtifactProbeRequest {
        subject_id: DigestIdentifier,
        schema_id: SchemaType,
        gov_version: u64,
        request_nonce: u64,
        info: ComunicateInfo,
        sender: PublicKey,
        receiver_actor: String,
    },
    ArtifactProbeResponse {
        result: ArtifactProbeResult,
        request_nonce: u64,
        sender: PublicKey,
    },
    /// Another node asks for the official artifact of the contract
    /// (plan B serving).
    ArtifactRequest {
        subject_id: DigestIdentifier,
        schema_id: SchemaType,
        gov_version: u64,
        request_nonce: u64,
        info: ComunicateInfo,
        sender: PublicKey,
        receiver_actor: String,
    },
    ArtifactResponse {
        result: ArtifactFetchResult,
        request_nonce: u64,
        sender: PublicKey,
    },
    ProbeTimeout {
        request_nonce: u64,
    },
    FetchTimeout {
        request_nonce: u64,
    },
    /// The stepped wait for a busy batch expired: re-probe it (or move
    /// to the next batch if the total budget is spent).
    BusyRetry {
        request_nonce: u64,
    },
    /// The timeoff of an exhausted cycle expired: start the next one.
    CycleStart {
        cycle: usize,
    },
    /// Expiry of the serving cache entry. Guarded by `filled_at`: a
    /// late eviction of an entry that was already refilled is moot.
    EvictServingCache {
        filled_at: Instant,
    },
}

impl Message for ContractCompilerMessage {}

impl NotPersistentActor for ContractCompiler {}

#[async_trait]
impl Actor for ContractCompiler {
    type Event = ();
    type Message = ContractCompilerMessage;
    type Response = CompilerResponse;
    type SinkEvent = ();
    type ChildError = ActorError;
    type ChildFault = ActorError;

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
        _: ActorPath,
        msg: ContractCompilerMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<CompilerResponse, ActorError> {
        match msg {
            ContractCompilerMessage::Reconcile {
                gov_version,
                compilers,
                evaluators,
                action,
            } => {
                let whitelists_changed =
                    self.compilers != compilers || self.evaluators != evaluators;
                self.gov_version = gov_version;
                self.compilers = compilers;
                self.evaluators = evaluators;

                match action {
                    ContractCompilerAction::Compile {
                        contract,
                        contract_name,
                        initial_value,
                        contract_path,
                    } => {
                        // A local compiler must not let an obsolete fetch
                        // register an artifact after taking over the schema.
                        self.cancel_fetch_timer(ctx);
                        self.fetch = None;
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
                            // The contract changed: the cached module is stale,
                            // evict it before recompiling — evaluating with it
                            // would diverge from the network (same policy as
                            // the fetch path).
                            Self::evict_module(ctx, &contract_name).await?;
                            // The artifact itself is changing too: nothing
                            // cached for serving may survive.
                            self.serving_cache = None;

                            let register_path = Self::register_path(ctx);
                            let (module, metadata) =
                                match CompilerSupport::compile_or_load_registered(
                                    self.hash,
                                    ctx,
                                    &contract_name,
                                    &contract,
                                    &contract_path,
                                    initial_value,
                                    &register_path,
                                    None,
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
                    ContractCompilerAction::Fetch {
                        contract,
                        contract_name,
                        initial_value,
                        contract_path,
                        gov_id,
                        schema_id,
                    } => {
                        let contract_hash =
                            match hash_borsh(&*self.hash.hasher(), &contract) {
                                Ok(hash) => hash,
                                Err(e) => {
                                    error!(
                                        msg_type = "Fetch",
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

                        // Already obtained: an unrelated governance event
                        // must not reset anything.
                        if contract_hash == self.contract {
                            debug!(
                                msg_type = "Fetch",
                                contract_name = %contract_name,
                                "Contract already available, skipping"
                            );
                            return Ok(CompilerResponse::Ok);
                        }

                        // In-flight fetch of the same contract: an
                        // unrelated governance event must not reset it.
                        // A whitelist change only matters when it drops
                        // peers this fetch is using (probing, waiting on
                        // or downloading from); then re-probe with the
                        // live sets, keeping the fetch (contract, anchor,
                        // cycle backoff). Probes and requests always
                        // carry the current governance version.
                        if self.fetch.as_ref().is_some_and(|fetch| {
                            fetch.contract_hash == contract_hash
                        }) {
                            let fetch_peers_dropped = whitelists_changed
                                && self.fetch.as_ref().is_some_and(|fetch| {
                                    match &fetch.phase {
                                        FetchPhase::Fetch {
                                            round, peer, ..
                                        } => {
                                            let live = if round.plan_b {
                                                &self.evaluators
                                            } else {
                                                &self.compilers
                                            };
                                            !live.contains(peer)
                                        }
                                        FetchPhase::Probe(round)
                                        | FetchPhase::BusyWait(round) => {
                                            let live = if round.plan_b {
                                                &self.evaluators
                                            } else {
                                                &self.compilers
                                            };
                                            round
                                                .pending
                                                .iter()
                                                .chain(round.busy.iter())
                                                .chain(round.can_serve.iter())
                                                .chain(round.untried.iter())
                                                .any(|peer| {
                                                    !live.contains(peer)
                                                })
                                        }
                                        // The next cycle re-reads the
                                        // live sets anyway.
                                        FetchPhase::Timeoff => false,
                                    }
                                });

                            if fetch_peers_dropped {
                                debug!(
                                    msg_type = "Fetch",
                                    contract_name = %contract_name,
                                    "Fetch peers left the whitelist, re-probing with the live sets"
                                );
                                self.cancel_fetch_timer(ctx);
                                self.start_probe_set(ctx, false).await?;
                            } else {
                                debug!(
                                    msg_type = "Fetch",
                                    contract_name = %contract_name,
                                    "Contract already being fetched, skipping"
                                );
                            }
                            return Ok(CompilerResponse::Ok);
                        }

                        // The contract changed (or was never loaded): the cached
                        // module is stale, evict it before fetching — evaluating
                        // with it would diverge from the network.
                        Self::evict_module(ctx, &contract_name).await?;
                        // The artifact itself is changing too: nothing cached
                        // for serving may survive.
                        self.serving_cache = None;
                        self.cancel_fetch_timer(ctx);
                        self.fetch = None;

                        let register_path = Self::register_path(ctx);

                        // The ledger anchor is the authority for local and fetched
                        // bytes alike. Without it, this node cannot know what is
                        // safe to execute or request.
                        let register = match ctx
                            .system()
                            .get_actor::<ContractRegister>(&register_path)
                            .await
                        {
                            Ok(register) => register,
                            Err(error) => {
                                return Err(crash_system(
                                    ctx,
                                    ActorError::FunctionalCritical {
                                        description: format!(
                                            "Can not access contract register for anchor: {}",
                                            error
                                        ),
                                    },
                                )
                                .await);
                            }
                        };
                        let wasm_hash = match register
                            .ask(ContractRegisterMessage::GetAnchor {
                                contract_name: contract_name.clone(),
                            })
                            .await
                        {
                            Ok(ContractRegisterResponse::Anchor(Some(anchor))) => anchor,
                            Ok(_) => {
                                return Err(crash_system(
                                    ctx,
                                    ActorError::FunctionalCritical {
                                        description: format!(
                                            "No ledger anchor for contract artifact {}",
                                            contract_name
                                        ),
                                    },
                                )
                                .await);
                            }
                            Err(error) => {
                                return Err(crash_system(
                                    ctx,
                                    ActorError::FunctionalCritical {
                                        description: format!(
                                            "Can not read contract anchor: {}",
                                            error
                                        ),
                                    },
                                )
                                .await);
                            }
                        };

                        // Local first: the artifact may already be on disk.
                        let manifest = ave_compiler::compilation_toml();
                        let manifest_hash = hash_borsh(&*self.hash.hasher(), &manifest);
                        let manifest_hash = match manifest_hash {
                            Ok(manifest_hash) => manifest_hash,
                            Err(e) => {
                                return self
                                    .fetch_failed(
                                        ctx,
                                        CompilerError::SerializationError {
                                            context: "contract manifest hash",
                                            details: e.to_string(),
                                        },
                                    )
                                    .await
                                    .map(|()| CompilerResponse::Ok);
                            }
                        };
                        let contract_runtime =
                            match CompilerSupport::contract_runtime(ctx).await {
                                Ok(contract_runtime) => contract_runtime,
                                Err(error) => {
                                    return self
                                        .fetch_failed(ctx, error)
                                        .await
                                        .map(|()| CompilerResponse::Ok);
                                }
                            };
                        let engine_fingerprint = match contract_runtime
                            .engine_fingerprint(self.hash)
                        {
                            Ok(engine_fingerprint) => engine_fingerprint,
                            Err(e) => {
                                return self
                                    .fetch_failed(
                                        ctx,
                                        ave_compiler::map_runtime_error_to_compiler_error(
                                            e,
                                        ),
                                    )
                                    .await
                                    .map(|()| CompilerResponse::Ok);
                            }
                        };

                        match CompilerSupport::load_registered_artifact(
                            self.hash,
                            ctx,
                            &contract_name,
                            &contract_path,
                            &initial_value,
                            &register_path,
                            &contract_hash,
                            &manifest_hash,
                            &engine_fingerprint,
                            None,
                            Some(&wasm_hash),
                        )
                        .await
                        {
                            Ok(Some((module, metadata, _))) => {
                                let contracts =
                                    CompilerSupport::contracts_helper(ctx).await?;
                                contracts
                                    .write()
                                    .await
                                    .insert(contract_name.clone(), module);
                                self.contract = metadata.contract_hash.clone();
                                debug!(
                                    msg_type = "Fetch",
                                    contract_name = %contract_name,
                                    "Contract artifact loaded from local disk"
                                );
                                return Ok(CompilerResponse::Ok);
                            }
                            Ok(None) => {}
                            Err(error) => {
                                self.fetch_failed(ctx, error).await?;
                                return Ok(CompilerResponse::Ok);
                            }
                        }

                        self.fetch = Some(FetchState {
                            contract,
                            contract_hash,
                            contract_name,
                            initial_value,
                            contract_path,
                            gov_id,
                            schema_id,
                            wasm_hash,
                            phase: FetchPhase::Timeoff,
                            nonce: 0,
                            timer: None,
                            started_at: Instant::now(),
                            cycles: 0,
                        });

                        self.start_probe_set(ctx, false).await?;

                        Ok(CompilerResponse::Ok)
                    }
                }
            }
            ContractCompilerMessage::ServingBlocked { blocked } => {
                self.serving_blocked = blocked;

                Ok(CompilerResponse::Ok)
            }
            ContractCompilerMessage::EvictServingCache { filled_at } => {
                // Guarded: a late eviction must not drop an entry that
                // was already refilled.
                if self
                    .serving_cache
                    .as_ref()
                    .is_some_and(|entry| entry.filled_at == filled_at)
                {
                    self.serving_cache = None;
                }

                Ok(CompilerResponse::Ok)
            }
            ContractCompilerMessage::ArtifactProbeRequest {
                subject_id,
                schema_id,
                gov_version,
                request_nonce,
                info,
                sender,
                receiver_actor,
            } => {
                let result = match self.artifact_gate(
                    ctx,
                    "ArtifactProbeRequest",
                    &subject_id,
                    &schema_id,
                    gov_version,
                    &sender,
                ) {
                    ArtifactGate::Reject => return Ok(CompilerResponse::Ok),
                    ArtifactGate::NotServed => ArtifactProbeResult::NotServed,
                    ArtifactGate::Busy => ArtifactProbeResult::Busy,
                    ArtifactGate::Outdated => ArtifactProbeResult::Outdated {
                        gov_version: self.gov_version,
                    },
                    ArtifactGate::Allowed => {
                        let contract_name =
                            format!("{}_{}", subject_id, schema_id);
                        if CompilerSupport::has_official_artifact(
                            ctx,
                            &contract_name,
                            &Self::register_path(ctx),
                        )
                        .await
                        {
                            ArtifactProbeResult::CanServe
                        } else {
                            ArtifactProbeResult::NotServed
                        }
                    }
                };

                self.send_artifact_message(
                    ctx,
                    "ArtifactProbeRequest",
                    info,
                    sender,
                    receiver_actor,
                    ActorMessage::ArtifactProbeRes {
                        request_nonce,
                        result,
                    },
                )
                .await?;

                Ok(CompilerResponse::Ok)
            }
            ContractCompilerMessage::ArtifactProbeResponse {
                result,
                request_nonce,
                sender,
            } => {
                // Probe round in flight.
                let in_probe_round = self.fetch.as_ref().is_some_and(|fetch| {
                    fetch.nonce == request_nonce
                        && matches!(fetch.phase, FetchPhase::Probe { .. })
                });

                if in_probe_round {
                    match result {
                        ArtifactProbeResult::CanServe => {
                            // First answer wins: fetch the bytes from
                            // this peer; the rest of the round keeps
                            // feeding the failover and busy lists.
                            let Some(fetch) = &mut self.fetch else {
                                return Ok(CompilerResponse::Ok);
                            };
                            let FetchPhase::Probe(round) = &mut fetch.phase
                            else {
                                return Ok(CompilerResponse::Ok);
                            };
                            // The chosen peer is being fetched now: it no
                            // longer counts as a pending answer.
                            round.pending.remove(&sender);
                            let round = std::mem::take(round);
                            self.start_fetch_from(ctx, round, sender).await?;
                        }
                        ArtifactProbeResult::NotServed
                        | ArtifactProbeResult::Busy => {
                            let mut round_closed = false;
                            if let Some(fetch) = &mut self.fetch
                                && let FetchPhase::Probe(round) =
                                    &mut fetch.phase
                            {
                                round.pending.remove(&sender);
                                if matches!(result, ArtifactProbeResult::Busy) {
                                    round.busy.insert(sender.clone());
                                }
                                round_closed = round.pending.is_empty();
                            }
                            if round_closed {
                                self.resolve_probe_round(ctx).await?;
                            }
                        }
                        ArtifactProbeResult::Outdated { .. } => {
                            // We are behind: sync instead of burning the
                            // rest of the round.
                            self.cycle_exhausted(ctx).await?;
                        }
                    }
                    return Ok(CompilerResponse::Ok);
                }

                // Late probe answers while fetching still feed the
                // round — nothing is lost.
                if let Some(fetch) = &mut self.fetch
                    && let FetchPhase::Fetch {
                        round,
                        probe_nonce,
                        peer,
                        ..
                    } = &mut fetch.phase
                    && *probe_nonce == request_nonce
                {
                    match result {
                        ArtifactProbeResult::CanServe => {
                            // A peer burned this round (failed attempt)
                            // is never re-admitted as a failover
                            // candidate.
                            if sender != *peer
                                && !round.failed.contains(&sender)
                                && !round.can_serve.contains(&sender)
                            {
                                round.can_serve.push_back(sender.clone());
                            }
                        }
                        ArtifactProbeResult::Busy => {
                            if !round.failed.contains(&sender) {
                                round.busy.insert(sender.clone());
                            }
                        }
                        ArtifactProbeResult::NotServed
                        | ArtifactProbeResult::Outdated { .. } => {}
                    }
                    round.pending.remove(&sender);
                }

                Ok(CompilerResponse::Ok)
            }
            ContractCompilerMessage::ArtifactRequest {
                subject_id,
                schema_id,
                gov_version,
                request_nonce,
                info,
                sender,
                receiver_actor,
            } => {
                let result = match self.artifact_gate(
                    ctx,
                    "ArtifactRequest",
                    &subject_id,
                    &schema_id,
                    gov_version,
                    &sender,
                ) {
                    ArtifactGate::Reject => return Ok(CompilerResponse::Ok),
                    ArtifactGate::NotServed => ArtifactFetchResult::NotServed,
                    ArtifactGate::Busy => ArtifactFetchResult::Busy,
                    ArtifactGate::Outdated => ArtifactFetchResult::Outdated {
                        gov_version: self.gov_version,
                    },
                    ArtifactGate::Allowed => {
                        let contract_name =
                            format!("{}_{}", subject_id, schema_id);
                        match self.serve_artifact(ctx, &contract_name).await?
                        {
                            Some(artifact) => {
                                ArtifactFetchResult::Artifact(artifact)
                            }
                            None => ArtifactFetchResult::NotServed,
                        }
                    }
                };

                self.send_artifact_message(
                    ctx,
                    "ArtifactRequest",
                    info,
                    sender,
                    receiver_actor,
                    ActorMessage::ArtifactRes {
                        request_nonce,
                        result,
                    },
                )
                .await?;

                debug!(
                    msg_type = "ArtifactRequest",
                    schema_id = ?schema_id,
                    "Artifact request served"
                );

                Ok(CompilerResponse::Ok)
            }
            ContractCompilerMessage::ArtifactResponse {
                result,
                request_nonce,
                sender,
            } => {
                // Stale or unexpected response: the fetch moved on.
                let matches_current = self.fetch.as_ref().is_some_and(|fetch| {
                    fetch.nonce == request_nonce
                        && matches!(
                            &fetch.phase,
                            FetchPhase::Fetch { peer, .. } if *peer == sender
                        )
                });
                if !matches_current {
                    debug!(
                        msg_type = "ArtifactResponse",
                        request_nonce,
                        sender = %sender,
                        "Stale artifact response, dropping"
                    );
                    return Ok(CompilerResponse::Ok);
                }

                self.cancel_fetch_timer(ctx);

                match result {
                    ArtifactFetchResult::Artifact(artifact) => {
                        let Some(fetch) = self.fetch.take() else {
                            return Ok(CompilerResponse::Ok);
                        };
                        match CompilerSupport::register_fetched_artifact(
                            self.hash,
                            ctx,
                            &fetch.contract_name,
                            &fetch.contract,
                            &fetch.contract_path,
                            fetch.initial_value.clone(),
                            &Self::register_path(ctx),
                            &fetch.wasm_hash,
                            artifact,
                        )
                        .await
                        {
                            Ok((module, metadata)) => {
                                let contracts =
                                    CompilerSupport::contracts_helper(ctx)
                                        .await?;
                                contracts.write().await.insert(
                                    fetch.contract_name.clone(),
                                    module,
                                );
                                self.contract = metadata.contract_hash.clone();
                                if let Some(metrics) = try_core_metrics() {
                                    metrics.observe_contract_prepare(
                                        "fetched",
                                        "ok",
                                        fetch.started_at.elapsed(),
                                    );
                                }
                                debug!(
                                    msg_type = "ArtifactResponse",
                                    contract_name = %fetch.contract_name,
                                    sender = %sender,
                                    "Contract artifact fetched and verified"
                                );
                            }
                            Err(error) => {
                                self.fetch = Some(fetch);
                                // A peer that answers a same-version
                                // request with corrupt bytes or bytes
                                // that do not match the ledger anchor is
                                // lying or corrupt: security log and next
                                // peer. The alerts system (future work)
                                // will report it.
                                if matches!(
                                    error,
                                    CompilerError::FetchedArtifactMismatch { .. }
                                        | CompilerError::FetchedArtifactDecompressionFailed { .. }
                                ) {
                                    warn!(
                                        msg_type = "ArtifactResponse",
                                        contract_name = %self
                                            .fetch
                                            .as_ref()
                                            .map(|f| f.contract_name.as_str())
                                            .unwrap_or_default(),
                                        sender = %sender,
                                        error = %error,
                                        "Fetched artifact is corrupt or does not match the ledger anchor"
                                    );
                                    self.attempt_failed(
                                        ctx,
                                        Some(error.to_string()),
                                        true,
                                    )
                                    .await?;
                                } else {
                                    self.fetch_failed(ctx, error).await?;
                                }
                            }
                        }
                    }
                    ArtifactFetchResult::NotServed => {
                        self.attempt_failed(
                            ctx,
                            Some("peer can not serve the artifact".to_owned()),
                            true,
                        )
                        .await?;
                    }
                    ArtifactFetchResult::Busy => {
                        // The peer started compiling after answering the
                        // probe: it joins the busy set of the round.
                        if let Some(fetch) = &mut self.fetch
                            && let FetchPhase::Fetch { round, peer, .. } =
                                &mut fetch.phase
                        {
                            round.busy.insert(peer.clone());
                        }
                        self.attempt_failed(
                            ctx,
                            Some("peer started compiling mid-fetch".to_owned()),
                            false,
                        )
                        .await?;
                    }
                    ArtifactFetchResult::Outdated { .. } => {
                        // We are behind: sync instead of burning the
                        // rest of the candidates.
                        self.cycle_exhausted(ctx).await?;
                    }
                }

                Ok(CompilerResponse::Ok)
            }
            ContractCompilerMessage::ProbeTimeout { request_nonce } => {
                let matches_current =
                    self.fetch.as_ref().is_some_and(|fetch| {
                        fetch.nonce == request_nonce
                            && matches!(fetch.phase, FetchPhase::Probe { .. })
                    });
                if matches_current {
                    // The round is closed: whoever did not answer is
                    // skipped (maybe down), the answered ones decide.
                    if let Some(fetch) = &mut self.fetch
                        && let FetchPhase::Probe(round) = &mut fetch.phase
                    {
                        round.pending.clear();
                    }
                    self.resolve_probe_round(ctx).await?;
                }

                Ok(CompilerResponse::Ok)
            }
            ContractCompilerMessage::FetchTimeout { request_nonce } => {
                let matches_current =
                    self.fetch.as_ref().is_some_and(|fetch| {
                        fetch.nonce == request_nonce
                            && matches!(fetch.phase, FetchPhase::Fetch { .. })
                    });
                if matches_current {
                    self.attempt_failed(
                        ctx,
                        Some("artifact fetch timed out".to_owned()),
                        true,
                    )
                    .await?;
                }

                Ok(CompilerResponse::Ok)
            }
            ContractCompilerMessage::BusyRetry { request_nonce } => {
                let matches_current =
                    self.fetch.as_ref().is_some_and(|fetch| {
                        fetch.nonce == request_nonce
                            && matches!(
                                fetch.phase,
                                FetchPhase::BusyWait { .. }
                            )
                    });
                if matches_current {
                    let Some(fetch) = &mut self.fetch else {
                        return Ok(CompilerResponse::Ok);
                    };
                    let FetchPhase::BusyWait(round) = &mut fetch.phase else {
                        return Ok(CompilerResponse::Ok);
                    };
                    let budget_spent =
                        round.busy_started.is_some_and(|started| {
                            started.elapsed() >= BUSY_TOTAL_BUDGET
                        });
                    let round = std::mem::take(round);
                    if budget_spent {
                        debug!(
                            msg_type = "Fetch",
                            "Busy batch budget exhausted, moving to the next batch"
                        );
                        self.next_batch(ctx, round).await?;
                    } else {
                        self.reprobe_busy(ctx, round).await?;
                    }
                }

                Ok(CompilerResponse::Ok)
            }
            ContractCompilerMessage::CycleStart { cycle } => {
                let matches_current =
                    self.fetch.as_ref().is_some_and(|fetch| {
                        fetch.cycles == cycle
                            && matches!(fetch.phase, FetchPhase::Timeoff)
                    });
                if matches_current {
                    debug!(
                        msg_type = "Fetch",
                        cycle, "Timeoff expired, starting new fetch cycle"
                    );
                    self.start_probe_set(ctx, false).await?;
                }

                Ok(CompilerResponse::Ok)
            }
        }
    }
}
