use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ChildAction, Handler, Message,
    NotPersistentActor,
};

use async_trait::async_trait;
use ave_common::identity::{DigestIdentifier, PublicKey};
use network::ComunicateInfo;
use serde::{Deserialize, Serialize};
use tracing::{Span, debug, error, info_span, warn};
use updater::{Updater, UpdaterMessage};

use crate::{
    NetworkMessage,
    governance::witnesses_register::{
        TrackerDeliveryMode, TrackerDeliveryRange,
    },
    helpers::network::{ActorMessage, service::NetworkSender},
    model::common::{emit_fail, subject::get_local_subject_sn},
    request::manager::{RequestManager, RequestManagerMessage},
};

pub mod updater;

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Eq)]
pub enum UpdateSubjectKind {
    Governance,
    Tracker,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct UpdateWitnessOffer {
    pub kind: UpdateSubjectKind,
    pub sn: u64,
    pub clear_sn: Option<u64>,
    pub ranges: Vec<TrackerDeliveryRange>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UpdateStartMode {
    Direct,
    Sweep,
    Empty,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum UpdateType {
    Auth,
    Request {
        subject_id: DigestIdentifier,
        id: DigestIdentifier,
    },
}

pub struct UpdateNew {
    pub subject_id: DigestIdentifier,
    pub witnesses: HashSet<PublicKey>,
    pub update_type: UpdateType,
    pub network: Arc<NetworkSender>,
    pub our_sn: Option<u64>,
    pub subject_kind_hint: Option<UpdateSubjectKind>,
    pub round_retry_interval_secs: u64,
    pub max_round_retries: usize,
    pub witness_retry_count: usize,
    pub witness_retry_interval_secs: u64,
}

#[derive(Clone, Debug)]
pub struct Update {
    subject_id: DigestIdentifier,
    witnesses: HashSet<PublicKey>,
    all_witnesses: HashSet<PublicKey>,
    offers: HashMap<PublicKey, UpdateWitnessOffer>,
    our_sn: Option<u64>,
    update_type: UpdateType,
    network: Arc<NetworkSender>,
    retry_round: u64,
    retry_token: u64,
    retry_attempt: usize,
    subject_kind_hint: Option<UpdateSubjectKind>,
    round_retry_interval_secs: u64,
    max_round_retries: usize,
    witness_retry_count: usize,
    witness_retry_interval_secs: u64,
}

impl Update {
    pub fn new(data: UpdateNew) -> Self {
        Self {
            network: data.network,
            subject_id: data.subject_id,
            witnesses: data.witnesses.clone(),
            all_witnesses: data.witnesses,
            update_type: data.update_type,
            our_sn: data.our_sn,
            offers: HashMap::new(),
            retry_round: 0,
            retry_token: 0,
            retry_attempt: 0,
            subject_kind_hint: data.subject_kind_hint,
            round_retry_interval_secs: data.round_retry_interval_secs,
            max_round_retries: data.max_round_retries,
            witness_retry_count: data.witness_retry_count,
            witness_retry_interval_secs: data.witness_retry_interval_secs,
        }
    }

    fn should_retry_auth_rounds(&self) -> bool {
        matches!(self.update_type, UpdateType::Auth)
            && !matches!(
                self.subject_kind_hint,
                Some(UpdateSubjectKind::Governance)
            )
    }

    fn has_progress(&self, sn: u64) -> bool {
        self.our_sn.is_none_or(|our_sn| sn > our_sn)
    }

    fn next_needed_sn(&self) -> u64 {
        self.our_sn.map_or(0, |sn| sn.saturating_add(1))
    }

    fn next_tracker_range<'a>(
        &self,
        ranges: &'a [TrackerDeliveryRange],
    ) -> Option<&'a TrackerDeliveryRange> {
        let next_sn = self.next_needed_sn();
        ranges
            .iter()
            .find(|range| range.from_sn <= next_sn && next_sn <= range.to_sn)
    }

    fn tracker_range_rank(
        mode: &TrackerDeliveryMode,
    ) -> u8 {
        match mode {
            TrackerDeliveryMode::Clear => 1,
            TrackerDeliveryMode::Opaque => 0,
        }
    }

    fn insert_offer(
        &mut self,
        sender: PublicKey,
        offer: Option<UpdateWitnessOffer>,
    ) {
        if let Some(offer) = offer
            && self.has_progress(offer.sn)
        {
            self.offers.insert(sender, offer);
        }
    }

    fn select_tracker_offer(
        &self,
    ) -> Option<(PublicKey, UpdateWitnessOffer, u64)> {
        self.offers
            .iter()
            .filter(|(_, offer)| offer.kind == UpdateSubjectKind::Tracker)
            .filter_map(|(sender, offer)| {
                if !self.has_progress(offer.sn) {
                    return None;
                }

                let range = self.next_tracker_range(&offer.ranges)?;
                let target_sn = range.to_sn.min(offer.sn);
                Some((
                    sender.clone(),
                    offer.clone(),
                    target_sn,
                    (Self::tracker_range_rank(&range.mode), target_sn, offer.sn),
                ))
            })
            .max_by_key(|(.., rank)| *rank)
            .map(|(sender, offer, target_sn, _)| (sender, offer, target_sn))
    }

    fn select_governance_offer(
        &self,
    ) -> Option<(PublicKey, UpdateWitnessOffer, u64)> {
        self.offers
            .iter()
            .filter(|(_, offer)| offer.kind == UpdateSubjectKind::Governance)
            .filter(|(_, offer)| self.has_progress(offer.sn))
            .max_by_key(|(_, offer)| offer.sn)
            .map(|(sender, offer)| (sender.clone(), offer.clone(), offer.sn))
    }

    fn select_next_request(
        &self,
    ) -> Option<(PublicKey, UpdateWitnessOffer, u64)> {
        self.select_tracker_offer()
            .or_else(|| self.select_governance_offer())
    }

    fn check_witness(&mut self, witness: PublicKey) -> bool {
        self.witnesses.remove(&witness)
    }

    fn reset_round(&mut self) {
        self.witnesses = self.all_witnesses.clone();
        self.offers.clear();
    }

    async fn stop_active_updaters(
        &self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let children = ctx.system().children(ctx.path()).await;
        for child_path in children {
            let Ok(child) = ctx.system().get_actor::<Updater>(&child_path).await
            else {
                continue;
            };

            if let Err(e) = child.ask_stop().await {
                warn!(
                    subject_id = %self.subject_id,
                    child = %child_path,
                    error = %e,
                    "Failed to stop stale updater child before starting next round"
                );
            }
        }

        Ok(())
    }

    async fn request_distribution(
        &self,
        witness: PublicKey,
        target_sn: Option<u64>,
    ) -> Result<(), ActorError> {
        let info = ComunicateInfo {
            receiver: witness,
            request_id: String::default(),
            version: 0,
            receiver_actor: format!(
                "/user/node/distributor_{}",
                self.subject_id
            ),
        };

        self.network
            .send_command(network::CommandHelper::SendMessage {
                message: NetworkMessage {
                    info,
                    message: ActorMessage::DistributionLedgerReq {
                        actual_sn: self.our_sn,
                        target_sn,
                        subject_id: self.subject_id.clone(),
                    },
                },
            })
            .await
    }

    async fn create_updates(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<UpdateStartMode, ActorError> {
        if self.all_witnesses.len() == 1 && self.our_sn.is_none() {
            let Some(witness) = self.all_witnesses.iter().next() else {
                return Ok(UpdateStartMode::Direct);
            };

            self.request_distribution(witness.clone(), None).await?;
            return Ok(UpdateStartMode::Direct);
        }

        self.stop_active_updaters(ctx).await?;

        for witness in self.witnesses.clone() {
            let updater = Updater::new(
                witness.clone(),
                self.retry_round,
                self.network.clone(),
                self.witness_retry_count,
                self.witness_retry_interval_secs,
            );
            let child_name = format!("{}_{}", witness, self.retry_round);
            let child = ctx.create_child(&child_name, updater).await?;
            let message = UpdaterMessage::NetworkLastSn {
                subject_id: self.subject_id.clone(),
                actual_sn: self.our_sn,
            };

            if let Err(e) = child.tell(message).await {
                warn!(
                    subject_id = %self.subject_id,
                    witness = %witness,
                    error = %e,
                    "Updater child rejected round start message, skipping this witness in current round"
                );
                self.witnesses.remove(&witness);
                continue;
            }
        }
        if self.witnesses.is_empty() {
            Ok(UpdateStartMode::Empty)
        } else {
            Ok(UpdateStartMode::Sweep)
        }
    }

    async fn schedule_retry(
        &mut self,
        ctx: &mut ActorContext<Self>,
        expected_target_sn: u64,
        attempt: usize,
    ) -> Result<(), ActorError> {
        let actor = ctx.reference().await?;
        let round = self.retry_round;
        let token = self.retry_token.saturating_add(1);
        self.retry_token = token;
        let retry_interval_secs = self.round_retry_interval_secs.max(1);
        tokio::spawn(async move {
            tokio::time::sleep(std::time::Duration::from_secs(
                retry_interval_secs,
            ))
            .await;
            let _ = actor
                .tell(UpdateMessage::RetryRound {
                    expected_target_sn,
                    round,
                    attempt,
                    token,
                })
                .await;
        });

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub enum UpdateMessage {
    Run,
    Continue,
    RetryRound {
        expected_target_sn: u64,
        round: u64,
        attempt: usize,
        token: u64,
    },
    Response {
        sender: PublicKey,
        offer: Option<UpdateWitnessOffer>,
        round: u64,
    },
}

impl Message for UpdateMessage {}

#[async_trait]
impl Actor for Update {
    type Event = ();
    type Message = UpdateMessage;
    type Response = ();

    fn get_span(id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("Update", id),
            |parent_span| info_span!(parent: parent_span, "Update", id),
        )
    }
}

impl NotPersistentActor for Update {}

#[async_trait]
impl Handler<Self> for Update {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: UpdateMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        match msg {
            UpdateMessage::Run => {
                self.retry_attempt = 0;
                self.reset_round();
                let start_mode = match self.create_updates(ctx).await {
                    Ok(start_mode) => start_mode,
                    Err(e) => {
                        error!(
                            msg_type = "Run",
                            error = %e,
                            "Failed to create updates"
                        );
                        return Err(emit_fail(ctx, e).await);
                    }
                };

                match start_mode {
                    UpdateStartMode::Direct | UpdateStartMode::Empty => {
                        ctx.stop(None).await;
                        return Ok(());
                    }
                    UpdateStartMode::Sweep => {}
                }

                debug!(
                    msg_type = "Run",
                    witnesses_count = self.witnesses.len(),
                    "Updates created successfully"
                );
            }
            UpdateMessage::Continue => {
                let current_sn =
                    get_local_subject_sn(ctx, &self.subject_id).await?;
                self.our_sn = current_sn;
                self.retry_round = self.retry_round.saturating_add(1);
                self.retry_attempt = 0;
                self.reset_round();

                let start_mode = match self.create_updates(ctx).await {
                    Ok(start_mode) => start_mode,
                    Err(e) => {
                        error!(
                            msg_type = "Continue",
                            subject_id = %self.subject_id,
                            current_sn = ?current_sn,
                            error = %e,
                            "Failed to continue update round"
                        );
                        return Err(emit_fail(ctx, e).await);
                    }
                };

                match start_mode {
                    UpdateStartMode::Direct | UpdateStartMode::Empty => {
                        ctx.stop(None).await;
                        return Ok(());
                    }
                    UpdateStartMode::Sweep => {}
                }
            }
            UpdateMessage::RetryRound {
                expected_target_sn,
                round,
                attempt,
                token,
            } => {
                if round != self.retry_round || token != self.retry_token {
                    return Ok(());
                }

                let current_sn =
                    get_local_subject_sn(ctx, &self.subject_id).await?;
                if current_sn.is_some_and(|sn| sn >= expected_target_sn) {
                    debug!(
                        msg_type = "RetryRound",
                        subject_id = %self.subject_id,
                        current_sn = ?current_sn,
                        expected_target_sn = expected_target_sn,
                        "Update target already reached before retry round restart"
                    );
                    ctx.stop(None).await;
                    return Ok(());
                }

                if attempt >= self.max_round_retries {
                    warn!(
                        msg_type = "RetryRound",
                        subject_id = %self.subject_id,
                        current_sn = ?current_sn,
                        expected_target_sn = expected_target_sn,
                        attempt = attempt,
                        "Update retry round exhausted before reaching target"
                    );
                    ctx.stop(None).await;
                    return Ok(());
                }

                self.our_sn = current_sn;
                self.retry_round = self.retry_round.saturating_add(1);
                self.retry_attempt = attempt.saturating_add(1);
                self.reset_round();

                let start_mode = match self.create_updates(ctx).await {
                    Ok(start_mode) => start_mode,
                    Err(e) => {
                        error!(
                            msg_type = "RetryRound",
                            subject_id = %self.subject_id,
                            current_sn = ?current_sn,
                            expected_target_sn = expected_target_sn,
                            error = %e,
                            "Failed to restart update round"
                        );
                        return Err(emit_fail(ctx, e).await);
                    }
                };

                match start_mode {
                    UpdateStartMode::Direct | UpdateStartMode::Empty => {
                        ctx.stop(None).await;
                        return Ok(());
                    }
                    UpdateStartMode::Sweep => {}
                }
            }
            UpdateMessage::Response {
                sender,
                offer,
                round,
            } => {
                if round != self.retry_round {
                    return Ok(());
                }

                if self.check_witness(sender.clone()) {
                    self.insert_offer(sender, offer);

                    if self.witnesses.is_empty() {
                        let selected_request = self.select_next_request();
                        let mut keep_running = false;

                        if let Some((better_node, offer, target_sn)) =
                            selected_request.clone()
                        {
                            if let Err(e) = self
                                .request_distribution(
                                    better_node.clone(),
                                    Some(target_sn),
                                )
                                .await
                            {
                                error!(
                                    msg_type = "Response",
                                    error = %e,
                                    node = %better_node,
                                    "Failed to send request to network"
                                );
                                return Err(emit_fail(ctx, e).await);
                            } else {
                                debug!(
                                    msg_type = "Response",
                                    node = %better_node,
                                    subject_id = %self.subject_id,
                                    offer_kind = ?offer.kind,
                                    offer_sn = offer.sn,
                                    offer_clear_sn = ?offer.clear_sn,
                                    target_sn = target_sn,
                                    "Request sent to better node"
                                );
                            }

                            if matches!(offer.kind, UpdateSubjectKind::Tracker)
                                && self.should_retry_auth_rounds()
                            {
                                keep_running = true;
                                if let Err(e) = self
                                    .schedule_retry(
                                        ctx,
                                        target_sn,
                                        self.retry_attempt,
                                    )
                                    .await
                                {
                                    error!(
                                        msg_type = "Response",
                                        subject_id = %self.subject_id,
                                        expected_target_sn = target_sn,
                                        error = %e,
                                        "Failed to schedule update retry"
                                    );
                                    return Err(emit_fail(ctx, e).await);
                                }
                            }
                        }

                        if let UpdateType::Request { id, subject_id } =
                            &self.update_type
                        {
                            let request_path = ActorPath::from(format!(
                                "/user/request/{}",
                                subject_id
                            ));
                            match ctx
                                .system()
                                .get_actor::<RequestManager>(&request_path)
                                .await
                            {
                                Ok(request_actor) => {
                                    let request = if self.offers.is_empty() {
                                        RequestManagerMessage::FinishReboot {
                                            request_id: id.clone(),
                                        }
                                    } else {
                                        RequestManagerMessage::RebootWait {
                                            request_id: id.clone(),
                                            governance_id: self
                                                .subject_id
                                                .clone(),
                                        }
                                    };

                                    if let Err(e) =
                                        request_actor.tell(request).await
                                    {
                                        error!(
                                            msg_type = "Response",
                                            error = %e,
                                            subject_id = %self.subject_id,
                                            "Failed to send response to request actor"
                                        );
                                        return Err(emit_fail(ctx, e).await);
                                    }
                                }
                                Err(e) => {
                                    error!(
                                        msg_type = "Response",
                                        error = %e,
                                        path = %request_path,
                                        subject_id = %self.subject_id,
                                        "Request actor not found"
                                    );
                                    return Err(emit_fail(ctx, e).await);
                                }
                            };
                        };

                        debug!(
                            msg_type = "Response",
                            subject_id = %self.subject_id,
                            has_better = selected_request.is_some(),
                            "All witnesses responded, update complete"
                        );

                        if self.should_retry_auth_rounds() {
                            if !keep_running {
                                ctx.stop(None).await;
                            }
                        } else if matches!(self.update_type, UpdateType::Auth)
                        {
                            ctx.stop(None).await;
                        } else {
                            ctx.stop(None).await;
                        }
                    }
                } else {
                    warn!(
                        msg_type = "Response",
                        subject_id = %self.subject_id,
                        sender = %sender,
                        has_offer = self.offers.contains_key(&sender),
                        "Ignoring response from unexpected or already-processed witness"
                    );
                }
            }
        };

        Ok(())
    }

    async fn on_child_fault(
        &mut self,
        error: ActorError,
        ctx: &mut ActorContext<Self>,
    ) -> ChildAction {
        error!(
            subject_id = %self.subject_id,
            update_type = ?self.update_type,
            error = %error,
            "Child fault in update actor"
        );
        emit_fail(ctx, error).await;
        ChildAction::Stop
    }
}
