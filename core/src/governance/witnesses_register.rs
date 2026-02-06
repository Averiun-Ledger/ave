use std::collections::{HashMap, HashSet};

use crate::governance::sn_register::{
    SnLimit, SnRegister, SnRegisterMessage, SnRegisterResponse,
};
use crate::model::common::{Interval, IntervalSet, emit_fail};
use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Event, Handler, Message,
    Response,
};
use ave_actors::{LightPersistence, PersistentActor};
use ave_common::identity::{DigestIdentifier, PublicKey};
use ave_common::{Namespace, SchemaType};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use tracing::{Span, debug, error, info_span};

use crate::db::Storable;

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Default,
    BorshDeserialize,
    BorshSerialize,
)]
pub struct WitnessesRegister {
    gov_sn: u64,
    subjects: HashMap<DigestIdentifier, TransferData>,
    witnesses: HashMap<
        (PublicKey, SchemaType),
        HashMap<Namespace, (IntervalSet, Option<u64>)>,
    >,
    witnesses_creator: HashMap<
        (PublicKey, String, SchemaType),
        HashMap<WitnessesType, (IntervalSet, Option<u64>)>,
    >,
}

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    BorshDeserialize,
    BorshSerialize,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
pub enum WitnessesType {
    User(PublicKey),
    Witnesses,
}

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Default,
    BorshDeserialize,
    BorshSerialize,
)]
pub struct TransferData {
    actual_owner: PublicKey,
    actual_new_owner_data: Option<(PublicKey, u64)>,
    sn: u64,
    gov_version: u64,
    old_owners: HashMap<PublicKey, OldOwnerData>,
}

#[derive(
    Debug,
    Clone,
    Serialize,
    Deserialize,
    Default,
    BorshDeserialize,
    BorshSerialize,
)]
pub struct OldOwnerData {
    sn: u64,
    interval_gov_version: IntervalSet,
}

#[derive(Debug, Clone)]
pub enum WitnessesRegisterMessage {
    GetSnGov,
    GetTrackerSnCreator {
        subject_id: DigestIdentifier,
    },
    UpdateCreatorsWitnesses {
        version: u64,
        new_creator:
            HashMap<(SchemaType, String, PublicKey), Vec<WitnessesType>>,
        remove_creator: HashSet<(SchemaType, String, PublicKey)>,
        update_creator_witnesses:
            HashSet<(SchemaType, String, PublicKey, Vec<WitnessesType>)>,

        new_witnesses: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
        remove_witnesses: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
    },
    UpdateSn {
        subject_id: DigestIdentifier,
        sn: u64,
    },
    UpdateSnGov {
        sn: u64,
    },
    Create {
        subject_id: DigestIdentifier,
        owner: PublicKey,
        gov_version: u64,
    },
    Transfer {
        subject_id: DigestIdentifier,
        new_owner: PublicKey,
        gov_version: u64,
    },
    Confirm {
        subject_id: DigestIdentifier,
        sn: u64,
        gov_version: u64,
    },
    Reject {
        subject_id: DigestIdentifier,
        sn: u64,
        gov_version: u64,
    },
    Access {
        subject_id: DigestIdentifier,
        node: PublicKey,
        namespace: String,
        schema_id: SchemaType,
    },
}

impl Message for WitnessesRegisterMessage {}

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub enum WitnessesRegisterEvent {
    UpdateCreatorsWitnesses {
        version: u64,
        new_creator:
            HashMap<(SchemaType, String, PublicKey), Vec<WitnessesType>>,
        remove_creator: HashSet<(SchemaType, String, PublicKey)>,
        update_creator_witnesses:
            HashSet<(SchemaType, String, PublicKey, Vec<WitnessesType>)>,

        new_witnesses: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
        remove_witnesses: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
    },
    UpdateSn {
        subject_id: DigestIdentifier,
        sn: u64,
    },
    UpdateSnGov {
        sn: u64,
    },
    Create {
        subject_id: DigestIdentifier,
        owner: PublicKey,
        gov_version: u64,
    },
    Transfer {
        subject_id: DigestIdentifier,
        new_owner: PublicKey,
        gov_version: u64,
    },
    Confirm {
        subject_id: DigestIdentifier,
        sn: u64,
        gov_version: u64,
    },
    Reject {
        subject_id: DigestIdentifier,
        sn: u64,
        gov_version: u64,
    },
}

impl Event for WitnessesRegisterEvent {}

pub enum WitnessesRegisterResponse {
    Access { sn: Option<u64> },
    GovSn { sn: u64 },
    TrackerCreatorSn { data: Option<(PublicKey, u64)> },
    Ok,
}

impl Response for WitnessesRegisterResponse {}

impl WitnessesRegister {
    async fn get_sn(
        &self,
        ctx: &mut ActorContext<Self>,
        subject_id: DigestIdentifier,
        gov_version: u64,
    ) -> Result<SnLimit, ActorError> {
        let governance_id = ctx.path().parent().key();

        let path = ActorPath::from(format!(
            "/user/node/{}/sn_register",
            governance_id
        ));
        let sn_register = ctx.system().get_actor::<SnRegister>(&path).await?;
        let response = sn_register
            .ask(SnRegisterMessage::GetSn {
                subject_id,
                gov_version,
            })
            .await?;

        match response {
            SnRegisterResponse::Sn(sn_limit) => Ok(sn_limit),
            _ => Err(ActorError::UnexpectedResponse {
                path,
                expected: "SnRegisterResponse::Sn".to_owned(),
            }),
        }
    }

    fn search_in_schema(
        witness_data: &HashMap<Namespace, (IntervalSet, Option<u64>)>,
        parse_namespace: &Namespace,
        data: &OldOwnerData,
        mut better_gov_version: Option<u64>,
        mut better_sn: Option<u64>,
    ) -> (Option<u64>, Option<u64>) {
        'witness: {
            for (namespace, (interval, actual_lo)) in witness_data.iter() {
                if namespace.is_ancestor_or_equal_of(&parse_namespace) {
                    for range in data.interval_gov_version.iter().rev() {
                        if let Some(actual_lo) = actual_lo {
                            if actual_lo >= &range.lo || actual_lo <= &range.hi
                            {
                                better_gov_version =
                                    better_gov_version.max(Some(range.hi));
                                better_sn = better_sn.max(Some(data.sn));

                                break 'witness;
                            }
                        }

                        if let Some(gov_version) =
                            interval.max_covered_in(range.lo, range.hi)
                        {
                            better_gov_version =
                                better_gov_version.max(Some(gov_version));
                            better_sn = better_sn.max(Some(data.sn));

                            break;
                        }
                    }
                }
            }
        }

        (better_gov_version, better_sn)
    }

    async fn search_witnesses(
        &self,
        ctx: &mut ActorContext<Self>,
        node: &PublicKey,
        creators: &HashMap<PublicKey, OldOwnerData>,
        namespace: String,
        schema_id: SchemaType,
        subject_id: DigestIdentifier,
    ) -> Result<SnLimit, ActorError> {
        let mut better_gov_version: Option<u64> = None;
        let mut better_sn: Option<u64> = None;
        let parse_namespace = Namespace::from(namespace.clone());

        for (creator, data) in creators.iter() {
            if let Some(witnesses_creator) = self.witnesses_creator.get(&(
                creator.to_owned(),
                namespace.clone(),
                schema_id.clone(),
            )) {
                if let Some((interval, actual_lo)) =
                    witnesses_creator.get(&WitnessesType::User(node.clone()))
                {
                    // Si es testigo explicito
                    for range in data.interval_gov_version.iter().rev() {
                        // Sigue siendo testigo.
                        if let Some(actual_lo) = actual_lo {
                            if actual_lo >= &range.lo || actual_lo <= &range.hi
                            {
                                better_gov_version =
                                    better_gov_version.max(Some(range.hi));
                                better_sn = better_sn.max(Some(data.sn));

                                break;
                            }
                        }

                        if let Some(gov_version) =
                            interval.max_covered_in(range.lo, range.hi)
                        {
                            better_gov_version =
                                better_gov_version.max(Some(gov_version));
                            better_sn = better_sn.max(Some(data.sn));

                            break;
                        }
                    }
                }
                // Witness de schema.
                if witnesses_creator.contains_key(&WitnessesType::Witnesses) {
                    // ha tenido el rol de testigo.

                    // el esquema X
                    if let Some(witness_data) =
                        self.witnesses.get(&(node.clone(), schema_id.clone()))
                    {
                        let search = Self::search_in_schema(
                            witness_data,
                            &parse_namespace,
                            data,
                            better_gov_version,
                            better_sn,
                        );
                        better_gov_version = search.0;
                        better_sn = search.1;
                    }

                    // todos los esquemas.
                    if let Some(witness_data) = self
                        .witnesses
                        .get(&(node.clone(), SchemaType::AllSchemas))
                    {
                        let search = Self::search_in_schema(
                            witness_data,
                            &parse_namespace,
                            data,
                            better_gov_version,
                            better_sn,
                        );
                        better_gov_version = search.0;
                        better_sn = search.1;
                    }
                }
            }
        }

        if let Some(gov_version) = better_gov_version
            && let Some(better_sn) = better_sn
        {
            let sn_limit =
                match self.get_sn(ctx, subject_id, gov_version).await? {
                    SnLimit::Sn(sn) => SnLimit::Sn(sn.min(better_sn)),
                    SnLimit::LastSn => SnLimit::Sn(better_sn),
                    SnLimit::NotSn => SnLimit::NotSn,
                };

            Ok(sn_limit)
        } else {
            Ok(SnLimit::NotSn)
        }
    }
}

#[async_trait]
impl Actor for WitnessesRegister {
    type Event = WitnessesRegisterEvent;
    type Message = WitnessesRegisterMessage;
    type Response = WitnessesRegisterResponse;

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        if let Some(parent_span) = parent_span {
            info_span!(parent: parent_span, "WitnessesRegister")
        } else {
            info_span!("WitnessesRegister")
        }
    }

    async fn pre_start(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        let prefix = ctx.path().parent().key();
        if let Err(e) = self
            .init_store("witnesses_register", Some(prefix), false, ctx)
            .await
        {
            error!(
                error = %e,
                "Failed to initialize witnesses_register store"
            );
            return Err(e);
        }
        Ok(())
    }

    async fn pre_stop(
        &mut self,
        ctx: &mut ActorContext<Self>,
    ) -> Result<(), ActorError> {
        if let Err(e) = self.stop_store(ctx).await {
            error!(
                error = %e,
                "Failed to stop witnesses_register store"
            );
            return Err(e);
        }
        Ok(())
    }
}

#[async_trait]
impl Handler<WitnessesRegister> for WitnessesRegister {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: WitnessesRegisterMessage,
        ctx: &mut ActorContext<WitnessesRegister>,
    ) -> Result<WitnessesRegisterResponse, ActorError> {
        match msg {
            WitnessesRegisterMessage::GetTrackerSnCreator { subject_id } => {
                let data = if let Some(data) = self.subjects.get(&subject_id) {
                    Some((data.actual_owner.clone(), data.sn))
                } else {
                    None
                };

                debug!(
                    msg_type = "GetTrackerSnCreator",
                    subject_id = %subject_id,
                    found = data.is_some(),
                    "Tracker sn creator lookup completed"
                );

                return Ok(WitnessesRegisterResponse::TrackerCreatorSn {
                    data,
                });
            }
            WitnessesRegisterMessage::GetSnGov => {
                debug!(
                    msg_type = "GetSnGov",
                    sn = self.gov_sn,
                    "Governance sn retrieved"
                );
                return Ok(WitnessesRegisterResponse::GovSn { sn: self.gov_sn });
            }
            WitnessesRegisterMessage::UpdateSnGov { sn } => {
                self.on_event(WitnessesRegisterEvent::UpdateSnGov { sn }, ctx)
                    .await;

                debug!(
                    msg_type = "UpdateSnGov",
                    sn = sn,
                    "Governance sn updated"
                );
            }
            WitnessesRegisterMessage::UpdateCreatorsWitnesses {
                version,
                new_creator,
                remove_creator,
                update_creator_witnesses,
                new_witnesses,
                remove_witnesses,
            } => {
                let new_creator_count = new_creator.len();
                let remove_creator_count = remove_creator.len();
                self.on_event(
                    WitnessesRegisterEvent::UpdateCreatorsWitnesses {
                        version,
                        new_creator,
                        remove_creator,
                        update_creator_witnesses,
                        new_witnesses,
                        remove_witnesses,
                    },
                    ctx,
                )
                .await;

                debug!(
                    msg_type = "UpdateCreatorsWitnesses",
                    version = version,
                    new_creator_count = new_creator_count,
                    remove_creator_count = remove_creator_count,
                    "Creators and witnesses updated"
                );
            }
            WitnessesRegisterMessage::UpdateSn { sn, subject_id } => {
                self.on_event(
                    WitnessesRegisterEvent::UpdateSn {
                        sn,
                        subject_id: subject_id.clone(),
                    },
                    ctx,
                )
                .await;

                debug!(
                    msg_type = "UpdateSn",
                    subject_id = %subject_id,
                    sn = sn,
                    "Sequence number updated"
                );
            }
            WitnessesRegisterMessage::Create {
                subject_id,
                owner,
                gov_version,
            } => {
                self.on_event(
                    WitnessesRegisterEvent::Create {
                        subject_id: subject_id.clone(),
                        owner: owner.clone(),
                        gov_version,
                    },
                    ctx,
                )
                .await;

                debug!(
                    msg_type = "Create",
                    subject_id = %subject_id,
                    owner = %owner,
                    "Transfer entry created"
                );
            }
            WitnessesRegisterMessage::Transfer {
                subject_id,
                new_owner,
                gov_version,
            } => {
                self.on_event(
                    WitnessesRegisterEvent::Transfer {
                        subject_id: subject_id.clone(),
                        new_owner: new_owner.clone(),
                        gov_version,
                    },
                    ctx,
                )
                .await;

                debug!(
                    msg_type = "Transfer",
                    subject_id = %subject_id,
                    new_owner = %new_owner,
                    "New transfer registered"
                );
            }
            WitnessesRegisterMessage::Reject {
                subject_id,
                sn,
                gov_version,
            } => {
                self.on_event(
                    WitnessesRegisterEvent::Reject {
                        subject_id: subject_id.clone(),
                        sn,
                        gov_version,
                    },
                    ctx,
                )
                .await;

                debug!(
                    msg_type = "Reject",
                    subject_id = %subject_id,
                    sn = sn,
                    "The transfer was rejected"
                );
            }
            WitnessesRegisterMessage::Confirm {
                subject_id,
                sn,
                gov_version,
            } => {
                self.on_event(
                    WitnessesRegisterEvent::Confirm {
                        subject_id: subject_id.clone(),
                        sn,
                        gov_version,
                    },
                    ctx,
                )
                .await;

                debug!(
                    msg_type = "Confirm",
                    subject_id = %subject_id,
                    sn = sn,
                    "The transfer was confirmed"
                );
            }
            WitnessesRegisterMessage::Access {
                subject_id,
                node,
                namespace,
                schema_id,
            } => {
                let sn = if let Some(data) = self.subjects.get(&subject_id) {
                    if data.actual_owner == node {
                        Some(data.sn)
                    } else if let Some((new_owner, ..)) =
                        &data.actual_new_owner_data
                        && new_owner == &node
                    {
                        Some(data.sn)
                    } else if let Some(old_data) = data.old_owners.get(&node) {
                        let sn_limit = self
                            .search_witnesses(
                                ctx,
                                &node,
                                &data.old_owners,
                                namespace,
                                schema_id,
                                subject_id.clone(),
                            )
                            .await?;

                        let sn = match sn_limit {
                            SnLimit::Sn(sn) => sn.max(old_data.sn),
                            SnLimit::LastSn => unreachable!(
                                "search_witnesses can not return SnLimit::LastSn"
                            ),
                            SnLimit::NotSn => old_data.sn,
                        };

                        Some(sn)
                    } else {
                        let sn_limit = self
                            .search_witnesses(
                                ctx,
                                &node,
                                &data.old_owners,
                                namespace,
                                schema_id,
                                subject_id.clone(),
                            )
                            .await?;

                        match sn_limit {
                            SnLimit::Sn(sn) => Some(sn),
                            SnLimit::LastSn => unreachable!(
                                "search_witnesses can not return SnLimit::LastSn"
                            ),
                            SnLimit::NotSn => None,
                        }
                    }
                } else {
                    None
                };

                debug!(
                    msg_type = "Access",
                    subject_id = %subject_id,
                    node = %node,
                    sn = sn,
                    "Checked access status"
                );

                return Ok(WitnessesRegisterResponse::Access { sn });
            }
        };

        Ok(WitnessesRegisterResponse::Ok)
    }

    async fn on_event(
        &mut self,
        event: WitnessesRegisterEvent,
        ctx: &mut ActorContext<WitnessesRegister>,
    ) {
        if let Err(e) = self.persist(&event, ctx).await {
            error!(
                event = ?event,
                error = %e,
                "Failed to persist witnesses register event"
            );
            emit_fail(ctx, e).await;
        }
    }
}

#[async_trait]
impl PersistentActor for WitnessesRegister {
    type Persistence = LightPersistence;
    type InitParams = ();

    fn create_initial(_params: Self::InitParams) -> Self {
        Self::default()
    }

    fn apply(&mut self, event: &Self::Event) -> Result<(), ActorError> {
        match event {
            WitnessesRegisterEvent::UpdateSnGov { sn } => {
                self.gov_sn = *sn;

                debug!(
                    event_type = "UpdateSnGov",
                    sn = sn,
                    "Governance sn updated in state"
                );
            }
            WitnessesRegisterEvent::UpdateCreatorsWitnesses {
                version,
                new_creator,
                remove_creator,
                update_creator_witnesses,
                new_witnesses,
                remove_witnesses,
            } => {
                for ((schema_id, ns, creator), witnesses) in new_creator.iter()
                {
                    for witness in witnesses.iter() {
                        self.witnesses_creator
                            .entry((
                                creator.clone(),
                                ns.clone(),
                                schema_id.clone(),
                            ))
                            .or_default()
                            .entry(witness.clone())
                            .or_default()
                            .1 = Some(*version);
                    }
                }

                for (schema_id, ns, creator) in remove_creator.iter() {
                    if let Some(witnesses) = self.witnesses_creator.get_mut(&(
                        creator.clone(),
                        ns.clone(),
                        schema_id.clone(),
                    )) {
                        for (.., (interval, last)) in witnesses.iter_mut() {
                            if let Some(last) = last.take() {
                                interval.insert(Interval {
                                    lo: last,
                                    hi: *version,
                                });
                            }
                        }
                    }
                }

                for (schema_id, ns, creator, witnesses) in
                    update_creator_witnesses.iter()
                {
                    if let Some(creator_witnesses) =
                        self.witnesses_creator.get_mut(&(
                            creator.clone(),
                            ns.clone(),
                            schema_id.clone(),
                        ))
                    {
                        for witness in witnesses.iter() {
                            if let Some((.., last)) =
                                creator_witnesses.get_mut(witness)
                            {
                                if last.is_none() {
                                    *last = Some(*version);
                                }
                            } else {
                                creator_witnesses.insert(
                                    witness.clone(),
                                    (IntervalSet::new(), Some(*version)),
                                );
                            }
                        }
                    }
                }

                for ((schema_id, witness), namespace) in new_witnesses {
                    for ns in namespace.iter() {
                        self.witnesses
                            .entry((witness.clone(), schema_id.clone()))
                            .or_default()
                            .entry(ns.clone())
                            .or_default()
                            .1 = Some(*version);
                    }
                }

                for ((schema_id, witness), namespace) in remove_witnesses {
                    if let Some(witness_namespace) = self
                        .witnesses
                        .get_mut(&(witness.clone(), schema_id.clone()))
                    {
                        for ns in namespace.iter() {
                            if let Some((interval, last)) =
                                witness_namespace.get_mut(ns)
                            {
                                if let Some(last) = last.take() {
                                    interval.insert(Interval {
                                        lo: last,
                                        hi: *version,
                                    });
                                }
                            }
                        }
                    }
                }

                debug!(
                    event_type = "UpdateCreatorsWitnesses",
                    version = version,
                    new_creator_count = new_creator.len(),
                    remove_creator_count = remove_creator.len(),
                    "Creators and witnesses updated in state"
                );
            }
            WitnessesRegisterEvent::UpdateSn { subject_id, sn } => {
                if let Some(data) = self.subjects.get_mut(subject_id) {
                    data.sn = *sn;

                    debug!(
                        event_type = "UpdateSn",
                        subject_id = %subject_id,
                        sn = sn,
                        "Sequence number updated"
                    );
                } else {
                    error!(
                        event_type = "UpdateSn",
                        subject_id = %subject_id,
                        "Subject not found in register"
                    );
                };
            }
            WitnessesRegisterEvent::Create {
                subject_id,
                owner,
                gov_version,
            } => {
                let data = self.subjects.entry(subject_id.clone()).or_default();

                data.actual_owner = owner.clone();
                data.gov_version = *gov_version;

                debug!(
                    event_type = "Create",
                    subject_id = %subject_id,
                    owner = %owner,
                    "Transfer entry created"
                );
            }
            WitnessesRegisterEvent::Transfer {
                subject_id,
                new_owner,
                gov_version,
            } => {
                if let Some(data) = self.subjects.get_mut(subject_id) {
                    data.actual_new_owner_data =
                        Some((new_owner.clone(), *gov_version));

                    debug!(
                        event_type = "Transfer",
                        subject_id = %subject_id,
                        new_owner = %new_owner,
                        "Transfer initiated"
                    );
                } else {
                    error!(
                        event_type = "Transfer",
                        subject_id = %subject_id,
                        new_owner = %new_owner,
                        "Subject not found in register"
                    );
                };
            }
            WitnessesRegisterEvent::Confirm {
                subject_id,
                sn,
                gov_version,
            } => {
                if let Some(data) = self.subjects.get_mut(subject_id) {
                    let new_owner = data.actual_new_owner_data.take();

                    if let Some((new_owner, new_owner_gov_version)) = new_owner
                    {
                        let entry = data
                            .old_owners
                            .entry(data.actual_owner.clone())
                            .or_default();
                        entry.sn = *sn;
                        entry.interval_gov_version.insert(Interval {
                            lo: data.gov_version,
                            hi: *gov_version,
                        });

                        data.actual_owner = new_owner;
                        data.gov_version = new_owner_gov_version;

                        debug!(
                            event_type = "Confirm",
                            subject_id = %subject_id,
                            sn = sn,
                            "Transfer confirmed"
                        );
                    } else {
                        error!(
                            event_type = "Confirm",
                            subject_id = %subject_id,
                            sn = sn,
                            "No pending new owner to confirm"
                        );
                    };
                } else {
                    error!(
                        event_type = "Confirm",
                        subject_id = %subject_id,
                        sn = sn,
                        "Subject not found in register"
                    );
                };
            }
            WitnessesRegisterEvent::Reject {
                subject_id,
                sn,
                gov_version,
            } => {
                if let Some(data) = self.subjects.get_mut(subject_id) {
                    let new_owner = data.actual_new_owner_data.take();

                    if let Some((new_owner, ..)) = new_owner {
                        let entry = data
                            .old_owners
                            .entry(new_owner.clone())
                            .or_default();
                        entry.sn = *sn;
                        entry.interval_gov_version.insert(Interval {
                            lo: data.gov_version,
                            hi: *gov_version,
                        });

                        debug!(
                            event_type = "Reject",
                            subject_id = %subject_id,
                            sn = sn,
                            "Transfer rejected"
                        );
                    } else {
                        error!(
                            event_type = "Reject",
                            subject_id = %subject_id,
                            sn = sn,
                            "No pending new owner to reject"
                        );
                    };
                } else {
                    error!(
                        event_type = "Reject",
                        subject_id = %subject_id,
                        sn = sn,
                        "Subject not found in register"
                    );
                };
            }
        };

        Ok(())
    }
}

impl Storable for WitnessesRegister {}
