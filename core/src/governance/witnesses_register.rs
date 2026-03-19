use std::collections::{BTreeMap, HashMap, HashSet};

use crate::governance::sn_register::{
    SnLimit, SnRegister, SnRegisterMessage, SnRegisterResponse,
};
use crate::governance::subject_register::{
    SubjectRegister, SubjectRegisterMessage, SubjectRegisterResponse,
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
    witnesses:
        HashMap<(PublicKey, SchemaType), HashMap<Namespace, IntervalData>>,
    witnesses_creator: HashMap<
        (PublicKey, String, SchemaType),
        HashMap<WitnessesType, IntervalData>,
    >,
}

type IntervalData = (IntervalSet, Option<u64>);

pub enum ActualSearch {
    End(SnLimit),
    Continue { gov_version: Option<u64> },
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
    ListCurrentWitnessSubjects {
        node: PublicKey,
        governance_version: u64,
        after_subject_id: Option<DigestIdentifier>,
        limit: usize,
    },
    UpdateCreatorsWitnessesFact {
        version: u64,
        new_creator:
            HashMap<(SchemaType, String, PublicKey), Vec<WitnessesType>>,
        remove_creator: HashSet<(SchemaType, String, PublicKey)>,
        update_creator_witnesses:
            HashSet<(SchemaType, String, PublicKey, Vec<WitnessesType>)>,

        new_witnesses: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
        remove_witnesses: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
    },
    UpdateCreatorsWitnessesConfirm {
        version: u64,
        remove_creator: HashSet<(SchemaType, String, PublicKey)>,
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

impl Message for WitnessesRegisterMessage {
    fn is_critical(&self) -> bool {
        matches!(
            self,
            Self::UpdateCreatorsWitnessesFact { .. }
                | Self::UpdateCreatorsWitnessesConfirm { .. }
                | Self::UpdateSn { .. }
                | Self::UpdateSnGov { .. }
                | Self::Create { .. }
                | Self::Transfer { .. }
                | Self::Confirm { .. }
                | Self::Reject { .. }
        )
    }
}

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub enum WitnessesRegisterEvent {
    UpdateCreatorsWitnessesFact {
        version: u64,
        new_creator:
            HashMap<(SchemaType, String, PublicKey), Vec<WitnessesType>>,
        remove_creator: HashSet<(SchemaType, String, PublicKey)>,
        update_creator_witnesses:
            HashSet<(SchemaType, String, PublicKey, Vec<WitnessesType>)>,

        new_witnesses: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
        remove_witnesses: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
    },
    UpdateCreatorsWitnessesConfirm {
        version: u64,
        remove_creator: HashSet<(SchemaType, String, PublicKey)>,
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
    CurrentWitnessSubjects {
        governance_version: u64,
        items: Vec<CurrentWitnessSubject>,
        next_cursor: Option<DigestIdentifier>,
    },
    Ok,
}

impl Response for WitnessesRegisterResponse {}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentWitnessSubject {
    pub subject_id: DigestIdentifier,
    pub target_sn: u64,
}

impl WitnessesRegister {
    async fn get_sn(
        &self,
        ctx: &ActorContext<Self>,
        subject_id: DigestIdentifier,
        gov_version: u64,
    ) -> Result<SnLimit, ActorError> {
        let governance_id = ctx.path().parent().key();

        let path = ActorPath::from(format!(
            "/user/node/subject_manager/{}/sn_register",
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
                if namespace.is_ancestor_or_equal_of(parse_namespace) {
                    for range in data.interval_gov_version.iter().rev() {
                        if let Some(actual_lo) = actual_lo
                            && *actual_lo <= range.hi
                        {
                            better_sn = better_sn.max(Some(data.sn));

                            break 'witness;
                        }

                        if let Some(gov_version) =
                            interval.max_covered_in(range.lo, range.hi)
                        {
                            better_gov_version =
                                better_gov_version.max(Some(gov_version));

                            break;
                        }
                    }
                }
            }
        }

        (better_gov_version, better_sn)
    }

    async fn search_in_schema_actual(
        witness_data: &HashMap<Namespace, (IntervalSet, Option<u64>)>,
        parse_namespace: &Namespace,
        gov_version: u64,
        sn: u64,
        mut better_gov_version: Option<u64>,
    ) -> ActualSearch {
        for (namespace, (interval, actual_lo)) in witness_data.iter() {
            if namespace.is_ancestor_or_equal_of(parse_namespace) {
                // Actualmente soy testigo del owner
                if actual_lo.is_some() {
                    return ActualSearch::End(SnLimit::Sn(sn));
                }

                if let Some(range) = interval.iter().last()
                    && gov_version <= range.hi
                {
                    // range.hi es la máxima gov_version que puede acceder, hay que pedir cual es ese sn.
                    better_gov_version = better_gov_version.max(Some(range.hi));
                }
            }
        }

        ActualSearch::Continue {
            gov_version: better_gov_version,
        }
    }

    /// Busca en los testigos de schema para ambos tipos (específico y TrackerSchemas) usando search_in_schema_actual
    async fn search_schemas_actual(
        &self,
        node: &PublicKey,
        schema_id: &SchemaType,
        parse_namespace: &Namespace,
        gov_version: u64,
        sn: u64,
        better_gov_version: Option<u64>,
    ) -> ActualSearch {
        // el esquema específico
        let better_gov_version = if let Some(witness_data) =
            self.witnesses.get(&(node.clone(), schema_id.clone()))
        {
            match Self::search_in_schema_actual(
                witness_data,
                parse_namespace,
                gov_version,
                sn,
                better_gov_version,
            )
            .await
            {
                ActualSearch::End(sn_limit) => {
                    return ActualSearch::End(sn_limit);
                }
                ActualSearch::Continue { gov_version } => gov_version,
            }
        } else {
            better_gov_version
        };

        // todos los esquemas
        if let Some(witness_data) = self
            .witnesses
            .get(&(node.clone(), SchemaType::TrackerSchemas))
        {
            return Self::search_in_schema_actual(
                witness_data,
                parse_namespace,
                gov_version,
                sn,
                better_gov_version,
            )
            .await;
        }

        ActualSearch::Continue {
            gov_version: better_gov_version,
        }
    }

    /// Busca en los testigos de schema para ambos tipos (específico y TrackerSchemas) usando search_in_schema para old owners
    fn search_schemas_old(
        &self,
        node: &PublicKey,
        schema_id: &SchemaType,
        parse_namespace: &Namespace,
        data: &OldOwnerData,
        better_gov_version: Option<u64>,
        better_sn: Option<u64>,
    ) -> (Option<u64>, Option<u64>) {
        // el esquema específico
        let (better_gov_version, better_sn) = self
            .witnesses
            .get(&(node.clone(), schema_id.clone()))
            .map_or((better_gov_version, better_sn), |witness_data| {
                Self::search_in_schema(
                    witness_data,
                    parse_namespace,
                    data,
                    better_gov_version,
                    better_sn,
                )
            });

        // todos los esquemas
        if let Some(witness_data) = self
            .witnesses
            .get(&(node.clone(), SchemaType::TrackerSchemas))
        {
            return Self::search_in_schema(
                witness_data,
                parse_namespace,
                data,
                better_gov_version,
                better_sn,
            );
        }

        (better_gov_version, better_sn)
    }

    /// Busca testigos para un owner actual (actual_owner o new_owner en transferencia)
    async fn check_current_owner(
        &self,
        witnesses_creator: &HashMap<WitnessesType, (IntervalSet, Option<u64>)>,
        node: &PublicKey,
        schema_id: &SchemaType,
        parse_namespace: &Namespace,
        sn: u64,
        owner_better_gov_version: (u64, Option<u64>),
    ) -> ActualSearch {
        let (owner_gov_version, mut better_gov_version) =
            owner_better_gov_version;

        // Si el nodo es testigo explicito
        if let Some((interval, actual_lo)) =
            witnesses_creator.get(&WitnessesType::User(node.clone()))
        {
            // Actualmente soy testigo del owner
            if actual_lo.is_some() {
                return ActualSearch::End(SnLimit::Sn(sn));
            }
            // Ya no soy testigo del owner, mira mi último intervalo, si era testigo cuando él empezó
            // a ser owner puedo recibir la copia hasta que dejé de ser testigo, mi rango.hi
            if let Some(range) = interval.iter().last()
                && owner_gov_version <= range.hi
            {
                // range.hi es la máxima gov_version que puede acceder, hay que pedir cual es ese sn.
                better_gov_version = better_gov_version.max(Some(range.hi));
            }
        }

        // Solo delegar a los testigos de schema si el rol Witnesses estaba activo
        // cuando el owner empezó a serlo (actual_lo activo, o intervalo cerrado que llega
        // hasta owner_gov_version). Si el intervalo cerró antes de que el owner empezase,
        // contains_key sería true pero no debe triggear search_schemas_actual.
        if let Some((interval, actual_lo)) =
            witnesses_creator.get(&WitnessesType::Witnesses)
        {
            let witnesses_active = actual_lo.is_some()
                || interval
                    .iter()
                    .last()
                    .is_some_and(|range| owner_gov_version <= range.hi);

            if witnesses_active {
                return self
                    .search_schemas_actual(
                        node,
                        schema_id,
                        parse_namespace,
                        owner_gov_version,
                        sn,
                        better_gov_version,
                    )
                    .await;
            }
        }

        ActualSearch::Continue {
            gov_version: better_gov_version,
        }
    }

    async fn search_witnesses(
        &self,
        ctx: &ActorContext<Self>,
        node: &PublicKey,
        data: &TransferData,
        namespace: String,
        schema_id: SchemaType,
        subject_id: DigestIdentifier,
    ) -> Result<SnLimit, ActorError> {
        let mut better_gov_version: Option<u64> = None;
        let mut better_sn: Option<u64> = None;
        let parse_namespace = Namespace::from(namespace.clone());

        // Obtengo los testigos del owner
        if let Some(witnesses_creator) = self.witnesses_creator.get(&(
            data.actual_owner.to_owned(),
            namespace.clone(),
            schema_id.clone(),
        )) {
            match self
                .check_current_owner(
                    witnesses_creator,
                    node,
                    &schema_id,
                    &parse_namespace,
                    data.sn,
                    (data.gov_version, better_gov_version),
                )
                .await
            {
                ActualSearch::End(sn_limit) => return Ok(sn_limit),
                ActualSearch::Continue { gov_version } => {
                    better_gov_version = gov_version;
                }
            }
        }

        if let Some((new_owner, new_owner_gov_version)) =
            &data.actual_new_owner_data
            && let Some(witnesses_creator) = self.witnesses_creator.get(&(
                new_owner.to_owned(),
                namespace.clone(),
                schema_id.clone(),
            ))
        {
            match self
                .check_current_owner(
                    witnesses_creator,
                    node,
                    &schema_id,
                    &parse_namespace,
                    data.sn,
                    (*new_owner_gov_version, better_gov_version),
                )
                .await
            {
                ActualSearch::End(sn_limit) => return Ok(sn_limit),
                ActualSearch::Continue { gov_version } => {
                    better_gov_version = gov_version;
                }
            }
        }

        // Not_owners
        for (creator, old_data) in data.old_owners.iter() {
            if let Some(witnesses_creator) = self.witnesses_creator.get(&(
                creator.to_owned(),
                namespace.clone(),
                schema_id.clone(),
            )) {
                if let Some((interval, actual_lo)) =
                    witnesses_creator.get(&WitnessesType::User(node.clone()))
                {
                    // Si es testigo explicito
                    for range in old_data.interval_gov_version.iter().rev() {
                        // Sigue siendo testigo.
                        if let Some(actual_lo) = actual_lo
                            && *actual_lo <= range.hi
                        {
                            better_sn = better_sn.max(Some(old_data.sn));

                            break;
                        }

                        if let Some(gov_version) =
                            interval.max_covered_in(range.lo, range.hi)
                        {
                            better_gov_version =
                                better_gov_version.max(Some(gov_version));

                            break;
                        }
                    }
                }

                // Witness de schema.
                if witnesses_creator.contains_key(&WitnessesType::Witnesses) {
                    // ha tenido el rol de testigo.
                    let (bgv, bs) = self.search_schemas_old(
                        node,
                        &schema_id,
                        &parse_namespace,
                        old_data,
                        better_gov_version,
                        better_sn,
                    );
                    better_gov_version = bgv;
                    better_sn = bs;
                }
            }
        }

        let sn_limit = if let Some(gov_version) = better_gov_version {
            match self.get_sn(ctx, subject_id, gov_version).await? {
                SnLimit::Sn(sn) => better_sn
                    .map_or(SnLimit::Sn(sn), |better_sn| {
                        SnLimit::Sn(sn.max(better_sn))
                    }),
                SnLimit::LastSn => SnLimit::Sn(data.sn),
                SnLimit::NotSn => better_sn.map_or(SnLimit::NotSn, SnLimit::Sn),
            }
        } else if let Some(better_sn) = better_sn {
            SnLimit::Sn(better_sn)
        } else {
            SnLimit::NotSn
        };

        Ok(sn_limit)
    }

    fn has_active_schema_witness(
        &self,
        node: &PublicKey,
        schema_id: &SchemaType,
        namespace: &Namespace,
    ) -> bool {
        let has_match = |witness_data: &HashMap<Namespace, IntervalData>| {
            witness_data.iter().any(|(current_namespace, (_, current_lo))| {
                current_lo.is_some()
                    && current_namespace.is_ancestor_or_equal_of(namespace)
            })
        };

        self.witnesses
            .get(&(node.clone(), schema_id.clone()))
            .is_some_and(has_match)
            || self
                .witnesses
                .get(&(node.clone(), SchemaType::TrackerSchemas))
                .is_some_and(has_match)
    }

    fn is_current_witness_for_entry(
        &self,
        node: &PublicKey,
        schema_id: &SchemaType,
        namespace: &str,
        creator_witnesses: &HashMap<WitnessesType, IntervalData>,
    ) -> bool {
        if creator_witnesses
            .get(&WitnessesType::User(node.clone()))
            .is_some_and(|(_, current_lo)| current_lo.is_some())
        {
            return true;
        }

        if !creator_witnesses
            .get(&WitnessesType::Witnesses)
            .is_some_and(|(_, current_lo)| current_lo.is_some())
        {
            return false;
        }

        self.has_active_schema_witness(
            node,
            schema_id,
            &Namespace::from(namespace.to_owned()),
        )
    }

    async fn get_subjects_for_owner_schema(
        &self,
        ctx: &ActorContext<Self>,
        owner: &PublicKey,
        schema_id: &SchemaType,
        namespace: &str,
    ) -> Result<Vec<DigestIdentifier>, ActorError> {
        let governance_id = ctx.path().parent().key();
        let path = ActorPath::from(format!(
            "/user/node/subject_manager/{}/subject_register",
            governance_id
        ));
        let actor = ctx.system().get_actor::<SubjectRegister>(&path).await?;
        let response = actor
            .ask(SubjectRegisterMessage::GetSubjectsByOwnerSchema {
                owner: owner.clone(),
                schema_id: schema_id.clone(),
                namespace: namespace.to_owned(),
            })
            .await?;

        match response {
            SubjectRegisterResponse::Subjects(subjects) => Ok(subjects),
            _ => Err(ActorError::UnexpectedResponse {
                path,
                expected: "SubjectRegisterResponse::Subjects".to_owned(),
            }),
        }
    }

    async fn list_current_witness_subjects(
        &self,
        ctx: &ActorContext<Self>,
        node: &PublicKey,
        governance_version: u64,
        after_subject_id: Option<DigestIdentifier>,
        limit: usize,
    ) -> Result<(Vec<CurrentWitnessSubject>, Option<DigestIdentifier>), ActorError>
    {
        let mut subjects = BTreeMap::new();

        for ((creator, namespace, schema_id), creator_witnesses) in
            &self.witnesses_creator
        {
            if !self.is_current_witness_for_entry(
                node,
                schema_id,
                namespace,
                creator_witnesses,
            ) {
                continue;
            }

            let current_subjects = self
                .get_subjects_for_owner_schema(
                    ctx,
                    creator,
                    schema_id,
                    namespace,
                )
                .await?;

            for subject_id in current_subjects {
                if let Some(data) = self.subjects.get(&subject_id) {
                    subjects.insert(subject_id, data.sn);
                }
            }
        }

        let limit = limit.max(1);
        let mut items = Vec::with_capacity(limit + 1);
        let effective_cursor = if governance_version == self.gov_sn {
            after_subject_id
        } else {
            None
        };

        for (subject_id, target_sn) in subjects {
            if effective_cursor
                .as_ref()
                .is_some_and(|cursor| &subject_id <= cursor)
            {
                continue;
            }

            items.push(CurrentWitnessSubject {
                subject_id,
                target_sn,
            });

            if items.len() > limit {
                break;
            }
        }

        let next_cursor = if items.len() > limit {
            let extra = items.pop();
            let _ = extra;
            items.last().map(|item| item.subject_id.clone())
        } else {
            None
        };

        Ok((items, next_cursor))
    }
}

#[async_trait]
impl Actor for WitnessesRegister {
    type Event = WitnessesRegisterEvent;
    type Message = WitnessesRegisterMessage;
    type Response = WitnessesRegisterResponse;

    fn get_span(_id: &str, parent_span: Option<Span>) -> tracing::Span {
        parent_span.map_or_else(
            || info_span!("WitnessesRegister"),
            |parent_span| info_span!(parent: parent_span, "WitnessesRegister"),
        )
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
}

#[async_trait]
impl Handler<Self> for WitnessesRegister {
    async fn handle_message(
        &mut self,
        _sender: ActorPath,
        msg: WitnessesRegisterMessage,
        ctx: &mut ActorContext<Self>,
    ) -> Result<WitnessesRegisterResponse, ActorError> {
        match msg {
            WitnessesRegisterMessage::ListCurrentWitnessSubjects {
                node,
                governance_version,
                after_subject_id,
                limit,
            } => {
                let (items, next_cursor) = self
                    .list_current_witness_subjects(
                        ctx,
                        &node,
                        governance_version,
                        after_subject_id,
                        limit,
                    )
                    .await?;

                return Ok(
                    WitnessesRegisterResponse::CurrentWitnessSubjects {
                        governance_version: self.gov_sn,
                        items,
                        next_cursor,
                    },
                );
            }
            WitnessesRegisterMessage::GetTrackerSnCreator { subject_id } => {
                let data = self
                    .subjects
                    .get(&subject_id)
                    .map(|data| (data.actual_owner.clone(), data.sn));

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
                return Ok(WitnessesRegisterResponse::GovSn {
                    sn: self.gov_sn,
                });
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
            WitnessesRegisterMessage::UpdateCreatorsWitnessesConfirm {
                version,
                remove_creator,
                remove_witnesses,
            } => {
                let remove_creator_count = remove_creator.len();
                let remove_witnesses_count = remove_witnesses.len();
                self.on_event(
                    WitnessesRegisterEvent::UpdateCreatorsWitnessesConfirm {
                        version,
                        remove_creator,
                        remove_witnesses,
                    },
                    ctx,
                )
                .await;

                debug!(
                    msg_type = "UpdateCreatorsWitnessesConfirm",
                    version = version,
                    remove_creator_count = remove_creator_count,
                    remove_witnesses_count = remove_witnesses_count,
                    "Creators and witnesses confirm updated"
                );
            }
            WitnessesRegisterMessage::UpdateCreatorsWitnessesFact {
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
                    WitnessesRegisterEvent::UpdateCreatorsWitnessesFact {
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
                    msg_type = "UpdateCreatorsWitnessesFact",
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
                    gov_version = gov_version,
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
                    gov_version = gov_version,
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
                    gov_version = gov_version,
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
                    gov_version = gov_version,
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
                    // Owner
                    if data.actual_owner == node {
                        Some(data.sn)
                        // New owner
                    } else if let Some((new_owner, ..)) =
                        &data.actual_new_owner_data
                        && new_owner == &node
                    {
                        Some(data.sn)
                        // old owner
                    } else if let Some(old_data) = data.old_owners.get(&node) {
                        let sn_limit = self
                            .search_witnesses(
                                ctx,
                                &node,
                                data,
                                namespace.clone(),
                                schema_id.clone(),
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
                        // witness
                        let sn_limit = self
                            .search_witnesses(
                                ctx,
                                &node,
                                data,
                                namespace.clone(),
                                schema_id.clone(),
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
                    namespace = %namespace,
                    schema_id = %schema_id,
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
        ctx: &mut ActorContext<Self>,
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
            WitnessesRegisterEvent::UpdateCreatorsWitnessesConfirm {
                version,
                remove_creator,
                remove_witnesses,
            } => {
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
                                    hi: *version - 1,
                                });
                            }
                        }
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
                                && let Some(last) = last.take()
                            {
                                interval.insert(Interval {
                                    lo: last,
                                    hi: *version - 1,
                                });
                            }
                        }
                    }
                }

                debug!(
                    event_type = "UpdateCreatorsWitnessesConfirm",
                    version = version,
                    remove_witnesses_count = remove_witnesses.len(),
                    remove_creator_count = remove_creator.len(),
                    "Creators and witnesses updated in state"
                );
            }
            WitnessesRegisterEvent::UpdateCreatorsWitnessesFact {
                version,
                new_creator,
                remove_creator,
                update_creator_witnesses,
                new_witnesses,
                remove_witnesses,
            } => {
                for ((schema_id, ns, creator), witnesses) in new_creator.iter()
                {
                    // Crear la entrada aunque witnesses esté vacío, para que
                    // futuros "change" con update_creator_witnesses puedan
                    // encontrarla con get_mut.
                    let creator_entry = self
                        .witnesses_creator
                        .entry((creator.clone(), ns.clone(), schema_id.clone()))
                        .or_default();
                    for witness in witnesses.iter() {
                        creator_entry.entry(witness.clone()).or_default().1 =
                            Some(*version);
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
                                    hi: *version - 1,
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
                        // Cerrar testigos que ya no están en la nueva lista
                        for (witness_type, (interval, last)) in
                            creator_witnesses.iter_mut()
                        {
                            if !witnesses.contains(witness_type)
                                && let Some(lo) = last.take()
                            {
                                interval.insert(Interval {
                                    lo,
                                    hi: *version - 1,
                                });
                            }
                        }
                        // Añadir o reactivar testigos en la nueva lista
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
                                && let Some(last) = last.take()
                            {
                                interval.insert(Interval {
                                    lo: last,
                                    hi: *version - 1,
                                });
                            }
                        }
                    }
                }

                debug!(
                    event_type = "UpdateCreatorsWitnessesFact",
                    version = version,
                    remove_creator_count = remove_creator.len(),
                    update_creator_witnesses_count =
                        update_creator_witnesses.len(),
                    new_witnesses_count = new_witnesses.len(),
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
                    gov_version = gov_version,
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
                        gov_version = gov_version,
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
                            gov_version = gov_version,
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

                    if let Some((new_owner, new_owner_gov_version)) = new_owner
                    {
                        let entry =
                            data.old_owners.entry(new_owner).or_default();
                        entry.sn = *sn;
                        entry.interval_gov_version.insert(Interval {
                            lo: new_owner_gov_version,
                            hi: *gov_version,
                        });

                        debug!(
                            event_type = "Reject",
                            subject_id = %subject_id,
                            sn = sn,
                            gov_version = gov_version,
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
