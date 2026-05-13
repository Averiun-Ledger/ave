use std::collections::{BTreeSet, HashMap, HashSet};

use crate::governance::sn_register::{
    SnLimit, SnRegister, SnRegisterMessage, SnRegisterResponse,
};

use crate::model::common::{
    Interval, IntervalSet, TrackerEventVisibility, TrackerStoredVisibility,
    TrackerVisibilityMode, TrackerVisibilityState, emit_fail, purge_storage,
};
use crate::model::event::Ledger;
use async_trait::async_trait;
use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, Event, Handler, Message,
    Response,
};
use ave_actors::{LightPersistence, PersistentActor};
use ave_common::identity::{DigestIdentifier, PublicKey};
use ave_common::request::EventRequest;
use ave_common::{Namespace, SchemaType};
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use tracing::{Span, debug, error, info_span, warn};

use crate::db::Storable;

mod access_engine;
mod subject_ownership;
mod sync_support;
mod witness_policy;

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
    pub(crate) gov_sn: u64,
    pub(crate) subjects: HashMap<DigestIdentifier, TransferData>,
    pub(crate) witnesses:
        HashMap<(PublicKey, SchemaType), HashMap<Namespace, IntervalData>>,
    pub(crate) witnesses_creator: HashMap<
        (PublicKey, String, SchemaType),
        HashMap<WitnessesType, IntervalData>,
    >,
    pub(crate) witnesses_creator_grants: HashMap<
        (PublicKey, String, SchemaType),
        HashMap<WitnessesType, CreatorWitnessGrantHistory>,
    >,
    #[serde(skip)]
    pub(crate) ledger_batch_size: usize,
}

pub type IntervalData = (IntervalSet, Option<u64>);

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
    BorshDeserialize,
    BorshSerialize,
    Hash,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
)]
pub enum CreatorWitnessGrant {
    Hash,
    Clear(BTreeSet<String>),
    Full,
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
pub struct CreatorWitnessRegistration {
    pub witnesses: Vec<WitnessesType>,
    pub grants: Vec<(WitnessesType, CreatorWitnessGrant)>,
}

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub struct CreatorWitnessGrantRange {
    pub interval: Interval,
    pub grant: CreatorWitnessGrant,
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
pub struct CreatorWitnessGrantHistory {
    pub closed: Vec<CreatorWitnessGrantRange>,
    pub current_from: Option<u64>,
    pub current_grant: Option<CreatorWitnessGrant>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TrackerDeliveryMode {
    Clear,
    Opaque,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrackerDeliveryRange {
    pub from_sn: u64,
    pub to_sn: u64,
    pub mode: TrackerDeliveryMode,
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
    pub(crate) actual_owner: PublicKey,
    pub(crate) actual_new_owner_data: Option<(PublicKey, u64)>,
    pub(crate) sn: u64,
    pub(crate) gov_version: u64,
    pub(crate) old_owners: HashMap<PublicKey, OldOwnerData>,
    pub(crate) visibility_state: TrackerVisibilityState,
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
    pub(crate) sn: u64,
    pub(crate) interval_gov_version: IntervalSet,
}

#[derive(Debug, Clone)]
pub enum WitnessesRegisterMessage {
    PurgeStorage,
    GetSnGov,
    GetTrackerSnOwner {
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
        new_creator: HashMap<
            (SchemaType, String, PublicKey),
            CreatorWitnessRegistration,
        >,
        remove_creator: HashSet<(SchemaType, String, PublicKey)>,
        update_creator_witnesses: HashMap<
            (SchemaType, String, PublicKey),
            CreatorWitnessRegistration,
        >,

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
    DeleteSubject {
        subject_id: DigestIdentifier,
    },
    UpdateTrackerVisibility {
        subject_id: DigestIdentifier,
        sn: u64,
        mode: TrackerVisibilityMode,
        stored_visibility: TrackerStoredVisibility,
        event_visibility: TrackerEventVisibility,
    },
    Reject {
        subject_id: DigestIdentifier,
        sn: u64,
        gov_version: u64,
    },
    GetTrackerVisibilityState {
        subject_id: DigestIdentifier,
    },
    GetTrackerWindow {
        subject_id: DigestIdentifier,
        node: PublicKey,
        sender: PublicKey,
        namespace: String,
        schema_id: SchemaType,
        actual_sn: Option<u64>,
    },
    GetTrackerWindowFromLedger {
        subject_id: DigestIdentifier,
        ledger: Vec<Ledger>,
        node: PublicKey,
        sender: PublicKey,
        namespace: String,
        schema_id: SchemaType,
        actual_sn: Option<u64>,
    },
    SimulateTransferHiSnLimit {
        subject_id: DigestIdentifier,
        transfer_event: Ledger,
        node: PublicKey,
        namespace: String,
        schema_id: SchemaType,
    },
    QueryWitnessStatus {
        subject_id: Option<DigestIdentifier>,
        node: PublicKey,
        namespace: String,
        schema_id: SchemaType,
        owner: Option<PublicKey>,
        owner_gov_version: Option<u64>,
    },
}

impl Message for WitnessesRegisterMessage {
    fn is_critical(&self) -> bool {
        matches!(
            self,
            Self::PurgeStorage
                | Self::UpdateCreatorsWitnessesFact { .. }
                | Self::UpdateCreatorsWitnessesConfirm { .. }
                | Self::UpdateSn { .. }
                | Self::UpdateSnGov { .. }
                | Self::Create { .. }
                | Self::Transfer { .. }
                | Self::Confirm { .. }
                | Self::UpdateTrackerVisibility { .. }
                | Self::DeleteSubject { .. }
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
        new_creator: HashMap<
            (SchemaType, String, PublicKey),
            CreatorWitnessRegistration,
        >,
        remove_creator: HashSet<(SchemaType, String, PublicKey)>,
        update_creator_witnesses: HashMap<
            (SchemaType, String, PublicKey),
            CreatorWitnessRegistration,
        >,

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
    DeleteSubject {
        subject_id: DigestIdentifier,
    },
    UpdateTrackerVisibility {
        subject_id: DigestIdentifier,
        sn: u64,
        mode: TrackerVisibilityMode,
        stored_visibility: TrackerStoredVisibility,
        event_visibility: TrackerEventVisibility,
    },
    Reject {
        subject_id: DigestIdentifier,
        sn: u64,
        gov_version: u64,
    },
}

impl Event for WitnessesRegisterEvent {}

pub enum WitnessesRegisterResponse {
    GovSn {
        sn: u64,
    },
    TrackerOwnerSn {
        data: Option<(PublicKey, u64)>,
    },
    CurrentWitnessSubjects {
        governance_version: u64,
        items: Vec<CurrentWitnessSubject>,
        next_cursor: Option<DigestIdentifier>,
    },
    TrackerVisibilityState {
        state: TrackerVisibilityState,
    },
    TrackerWindow {
        sn: Option<u64>,
        transfer_sn: Option<u64>,
        clear_sn: Option<u64>,
        is_all: bool,
        ranges: Vec<TrackerDeliveryRange>,
    },
    WitnessStatus(WitnessStatus),
    Ok,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WitnessStatus {
    pub access_sn: Option<u64>,
    pub hi_sn_limit: HiSnLimit,
    pub gov_version_limit: GovVersionLimit,
    pub create_access: bool,
    pub create_gov_version_limit: GovVersionLimit,
}

impl Response for WitnessesRegisterResponse {}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum HiSnLimit {
    None,
    Sn(u64),
    Infinity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum GovVersionLimit {
    None,
    Version(u64),
    Infinity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CurrentWitnessSubject {
    pub subject_id: DigestIdentifier,
    pub target_sn: u64,
}

impl CreatorWitnessGrantHistory {
    pub(crate) fn apply_version(
        &mut self,
        version: u64,
        grant: Option<CreatorWitnessGrant>,
    ) {
        match (&self.current_from, &self.current_grant, &grant) {
            (Some(current_from), Some(current_grant), Some(next_grant))
                if current_grant != next_grant =>
            {
                self.closed.push(CreatorWitnessGrantRange {
                    interval: Interval::new(*current_from, version - 1),
                    grant: current_grant.clone(),
                });
                self.current_from = Some(version);
                self.current_grant = Some(next_grant.clone());
            }
            (Some(_), Some(_), Some(_)) => {}
            (Some(current_from), Some(current_grant), None) => {
                self.closed.push(CreatorWitnessGrantRange {
                    interval: Interval::new(*current_from, version - 1),
                    grant: current_grant.clone(),
                });
                self.current_from = None;
                self.current_grant = None;
            }
            (None, None, Some(next_grant)) => {
                self.current_from = Some(version);
                self.current_grant = Some(next_grant.clone());
            }
            _ => {}
        }
    }
}

impl WitnessesRegister {
    fn merge_grant(
        actual: Option<CreatorWitnessGrant>,
        next: &CreatorWitnessGrant,
    ) -> CreatorWitnessGrant {
        match (actual, next) {
            (Some(CreatorWitnessGrant::Full), ..)
            | (_, CreatorWitnessGrant::Full) => CreatorWitnessGrant::Full,
            (
                Some(CreatorWitnessGrant::Clear(mut left)),
                CreatorWitnessGrant::Clear(right),
            ) => {
                left.extend(right.iter().cloned());
                CreatorWitnessGrant::Clear(left)
            }
            (
                Some(CreatorWitnessGrant::Clear(left)),
                CreatorWitnessGrant::Hash,
            ) => CreatorWitnessGrant::Clear(left),
            (
                Some(CreatorWitnessGrant::Hash),
                CreatorWitnessGrant::Clear(right),
            ) => CreatorWitnessGrant::Clear(right.clone()),
            (Some(CreatorWitnessGrant::Hash), CreatorWitnessGrant::Hash)
            | (None, CreatorWitnessGrant::Hash) => CreatorWitnessGrant::Hash,
            (None, CreatorWitnessGrant::Clear(right)) => {
                CreatorWitnessGrant::Clear(right.clone())
            }
        }
    }

    fn interval_overlaps_owner(
        current_from: Option<u64>,
        intervals: &IntervalSet,
        owner_lo: u64,
        owner_hi: u64,
    ) -> bool {
        current_from.is_some_and(|from| from <= owner_hi)
            || intervals.max_covered_in(owner_lo, owner_hi).is_some()
    }

    fn covered_old_owner_intervals(
        current_from: Option<u64>,
        intervals: &IntervalSet,
        old_owner: &OldOwnerData,
    ) -> IntervalSet {
        let mut covered = IntervalSet::new();

        for owner_range in old_owner.interval_gov_version.iter() {
            if let Some(from) = current_from {
                let lo = from.max(owner_range.lo);
                if lo <= owner_range.hi {
                    covered.insert(Interval {
                        lo,
                        hi: owner_range.hi,
                    });
                }
            }

            for witness_range in intervals.iter() {
                let lo = witness_range.lo.max(owner_range.lo);
                let hi = witness_range.hi.min(owner_range.hi);

                if lo <= hi {
                    covered.insert(Interval { lo, hi });
                }
            }
        }

        covered
    }

    fn max_covered_old_owner_gov_version(
        current_from: Option<u64>,
        intervals: &IntervalSet,
        old_owner: &OldOwnerData,
    ) -> Option<u64> {
        Self::covered_old_owner_intervals(current_from, intervals, old_owner)
            .iter()
            .last()
            .map(|range| range.hi)
    }

    fn grant_for_owner_interval(
        history: &CreatorWitnessGrantHistory,
        owner_lo: u64,
        owner_hi: u64,
    ) -> Option<&CreatorWitnessGrant> {
        if let (Some(current_from), Some(current_grant)) =
            (history.current_from, history.current_grant.as_ref())
            && current_from <= owner_hi
        {
            return Some(current_grant);
        }

        history
            .closed
            .iter()
            .rev()
            .find(|range| {
                range.interval.lo <= owner_hi && range.interval.hi >= owner_lo
            })
            .map(|range| &range.grant)
    }

    fn schema_witness_covers_owner_interval(
        &self,
        node: &PublicKey,
        schema_id: &SchemaType,
        namespace: &Namespace,
        owner_lo: u64,
        owner_hi: u64,
    ) -> bool {
        let matches = |witness_data: &HashMap<Namespace, IntervalData>| {
            witness_data.iter().any(
                |(current_namespace, (intervals, current_from))| {
                    current_namespace.is_ancestor_or_equal_of(namespace)
                        && Self::interval_overlaps_owner(
                            *current_from,
                            intervals,
                            owner_lo,
                            owner_hi,
                        )
                },
            )
        };

        self.witnesses
            .get(&(node.clone(), schema_id.clone()))
            .is_some_and(matches)
            || self
                .witnesses
                .get(&(node.clone(), SchemaType::TrackerSchemas))
                .is_some_and(matches)
    }

    fn creator_grant_for_owner_interval(
        &self,
        node: &PublicKey,
        creator: &PublicKey,
        schema_id: &SchemaType,
        namespace: &Namespace,
        owner_lo: u64,
        owner_hi: u64,
    ) -> Option<CreatorWitnessGrant> {
        let grants = self.witnesses_creator_grants.get(&(
            creator.clone(),
            namespace.to_string(),
            schema_id.clone(),
        ))?;
        let intervals = self.witnesses_creator.get(&(
            creator.clone(),
            namespace.to_string(),
            schema_id.clone(),
        ))?;

        let mut out = None;

        if let (Some(history), Some((creator_intervals, creator_current_from))) = (
            grants.get(&WitnessesType::User(node.clone())),
            intervals.get(&WitnessesType::User(node.clone())),
        ) && Self::interval_overlaps_owner(
            *creator_current_from,
            creator_intervals,
            owner_lo,
            owner_hi,
        ) && let Some(grant) =
            Self::grant_for_owner_interval(history, owner_lo, owner_hi)
        {
            out = Some(Self::merge_grant(out, grant));
        }

        if let (Some(history), Some((creator_intervals, creator_current_from))) = (
            grants.get(&WitnessesType::Witnesses),
            intervals.get(&WitnessesType::Witnesses),
        ) && Self::interval_overlaps_owner(
            *creator_current_from,
            creator_intervals,
            owner_lo,
            owner_hi,
        ) && self.schema_witness_covers_owner_interval(
            node, schema_id, namespace, owner_lo, owner_hi,
        ) && let Some(grant) =
            Self::grant_for_owner_interval(history, owner_lo, owner_hi)
        {
            out = Some(Self::merge_grant(out, grant));
        }

        out
    }

    fn creator_grant_for_event_or_current_owner(
        &self,
        node: &PublicKey,
        creator: &PublicKey,
        schema_id: &SchemaType,
        namespace: &Namespace,
        event_gov_version: u64,
        owner_from_gov_version: u64,
    ) -> Option<CreatorWitnessGrant> {
        self.creator_grant_for_owner_interval(
            node,
            creator,
            schema_id,
            namespace,
            event_gov_version,
            event_gov_version,
        )
        .or_else(|| {
            self.creator_grant_for_owner_interval(
                node,
                creator,
                schema_id,
                namespace,
                owner_from_gov_version,
                u64::MAX,
            )
        })
    }

    fn grant_allows_clear(
        grant: Option<CreatorWitnessGrant>,
        viewpoints: &BTreeSet<String>,
    ) -> bool {
        match grant {
            Some(CreatorWitnessGrant::Full) => true,
            Some(CreatorWitnessGrant::Clear(allowed)) => {
                viewpoints.is_empty() || viewpoints.is_subset(&allowed)
            }
            Some(CreatorWitnessGrant::Hash) | None => false,
        }
    }

    async fn get_gov_version_window(
        &self,
        ctx: &ActorContext<Self>,
        subject_id: &DigestIdentifier,
        from_sn: u64,
        to_sn: u64,
    ) -> Result<Vec<(Interval, u64)>, ActorError> {
        let governance_id = ctx.path().parent().key();
        let path = ActorPath::from(format!(
            "/user/node/subject_manager/{}/sn_register",
            governance_id
        ));
        let sn_register = ctx.system().get_actor::<SnRegister>(&path).await?;
        let response = sn_register
            .ask(SnRegisterMessage::GetGovVersionWindow {
                subject_id: subject_id.clone(),
                from_sn,
                to_sn,
            })
            .await?;

        match response {
            SnRegisterResponse::GovVersionWindow(ranges) => Ok(ranges
                .into_iter()
                .map(|range| {
                    (
                        Interval::new(range.from_sn, range.to_sn),
                        range.gov_version,
                    )
                })
                .collect()),
            _ => Err(ActorError::UnexpectedResponse {
                path,
                expected: "SnRegisterResponse::GovVersionWindow".to_owned(),
            }),
        }
    }

    fn gov_version_for_sn(
        gov_versions: &[(Interval, u64)],
        sn: u64,
    ) -> Option<u64> {
        gov_versions
            .iter()
            .find(|(interval, _)| interval.contains(sn))
            .map(|(_, gov_version)| *gov_version)
    }

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
    ) -> Option<u64> {
        for (namespace, (interval, actual_lo)) in witness_data.iter() {
            if !namespace.is_ancestor_or_equal_of(parse_namespace) {
                continue;
            }

            if let Some(gov_version) = Self::max_covered_old_owner_gov_version(
                *actual_lo, interval, data,
            ) {
                better_gov_version = better_gov_version.max(Some(gov_version));
            }
        }

        better_gov_version
    }

    async fn search_in_schema_actual(
        witness_data: &HashMap<Namespace, (IntervalSet, Option<u64>)>,
        parse_namespace: &Namespace,
        gov_version: u64,
        _sn: u64,
        mut better_gov_version: Option<u64>,
    ) -> ActualSearch {
        for (namespace, (interval, actual_lo)) in witness_data.iter() {
            if namespace.is_ancestor_or_equal_of(parse_namespace) {
                // Actualmente soy testigo del owner
                if actual_lo.is_some() {
                    return ActualSearch::End(SnLimit::LastSn);
                }

                if let Some(range) = interval.iter().last()
                    && gov_version <= range.hi
                {
                    // range.hi es la máxima gov_version que puede acceder, hay que pedir cual es ese sn.
                    better_gov_version = better_gov_version.max(Some(range.hi));
                }
            } else {
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
    ) -> Option<u64> {
        // el esquema específico
        let better_gov_version = self
            .witnesses
            .get(&(node.clone(), schema_id.clone()))
            .map_or(better_gov_version, |witness_data| {
                Self::search_in_schema(
                    witness_data,
                    parse_namespace,
                    data,
                    better_gov_version,
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
            );
        }

        better_gov_version
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
                return ActualSearch::End(SnLimit::LastSn);
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

        // Si el rol Witnesses está activo actualmente, los testigos de schema pueden
        // pedir el tracker actual. Para intervalos cerrados sí hay que comprobar que
        // cubrieron el momento en que este owner pasó a ser owner.
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

    fn interval_active_at_version(
        current_from: Option<u64>,
        intervals: &IntervalSet,
        gov_version: u64,
    ) -> bool {
        current_from.is_some_and(|from| from <= gov_version)
            || intervals.contains(gov_version)
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
            WitnessesRegisterMessage::PurgeStorage => {
                purge_storage(ctx).await?;

                debug!(
                    msg_type = "PurgeStorage",
                    "Witnesses register storage purged"
                );

                return Ok(WitnessesRegisterResponse::Ok);
            }
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

                return Ok(WitnessesRegisterResponse::CurrentWitnessSubjects {
                    governance_version: self.gov_sn,
                    items,
                    next_cursor,
                });
            }
            WitnessesRegisterMessage::GetTrackerSnOwner { subject_id } => {
                let data = self
                    .subjects
                    .get(&subject_id)
                    .map(|data| (data.actual_owner.clone(), data.sn));

                debug!(
                    msg_type = "GetTrackerSnOwner",
                    subject_id = %subject_id,
                    found = data.is_some(),
                    "Tracker sn owner lookup completed"
                );

                return Ok(WitnessesRegisterResponse::TrackerOwnerSn { data });
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
            WitnessesRegisterMessage::UpdateTrackerVisibility {
                subject_id,
                sn,
                mode,
                stored_visibility,
                event_visibility,
            } => {
                self.on_event(
                    WitnessesRegisterEvent::UpdateTrackerVisibility {
                        subject_id: subject_id.clone(),
                        sn,
                        mode,
                        stored_visibility: stored_visibility.clone(),
                        event_visibility: event_visibility.clone(),
                    },
                    ctx,
                )
                .await;

                debug!(
                    msg_type = "UpdateTrackerVisibility",
                    subject_id = %subject_id,
                    sn = sn,
                    "Tracker visibility updated"
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
            WitnessesRegisterMessage::DeleteSubject { subject_id } => {
                self.on_event(
                    WitnessesRegisterEvent::DeleteSubject {
                        subject_id: subject_id.clone(),
                    },
                    ctx,
                )
                .await;

                debug!(
                    msg_type = "DeleteSubject",
                    subject_id = %subject_id,
                    "Witness subject entry deleted"
                );
            }
            WitnessesRegisterMessage::GetTrackerVisibilityState {
                subject_id,
            } => {
                let state = self
                    .subjects
                    .get(&subject_id)
                    .map(|data| data.visibility_state.clone())
                    .unwrap_or_default();

                return Ok(WitnessesRegisterResponse::TrackerVisibilityState {
                    state,
                });
            }
            WitnessesRegisterMessage::GetTrackerWindow {
                subject_id,
                node,
                sender,
                namespace,
                schema_id,
                actual_sn,
            } => {
                let (sn, transfer_sn, clear_sn, is_all, ranges) = self
                    .build_tracker_window(
                        ctx,
                        &subject_id,
                        &node,
                        &sender,
                        namespace,
                        schema_id,
                        actual_sn,
                    )
                    .await?;

                return Ok(WitnessesRegisterResponse::TrackerWindow {
                    sn,
                    transfer_sn,
                    clear_sn,
                    is_all,
                    ranges,
                });
            }
            WitnessesRegisterMessage::GetTrackerWindowFromLedger {
                subject_id,
                ledger,
                node,
                sender,
                namespace,
                schema_id,
                actual_sn,
            } => {
                let data =
                    Self::transfer_data_from_ledger(&subject_id, &ledger)?;
                let (sn, transfer_sn, clear_sn, is_all, ranges) = self
                    .build_tracker_window_from_data(
                        ctx,
                        &subject_id,
                        &data,
                        &node,
                        &sender,
                        namespace,
                        schema_id,
                        actual_sn,
                    )
                    .await?;

                return Ok(WitnessesRegisterResponse::TrackerWindow {
                    sn,
                    transfer_sn,
                    clear_sn,
                    is_all,
                    ranges,
                });
            }
            WitnessesRegisterMessage::SimulateTransferHiSnLimit {
                subject_id,
                transfer_event,
                node,
                namespace,
                schema_id,
            } => {
                let (new_owner, gov_version) =
                    match transfer_event.get_event_request() {
                        Some(EventRequest::Transfer(req)) => {
                            (req.new_owner, transfer_event.gov_version)
                        }
                        _ => {
                            return Err(ActorError::Functional {
                                description:
                                    "SimulateTransferHiSnLimit called with non-Transfer event"
                                        .to_string(),
                            });
                        }
                    };

                // Si ya tenemos TransferData para este subject (por gobernanza o
                // batches anteriores), lo usamos como base y solo actualizamos el
                // estado actual con el evento de transferencia. Así conservamos
                // el historial de old_owners que la simulación necesita.
                let mut data = if let Some(existing) = self.subjects.get(&subject_id) {
                    let mut data = existing.clone();
                    data.actual_owner = transfer_event.ledger_seal_signature.signer.clone();
                    data.actual_new_owner_data = Some((new_owner, gov_version));
                    data.sn = transfer_event.sn;
                    data.gov_version = gov_version;
                    data
                } else {
                    TransferData {
                        actual_owner: transfer_event.ledger_seal_signature.signer.clone(),
                        actual_new_owner_data: Some((new_owner, gov_version)),
                        sn: transfer_event.sn,
                        gov_version,
                        old_owners: HashMap::new(),
                        visibility_state: TrackerVisibilityState::default(),
                    }
                };
                data.visibility_state.record_event(
                    0,
                    TrackerStoredVisibility::Full,
                    TrackerEventVisibility::NonFact,
                );

                let limit = self
                    .hi_sn_limit_for_transfer_data(
                        ctx,
                        &subject_id,
                        &node,
                        &namespace,
                        &schema_id,
                        &data,
                    )
                    .await?;

                return Ok(WitnessesRegisterResponse::WitnessStatus(WitnessStatus {
                    access_sn: None,
                    hi_sn_limit: limit,
                    gov_version_limit: GovVersionLimit::None,
                    create_access: false,
                    create_gov_version_limit: GovVersionLimit::None,
                }));
            }
            WitnessesRegisterMessage::QueryWitnessStatus {
                subject_id,
                node,
                namespace,
                schema_id,
                owner,
                owner_gov_version,
            } => {
                let status = self
                    .query_witness_status(
                        ctx,
                        subject_id,
                        node,
                        namespace,
                        schema_id,
                        owner,
                        owner_gov_version,
                    )
                    .await?;

                return Ok(WitnessesRegisterResponse::WitnessStatus(status));
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
    type InitParams = usize;

    fn create_initial(params: Self::InitParams) -> Self {
        Self {
            ledger_batch_size: params,
            ..Self::default()
        }
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
                    self.close_creator_registration(
                        schema_id, ns, creator, *version,
                    );
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
                for ((schema_id, ns, creator), registration) in
                    new_creator.iter()
                {
                    self.apply_creator_registration(
                        schema_id,
                        ns,
                        creator,
                        registration,
                        *version,
                    );
                }

                for (schema_id, ns, creator) in remove_creator.iter() {
                    self.close_creator_registration(
                        schema_id, ns, creator, *version,
                    );
                }

                for ((schema_id, ns, creator), registration) in
                    update_creator_witnesses.iter()
                {
                    self.apply_creator_registration(
                        schema_id,
                        ns,
                        creator,
                        registration,
                        *version,
                    );
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
            WitnessesRegisterEvent::UpdateTrackerVisibility {
                subject_id,
                sn,
                mode,
                stored_visibility,
                event_visibility,
            } => {
                if let Some(data) = self.subjects.get_mut(subject_id) {
                    data.visibility_state.set_mode(*mode);
                    data.visibility_state.record_event(
                        *sn,
                        stored_visibility.clone(),
                        event_visibility.clone(),
                    );
                } else {
                    warn!(
                        event_type = "UpdateTrackerVisibility",
                        subject_id = %subject_id,
                        sn = sn,
                        "Tracker visibility update ignored because subject was not found"
                    );
                }
            }
            WitnessesRegisterEvent::Create {
                subject_id,
                owner,
                gov_version,
            } => {
                let data = self.subjects.entry(subject_id.clone()).or_default();

                data.actual_owner = owner.clone();
                data.gov_version = *gov_version;
                data.visibility_state = TrackerVisibilityState::default();
                data.visibility_state.record_event(
                    0,
                    TrackerStoredVisibility::Full,
                    TrackerEventVisibility::NonFact,
                );

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
            WitnessesRegisterEvent::DeleteSubject { subject_id } => {
                self.subjects.remove(subject_id);

                debug!(
                    event_type = "DeleteSubject",
                    subject_id = %subject_id,
                    "Witness subject entry deleted from state"
                );
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
