use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

use crate::governance::sn_register::{
    SnLimit, SnRegister, SnRegisterMessage, SnRegisterResponse,
};
use crate::governance::subject_register::{
    SubjectRegister, SubjectRegisterMessage, SubjectRegisterResponse,
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

use super::{
    CreatorWitnessGrant, CreatorWitnessGrantHistory, CreatorWitnessGrantRange,
    CreatorWitnessRegistration, CurrentWitnessSubject, GovVersionLimit,
    HiSnLimit, IntervalData, OldOwnerData, TransferData, TrackerDeliveryMode,
    TrackerDeliveryRange, WitnessesRegister, WitnessesRegisterEvent,
    WitnessesRegisterMessage, WitnessesRegisterResponse, WitnessesType,
    ActualSearch, WitnessStatus,
};

impl WitnessesRegister {
    pub(crate) fn close_creator_registration(
        &mut self,
        schema_id: &SchemaType,
        namespace: &str,
        creator: &PublicKey,
        version: u64,
    ) {
        if let Some(witnesses) = self.witnesses_creator.get_mut(&(
            creator.clone(),
            namespace.to_owned(),
            schema_id.clone(),
        )) {
            for (.., (interval, last)) in witnesses.iter_mut() {
                if let Some(last) = last.take() {
                    interval.insert(Interval {
                        lo: last,
                        hi: version - 1,
                    });
                }
            }
        }

        if let Some(grants) = self.witnesses_creator_grants.get_mut(&(
            creator.clone(),
            namespace.to_owned(),
            schema_id.clone(),
        )) {
            for history in grants.values_mut() {
                history.apply_version(version, None);
            }
        }
    }

    pub(crate) fn apply_creator_registration(
        &mut self,
        schema_id: &SchemaType,
        namespace: &str,
        creator: &PublicKey,
        registration: &CreatorWitnessRegistration,
        version: u64,
    ) {
        let creator_entry = self
            .witnesses_creator
            .entry((creator.clone(), namespace.to_owned(), schema_id.clone()))
            .or_default();

        let witnesses: HashSet<_> =
            registration.witnesses.iter().cloned().collect();
        for (witness_type, (interval, last)) in creator_entry.iter_mut() {
            if !witnesses.contains(witness_type)
                && let Some(lo) = last.take()
            {
                interval.insert(Interval {
                    lo,
                    hi: version - 1,
                });
            }
        }

        for witness in &registration.witnesses {
            if let Some((.., last)) = creator_entry.get_mut(witness) {
                if last.is_none() {
                    *last = Some(version);
                }
            } else {
                creator_entry.insert(
                    witness.clone(),
                    (IntervalSet::new(), Some(version)),
                );
            }
        }

        let creator_grants = self
            .witnesses_creator_grants
            .entry((creator.clone(), namespace.to_owned(), schema_id.clone()))
            .or_default();

        let grant_map: HashMap<_, _> =
            registration.grants.iter().cloned().collect();

        for (witness_type, history) in creator_grants.iter_mut() {
            history
                .apply_version(version, grant_map.get(witness_type).cloned());
        }

        for (witness_type, grant) in grant_map {
            creator_grants
                .entry(witness_type)
                .or_default()
                .apply_version(version, Some(grant));
        }
    }

    pub(crate) fn has_active_schema_witness(
        &self,
        node: &PublicKey,
        schema_id: &SchemaType,
        namespace: &Namespace,
    ) -> bool {
        let has_match = |witness_data: &HashMap<Namespace, IntervalData>| {
            witness_data
                .iter()
                .any(|(current_namespace, (_, current_lo))| {
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

    pub(crate) fn is_current_witness_for_entry(
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

    pub(crate) fn has_schema_witness_at_version(
        &self,
        node: &PublicKey,
        schema_id: &SchemaType,
        namespace: &Namespace,
        gov_version: u64,
    ) -> bool {
        let has_match = |witness_data: &HashMap<Namespace, IntervalData>| {
            witness_data.iter().any(
                |(current_namespace, (intervals, current_from))| {
                    current_namespace.is_ancestor_or_equal_of(namespace)
                        && Self::interval_active_at_version(
                            *current_from,
                            intervals,
                            gov_version,
                        )
                },
            )
        };

        self.witnesses
            .get(&(node.clone(), schema_id.clone()))
            .is_some_and(has_match)
            || self
                .witnesses
                .get(&(node.clone(), SchemaType::TrackerSchemas))
                .is_some_and(has_match)
    }

    pub(crate) fn has_create_access_for_node_at_version(
        &self,
        node: &PublicKey,
        owner: &PublicKey,
        schema_id: &SchemaType,
        namespace: &str,
        gov_version: u64,
    ) -> bool {
        if node == owner {
            return true;
        }

        let namespace = Namespace::from(namespace.to_owned());

        self.witnesses_creator
            .get(&(owner.clone(), namespace.to_string(), schema_id.clone()))
            .is_some_and(|creator_witnesses| {
                creator_witnesses
                    .get(&WitnessesType::User(node.clone()))
                    .is_some_and(|(intervals, current_from)| {
                        Self::interval_active_at_version(
                            *current_from,
                            intervals,
                            gov_version,
                        )
                    })
                    || creator_witnesses
                        .get(&WitnessesType::Witnesses)
                        .is_some_and(|(intervals, current_from)| {
                            Self::interval_active_at_version(
                                *current_from,
                                intervals,
                                gov_version,
                            )
                        })
                        && self.has_schema_witness_at_version(
                            node,
                            schema_id,
                            &namespace,
                            gov_version,
                        )
            })
    }

    pub(crate) async fn create_gov_version_limit_for_node(
        &self,
        node: &PublicKey,
        owner: &PublicKey,
        schema_id: &SchemaType,
        namespace: &str,
        owner_gov_version: u64,
    ) -> GovVersionLimit {
        if node == owner {
            return GovVersionLimit::Infinity;
        }

        let namespace = Namespace::from(namespace.to_owned());
        let Some(creator_witnesses) = self.witnesses_creator.get(&(
            owner.clone(),
            namespace.to_string(),
            schema_id.clone(),
        )) else {
            return GovVersionLimit::None;
        };

        match self
            .check_current_owner(
                creator_witnesses,
                node,
                schema_id,
                &namespace,
                0,
                (owner_gov_version, None),
            )
            .await
        {
            ActualSearch::End(SnLimit::LastSn) => GovVersionLimit::Infinity,
            ActualSearch::End(_) => GovVersionLimit::None,
            ActualSearch::Continue {
                gov_version: Some(version),
            } => GovVersionLimit::Version(version),
            ActualSearch::Continue { gov_version: None } => {
                GovVersionLimit::None
            }
        }
    }

    pub(crate) async fn query_witness_status(
        &self,
        ctx: &ActorContext<Self>,
        subject_id: Option<DigestIdentifier>,
        node: PublicKey,
        namespace: String,
        schema_id: SchemaType,
        owner: Option<PublicKey>,
        owner_gov_version: Option<u64>,
    ) -> Result<WitnessStatus, ActorError> {
        let mut access_sn = None;
        let mut hi_sn_limit = HiSnLimit::None;
        let mut gov_version_limit = GovVersionLimit::None;
        let mut create_access = false;
        let mut create_gov_version_limit = GovVersionLimit::None;

        if let Some(subject_id) = subject_id {
            access_sn = self
                .access_limit_for_node(ctx, &subject_id, &node, &namespace, &schema_id)
                .await?;
            hi_sn_limit = self
                .hi_sn_limit_for_node(ctx, &subject_id, &node, &namespace, &schema_id)
                .await?;
            gov_version_limit = self
                .gov_version_limit_for_node(&subject_id, &node, &namespace, &schema_id)
                .await?;
        }

        if let Some(owner) = owner {
            if let Some(gov_version) = owner_gov_version {
                create_access = self.has_create_access_for_node_at_version(
                    &node, &owner, &schema_id, &namespace, gov_version,
                );
                create_gov_version_limit = self
                    .create_gov_version_limit_for_node(
                        &node, &owner, &schema_id, &namespace, gov_version,
                    )
                    .await;
            }
        }

        Ok(WitnessStatus {
            access_sn,
            hi_sn_limit,
            gov_version_limit,
            create_access,
            create_gov_version_limit,
        })
    }

}
