use std::collections::{HashMap, HashSet};

use crate::governance::sn_register::SnLimit;
use crate::model::common::{Interval, IntervalSet, OwnerContext, TrackerIdentity};
use ave_actors::{ActorContext, ActorError};
use ave_common::identity::{DigestIdentifier, PublicKey};
use ave_common::{Namespace, SchemaType};

use super::{
    CreatorWitnessRegistration, GovVersionLimit, HiSnLimit, IntervalData,
    WitnessesRegister, WitnessesType, ActualSearch, WitnessStatus,
};

impl WitnessesRegister {
    pub(crate) fn close_creator_registration(
        &mut self,
        schema_id: &SchemaType,
        namespace: &str,
        creator: &PublicKey,
        version: u64,
    ) {
        if let Some(entry) = self.creator_witnesses.get_mut(&(
            creator.clone(),
            namespace.to_owned(),
            schema_id.clone(),
        )) {
            for (.., (interval, last)) in entry.intervals.iter_mut() {
                if let Some(last) = last.take() {
                    interval.insert(Interval {
                        lo: last,
                        hi: version - 1,
                    });
                }
            }

            for history in entry.grants.values_mut() {
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
        let entry = self
            .creator_witnesses
            .entry((creator.clone(), namespace.to_owned(), schema_id.clone()))
            .or_default();

        let witnesses: HashSet<_> =
            registration.witnesses.iter().cloned().collect();
        for (witness_type, (interval, last)) in entry.intervals.iter_mut() {
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
            if let Some((.., last)) = entry.intervals.get_mut(witness) {
                if last.is_none() {
                    *last = Some(version);
                }
            } else {
                entry.intervals.insert(
                    witness.clone(),
                    (IntervalSet::new(), Some(version)),
                );
            }
        }

        let grant_map: HashMap<_, _> =
            registration.grants.iter().cloned().collect();

        for (witness_type, history) in entry.grants.iter_mut() {
            history
                .apply_version(version, grant_map.get(witness_type).cloned());
        }

        for (witness_type, grant) in grant_map {
            entry.grants
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

    pub(crate) fn rebuild_node_creator_index(&mut self) {
        self.node_creator_index.clear();
        for ((creator, namespace, schema_id), entry) in
            &self.creator_witnesses
        {
            for (witness_type, (_, current_lo)) in &entry.intervals {
                if let WitnessesType::User(node) = witness_type && current_lo.is_some() {
                    let key = (creator.clone(), namespace.clone(), schema_id.clone());
                    if let Some(set) = self.node_creator_index.get_mut(node) {
                        set.insert(key);
                    } else {
                        let mut set = HashSet::new();
                        set.insert(key);
                        self.node_creator_index.insert(node.clone(), set);
                    }
                }
            }
        }
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

        self.creator_witnesses
            .get(&(owner.clone(), namespace.to_string(), schema_id.clone()))
            .is_some_and(|entry| {
                entry.intervals
                    .get(&WitnessesType::User(node.clone()))
                    .is_some_and(|(intervals, current_from)| {
                        Self::interval_active_at_version(
                            *current_from,
                            intervals,
                            gov_version,
                        )
                    })
                    || entry.intervals
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
        let Some(entry) = self.creator_witnesses.get(&(
            owner.clone(),
            namespace.to_string(),
            schema_id.clone(),
        )) else {
            return GovVersionLimit::None;
        };

        match self
            .check_current_owner(
                &entry.intervals,
                node,
                schema_id,
                &namespace,
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
        identity: TrackerIdentity,
        owner_ctx: OwnerContext,
        cached_search: Option<(SnLimit, Option<PublicKey>)>,
    ) -> Result<(WitnessStatus, Option<(SnLimit, Option<PublicKey>)>), ActorError> {
        let mut access_sn = None;
        let mut hi_sn_limit = HiSnLimit::None;
        let mut gov_version_limit = GovVersionLimit::None;
        let mut create_access = false;
        let mut create_gov_version_limit = GovVersionLimit::None;
        let mut cached = cached_search;

        if let Some(subject_id) = &subject_id {
            access_sn = self
                .access_limit_for_node(ctx, subject_id, &node, &identity.namespace, &identity.schema_id, &mut cached)
                .await?;
            hi_sn_limit = self
                .hi_sn_limit_for_node(ctx, subject_id, &node, &identity.namespace, &identity.schema_id, &mut cached)
                .await?;
            gov_version_limit = self
                .gov_version_limit_for_node(subject_id, &node, &identity.namespace, &identity.schema_id)
                .await?;
        }

        if let Some(owner) = owner_ctx.owner && let Some(gov_version) = owner_ctx.gov_version {
            create_access = self.has_create_access_for_node_at_version(
                &node, &owner, &identity.schema_id, &identity.namespace, gov_version,
            );
            create_gov_version_limit = self
                .create_gov_version_limit_for_node(
                    &node, &owner, &identity.schema_id, &identity.namespace, gov_version,
                )
                .await;
        }

        Ok((WitnessStatus {
            access_sn,
            hi_sn_limit,
            gov_version_limit,
            create_access,
            create_gov_version_limit,
        }, cached))
    }

}
