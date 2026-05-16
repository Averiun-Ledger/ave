use std::collections::{BTreeSet, HashMap};

use crate::governance::sn_register::SnLimit;

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
    ActualSearch,
};

impl WitnessesRegister {
    pub(crate) fn event_delivery_mode(
        &self,
        data: &TransferData,
        node: &PublicKey,
        namespace: &Namespace,
        schema_id: &SchemaType,
        sn: u64,
        gov_version: u64,
    ) -> TrackerDeliveryMode {
        let stored_span = data.visibility_state.iter_stored(sn, sn).next();
        let event_span = data.visibility_state.iter_events(sn, sn).next();

        let Some(stored_span) = stored_span else {
            return TrackerDeliveryMode::Opaque;
        };
        let Some(event_span) = event_span else {
            return TrackerDeliveryMode::Opaque;
        };

        match event_span.visibility {
            TrackerEventVisibility::NonFact => TrackerDeliveryMode::Clear,
            TrackerEventVisibility::Fact(viewpoints) => {
                if viewpoints.is_empty() {
                    return TrackerDeliveryMode::Clear;
                }

                if data.actual_owner == *node
                    || data
                        .actual_new_owner_data
                        .as_ref()
                        .is_some_and(|(new_owner, _)| new_owner == node)
                {
                    return TrackerDeliveryMode::Clear;
                }

                if let Some(old_owner) = data.old_owners.get(node)
                    && sn <= old_owner.sn
                {
                    return TrackerDeliveryMode::Clear;
                }

                if matches!(
                    stored_span.visibility,
                    TrackerStoredVisibility::None
                ) {
                    return TrackerDeliveryMode::Opaque;
                }

                let mut grant = None;

                if gov_version >= data.gov_version {
                    grant = Some(Self::merge_grant(
                        grant,
                        &self
                            .creator_grant_for_event_or_current_owner(
                                node,
                                &data.actual_owner,
                                schema_id,
                                namespace,
                                gov_version,
                                data.gov_version,
                            )
                            .unwrap_or(CreatorWitnessGrant::Hash),
                    ));
                }

                if let Some((new_owner, new_owner_gov_version)) =
                    &data.actual_new_owner_data
                    && gov_version >= *new_owner_gov_version
                {
                    grant = Some(Self::merge_grant(
                        grant,
                        &self
                            .creator_grant_for_event_or_current_owner(
                                node,
                                new_owner,
                                schema_id,
                                namespace,
                                gov_version,
                                *new_owner_gov_version,
                            )
                            .unwrap_or(CreatorWitnessGrant::Hash),
                    ));
                }

                for (creator, old_owner) in &data.old_owners {
                    if sn > old_owner.sn {
                        continue;
                    }

                    for range in old_owner.interval_gov_version.iter().rev() {
                        if !range.contains(gov_version) {
                            continue;
                        }

                        grant = Some(Self::merge_grant(
                            grant,
                            &self
                                .creator_grant_for_owner_interval(
                                    node,
                                    creator,
                                    schema_id,
                                    namespace,
                                    gov_version,
                                    gov_version,
                                )
                                .unwrap_or(CreatorWitnessGrant::Hash),
                        ));
                        break;
                    }
                }

                if Self::grant_allows_clear(grant, viewpoints) {
                    TrackerDeliveryMode::Clear
                } else {
                    TrackerDeliveryMode::Opaque
                }
            }
        }
    }

    /// Calcula los puntos de corte (cut points) donde cualquier factor que afecta
    /// `event_delivery_mode` puede cambiar. Entre dos cortes consecutivos el modo
    /// es constante, permitiendo iterar por rangos en lugar de SN-a-SN.
    fn compute_cut_points(
        from_sn: u64,
        access_limit: u64,
        visibility_state: &TrackerVisibilityState,
        gov_versions: &[(Interval, u64)],
        old_owners: &HashMap<PublicKey, OldOwnerData>,
    ) -> Vec<u64> {
        let mut cuts: BTreeSet<u64> = BTreeSet::new();
        cuts.insert(from_sn);
        cuts.insert(access_limit.saturating_add(1));

        // Corte por stored_ranges
        for range in &visibility_state.stored_ranges {
            if range.from_sn > access_limit {
                continue;
            }
            if range.to_sn.map_or(false, |to| to < from_sn) {
                continue;
            }
            if range.from_sn >= from_sn {
                cuts.insert(range.from_sn);
            }
            if let Some(to) = range.to_sn {
                let next = to.saturating_add(1);
                if next <= access_limit {
                    cuts.insert(next);
                }
            }
        }

        // Corte por event_ranges
        for range in &visibility_state.event_ranges {
            if range.from_sn > access_limit {
                continue;
            }
            if range.to_sn.map_or(false, |to| to < from_sn) {
                continue;
            }
            if range.from_sn >= from_sn {
                cuts.insert(range.from_sn);
            }
            if let Some(to) = range.to_sn {
                let next = to.saturating_add(1);
                if next <= access_limit {
                    cuts.insert(next);
                }
            }
        }

        // Corte por gov_versions
        for (interval, _) in gov_versions {
            if interval.lo > access_limit {
                continue;
            }
            if interval.hi < from_sn {
                continue;
            }
            if interval.lo >= from_sn {
                cuts.insert(interval.lo);
            }
            let next = interval.hi.saturating_add(1);
            if next <= access_limit {
                cuts.insert(next);
            }
        }

        // Corte por old_owners (condición sn <= old_owner.sn cambia en old_owner.sn + 1)
        for (_, old_data) in old_owners {
            if old_data.sn >= from_sn && old_data.sn <= access_limit {
                let next = old_data.sn.saturating_add(1);
                if next <= access_limit {
                    cuts.insert(next);
                }
            }
        }

        cuts.into_iter().collect()
    }

    pub(crate) async fn build_tracker_window_from_data(
        &self,
        ctx: &ActorContext<Self>,
        subject_id: &DigestIdentifier,
        data: &TransferData,
        node: &PublicKey,
        _sender: &PublicKey,
        namespace: String,
        schema_id: SchemaType,
        actual_sn: Option<u64>,
        search_result: Option<(SnLimit, Option<PublicKey>)>,
    ) -> Result<
        (
            Option<u64>,
            Option<u64>,
            Option<u64>,
            bool,
            Vec<TrackerDeliveryRange>,
        ),
        ActorError,
    > {
        let (sn_limit, mut effective_owner) = match search_result {
            Some(result) => result,
            None => {
                self
                    .search_witnesses_with_owner(
                        ctx,
                        node,
                        data,
                        namespace.clone(),
                        schema_id.clone(),
                        subject_id.clone(),
                    )
                    .await?
            }
        };

        debug!(
            msg_type = "BuildTrackerWindow",
            subject_id = %subject_id,
            node = %node,
            actual_owner = %data.actual_owner,
            old_owners = ?data.old_owners.keys(),
            actual_new_owner = ?data.actual_new_owner_data.as_ref().map(|(o,_)| o),
            data.sn = data.sn,
            sn_limit = ?sn_limit,
            effective_owner = ?effective_owner,
            "Starting build_tracker_window_from_data"
        );

        let access_limit = match sn_limit {
            SnLimit::Sn(sn) => Some(sn),
            SnLimit::LastSn => Some(data.sn),
            SnLimit::NotSn => {
                if data.actual_owner == *node {
                    effective_owner = Some(data.actual_owner.clone());
                    Some(data.sn)
                } else if let Some((new_owner, _)) = &data.actual_new_owner_data
                    && new_owner == node
                {
                    effective_owner = Some(new_owner.clone());
                    Some(data.sn)
                } else {
                    data.old_owners.get(node).map(|old_owner| {
                        effective_owner = Some(node.clone());
                        old_owner.sn
                    })
                }
            }
        };

        debug!(
            msg_type = "BuildTrackerWindow",
            subject_id = %subject_id,
            node = %node,
            access_limit = ?access_limit,
            "Access limit computed"
        );

        let Some(access_limit) = access_limit else {
            return Ok((None, None, None, true, Vec::new()));
        };

        let mut sorted_old_owners: Vec<(PublicKey, u64)> = data
            .old_owners
            .iter()
            .map(|(k, v)| (k.clone(), v.sn))
            .collect();
        sorted_old_owners.sort_by_key(|(_, sn)| *sn);

        let transfer_sn = if let Some(owner) = effective_owner {
            if data.actual_new_owner_data.as_ref().is_some_and(|(new_owner, _)| new_owner == &owner)
            {
                // Es el new_owner pendiente: necesita ver la transferencia actual
                Some(data.sn)
            } else if data.actual_owner == owner {
                // Es el owner actual: su incoming transfer es el outgoing del
                // último old_owner. Solo lo necesita si su acceso cruza ese transfer.
                sorted_old_owners
                    .last()
                    .map(|(_, sn)| sn.saturating_sub(1))
                    .filter(|transfer_sn| access_limit >= *transfer_sn)
            } else if let Some(idx) = sorted_old_owners.iter().position(|(o, _)| o == &owner) {
                // Es un old_owner: su incoming transfer es el outgoing del owner
                // anterior. Para idx==0, el owner anterior es el creador original
                // (que no está en old_owners); su outgoing transfer está justo
                // antes del Confirm del primer old_owner.
                let candidate = if idx == 0 {
                    sorted_old_owners[0].1.saturating_sub(1)
                } else {
                    sorted_old_owners[idx - 1].1.saturating_sub(1)
                };
                // Solo necesita el transfer_event si su access_limit lo cruza
                if access_limit >= candidate {
                    Some(candidate)
                } else {
                    None
                }
            } else {
                None
            }
        } else {
            None
        }
        .filter(|transfer_sn| actual_sn.is_none_or(|sn| sn < *transfer_sn));



        let from_sn = actual_sn.map_or(0, |sn| sn.saturating_add(1));
        if from_sn > access_limit {

            return Ok((None, transfer_sn, None, true, Vec::new()));
        }

        let namespace = Namespace::from(namespace);
        let gov_versions = self
            .get_gov_version_window(ctx, subject_id, from_sn, access_limit)
            .await?;

        let mut ranges: Vec<TrackerDeliveryRange> = Vec::new();
        let mut clear_sn = None;

        let cuts = Self::compute_cut_points(
            from_sn,
            access_limit,
            &data.visibility_state,
            &gov_versions,
            &data.old_owners,
        );

        let mut gv_idx = 0;
        for window in cuts.windows(2) {
            let range_from = window[0];
            let range_to = window[1].saturating_sub(1);

            while gv_idx < gov_versions.len() && gov_versions[gv_idx].0.hi < range_from {
                gv_idx += 1;
            }

            let gov_version = if gv_idx < gov_versions.len()
                && gov_versions[gv_idx].0.contains(range_from)
            {
                Some(gov_versions[gv_idx].1)
            } else {
                (range_from == 0).then_some(data.gov_version)
            };

            let Some(gov_version) = gov_version else {
                warn!(
                    msg_type = "BuildTrackerWindow",
                    subject_id = %subject_id,
                    node = %node,
                    range_from = range_from,
                    range_to = range_to,
                    "gov_version missing for range"
                );
                continue;
            };

            let mode = self.event_delivery_mode(
                data,
                node,
                &namespace,
                &schema_id,
                range_from,
                gov_version,
            );

            match ranges.last_mut() {
                Some(last)
                    if std::mem::discriminant(&last.mode)
                        == std::mem::discriminant(&mode)
                        && last.to_sn + 1 == range_from =>
                {
                    last.to_sn = range_to;
                }
                _ => ranges.push(TrackerDeliveryRange {
                    from_sn: range_from,
                    to_sn: range_to,
                    mode: mode.clone(),
                }),
            }

            if matches!(mode, TrackerDeliveryMode::Clear)
                && ((clear_sn.is_none()
                    && matches!(
                        ranges.first().map(|x| &x.mode),
                        Some(TrackerDeliveryMode::Clear)
                    ))
                    || clear_sn == Some(range_from.saturating_sub(1)))
            {
                clear_sn = Some(range_to);
            }
        }

        debug!(
            msg_type = "BuildTrackerWindow",
            subject_id = %subject_id,
            node = %node,
            access_limit = ?access_limit,
            transfer_sn = ?transfer_sn,
            clear_sn = ?clear_sn,
            actual_sn = ?actual_sn,
            "Tracker window built"
        );

        Ok((Some(access_limit), transfer_sn, clear_sn, true, ranges))
    }

    pub(crate) async fn build_tracker_window(
        &self,
        ctx: &ActorContext<Self>,
        subject_id: &DigestIdentifier,
        node: &PublicKey,
        sender: &PublicKey,
        namespace: String,
        schema_id: SchemaType,
        actual_sn: Option<u64>,
    ) -> Result<
        (
            Option<u64>,
            Option<u64>,
            Option<u64>,
            bool,
            Vec<TrackerDeliveryRange>,
        ),
        ActorError,
    > {
        let Some(data) = self.subjects.get(subject_id) else {
            return Ok((None, None, None, true, Vec::new()));
        };

        self.build_tracker_window_from_data(
            ctx, subject_id, data, node, sender, namespace, schema_id,
            actual_sn,
            None,
        )
        .await
    }

    pub(crate) async fn access_limit_for_node(
        &self,
        ctx: &ActorContext<Self>,
        subject_id: &DigestIdentifier,
        node: &PublicKey,
        namespace: &str,
        schema_id: &SchemaType,
        cached: &mut Option<(SnLimit, Option<PublicKey>)>,
    ) -> Result<Option<u64>, ActorError> {
        let Some(data) = self.subjects.get(subject_id) else {
            return Ok(None);
        };

        let sn = if data.actual_owner == *node {
            Some(data.sn)
        } else if let Some((new_owner, ..)) = &data.actual_new_owner_data
            && new_owner == node
        {
            Some(data.sn)
        } else if let Some(old_data) = data.old_owners.get(node) {
            let sn_limit = self
                .search_witnesses(
                    ctx,
                    node,
                    data,
                    namespace.to_owned(),
                    schema_id.clone(),
                    subject_id.clone(),
                    cached,
                )
                .await?;

            let sn = match sn_limit {
                SnLimit::Sn(sn) => sn.max(old_data.sn),
                SnLimit::LastSn => data.sn.max(old_data.sn),
                SnLimit::NotSn => old_data.sn,
            };

            Some(sn)
        } else {
            let sn_limit = self
                .search_witnesses(
                    ctx,
                    node,
                    data,
                    namespace.to_owned(),
                    schema_id.clone(),
                    subject_id.clone(),
                    cached,
                )
                .await?;

            match sn_limit {
                SnLimit::Sn(sn) => Some(sn),
                SnLimit::LastSn => Some(data.sn),
                SnLimit::NotSn => None,
            }
        };

        Ok(sn)
    }

    pub(crate) async fn hi_sn_limit_for_transfer_data(
        &self,
        ctx: &ActorContext<Self>,
        subject_id: &DigestIdentifier,
        node: &PublicKey,
        namespace: &str,
        schema_id: &SchemaType,
        data: &TransferData,
        cached: &mut Option<(SnLimit, Option<PublicKey>)>,
    ) -> Result<HiSnLimit, ActorError> {


        if data.actual_owner == *node
            || data
                .actual_new_owner_data
                .as_ref()
                .is_some_and(|(new_owner, _)| new_owner == node)
        {

            return Ok(HiSnLimit::Infinity);
        }

        let sn_limit = self
            .search_witnesses(
                ctx,
                node,
                data,
                namespace.to_owned(),
                schema_id.clone(),
                subject_id.clone(),
                cached,
            )
            .await?;

        let old_owner_limit = data.old_owners.get(node).map(|old| old.sn);

        let limit = match sn_limit {
            SnLimit::LastSn => HiSnLimit::Infinity,
            SnLimit::Sn(sn) => {
                HiSnLimit::Sn(old_owner_limit.map_or(sn, |old| sn.max(old)))
            }
            SnLimit::NotSn => match old_owner_limit {
                Some(sn) => HiSnLimit::Sn(sn),
                None => HiSnLimit::None,
            },
        };
        Ok(limit)
    }

    pub(crate) async fn hi_sn_limit_for_node(
        &self,
        ctx: &ActorContext<Self>,
        subject_id: &DigestIdentifier,
        node: &PublicKey,
        namespace: &str,
        schema_id: &SchemaType,
        cached: &mut Option<(SnLimit, Option<PublicKey>)>,
    ) -> Result<HiSnLimit, ActorError> {
        let Some(data) = self.subjects.get(subject_id) else {
            return Ok(HiSnLimit::None);
        };

        if data.actual_owner == *node
            || data
                .actual_new_owner_data
                .as_ref()
                .is_some_and(|(new_owner, _)| new_owner == node)
        {
            return Ok(HiSnLimit::Infinity);
        }

        let limit = self
            .hi_sn_limit_for_transfer_data(
                ctx, subject_id, node, namespace, schema_id, data, cached,
            )
            .await?;

        Ok(limit)
    }

    pub(crate) async fn gov_version_limit_for_node(
        &self,
        subject_id: &DigestIdentifier,
        node: &PublicKey,
        namespace: &str,
        schema_id: &SchemaType,
    ) -> Result<GovVersionLimit, ActorError> {
        let Some(data) = self.subjects.get(subject_id) else {
            return Ok(GovVersionLimit::None);
        };

        if data.actual_owner == *node
            || data
                .actual_new_owner_data
                .as_ref()
                .is_some_and(|(new_owner, _)| new_owner == node)
        {
            return Ok(GovVersionLimit::Infinity);
        }

        let limit = self
            .gov_version_limit_for_transfer_data(
                node, namespace, schema_id, data,
            )
            .await;

        Ok(limit)
    }

    pub(crate) async fn gov_version_limit_for_transfer_data(
        &self,
        node: &PublicKey,
        namespace: &str,
        schema_id: &SchemaType,
        data: &TransferData,
    ) -> GovVersionLimit {
        let parse_namespace = Namespace::from(namespace.to_owned());
        let mut better_gov_version: Option<u64> = None;

        // Obtengo los testigos del owner actual
        if let Some(entry) = self.creator_witnesses.get(&(
            data.actual_owner.to_owned(),
            namespace.to_owned(),
            schema_id.clone(),
        )) {
            match self
                .check_current_owner(
                    &entry.intervals,
                    node,
                    schema_id,
                    &parse_namespace,
                    data.sn,
                    (data.gov_version, better_gov_version),
                )
                .await
            {
                ActualSearch::End(SnLimit::LastSn) => {
                    return GovVersionLimit::Infinity;
                }
                ActualSearch::End(_) => {}
                ActualSearch::Continue { gov_version } => {
                    better_gov_version = gov_version;
                }
            }
        }

        // Obtengo los testigos del new_owner (si hay transferencia pendiente)
        if let Some((new_owner, new_owner_gov_version)) =
            &data.actual_new_owner_data
            && let Some(entry) = self.creator_witnesses.get(&(
                new_owner.to_owned(),
                namespace.to_owned(),
                schema_id.clone(),
            ))
        {
            match self
                .check_current_owner(
                    &entry.intervals,
                    node,
                    schema_id,
                    &parse_namespace,
                    data.sn,
                    (*new_owner_gov_version, better_gov_version),
                )
                .await
            {
                ActualSearch::End(SnLimit::LastSn) => {
                    return GovVersionLimit::Infinity;
                }
                ActualSearch::End(_) => {}
                ActualSearch::Continue { gov_version } => {
                    better_gov_version = gov_version;
                }
            }
        }

        // Not_owners
        for (creator, old_data) in data.old_owners.iter() {
            if let Some(entry) = self.creator_witnesses.get(&(
                creator.to_owned(),
                namespace.to_owned(),
                schema_id.clone(),
            )) {
                if let Some((interval, actual_lo)) =
                    entry.intervals.get(&WitnessesType::User(node.clone()))
                {
                    let covered_old_owner = Self::covered_old_owner_intervals(
                        *actual_lo, interval, old_data,
                    );

                    if let Some(gov_version) =
                        covered_old_owner.iter().last().map(|range| range.hi)
                    {
                        better_gov_version =
                            better_gov_version.max(Some(gov_version));
                    }
                }

                if let Some((interval, actual_lo)) =
                    entry.intervals.get(&WitnessesType::Witnesses)
                {
                    let covered_old_owner = Self::covered_old_owner_intervals(
                        *actual_lo, interval, old_data,
                    );

                    if covered_old_owner.iter().next().is_some() {
                        let capped_old_owner = OldOwnerData {
                            sn: old_data.sn,
                            interval_gov_version: covered_old_owner,
                        };

                        if let Some(gov_version) = self.search_schemas_old(
                            node,
                            schema_id,
                            &parse_namespace,
                            &capped_old_owner,
                            better_gov_version,
                        ) {
                            better_gov_version =
                                better_gov_version.max(Some(gov_version));
                        }
                    }
                }
            }
        }

        match better_gov_version {
            Some(version) => GovVersionLimit::Version(version),
            None => GovVersionLimit::None,
        }
    }

    pub(crate) async fn search_witnesses_with_owner(
        &self,
        ctx: &ActorContext<Self>,
        node: &PublicKey,
        data: &TransferData,
        namespace: String,
        schema_id: SchemaType,
        subject_id: DigestIdentifier,
    ) -> Result<(SnLimit, Option<PublicKey>), ActorError> {
        let mut better_gov_version: Option<u64> = None;
        let mut better_sn: Option<u64> = None;
        let mut effective_owner: Option<PublicKey> = None;
        let parse_namespace = Namespace::from(namespace.clone());

        // Obtengo los testigos del owner
        if let Some(entry) = self.creator_witnesses.get(&(
            data.actual_owner.to_owned(),
            namespace.clone(),
            schema_id.clone(),
        )) {
            match self
                .check_current_owner(
                    &entry.intervals,
                    node,
                    &schema_id,
                    &parse_namespace,
                    data.sn,
                    (data.gov_version, better_gov_version),
                )
                .await
            {
                ActualSearch::End(sn_limit) => {
                    return Ok((sn_limit, Some(data.actual_owner.clone())));
                }
                ActualSearch::Continue { gov_version } => {
                    better_gov_version = gov_version;
                }
            }
        }

        if let Some((new_owner, new_owner_gov_version)) =
            &data.actual_new_owner_data
            && let Some(entry) = self.creator_witnesses.get(&(
                new_owner.to_owned(),
                namespace.clone(),
                schema_id.clone(),
            ))
        {
            match self
                .check_current_owner(
                    &entry.intervals,
                    node,
                    &schema_id,
                    &parse_namespace,
                    data.sn,
                    (*new_owner_gov_version, better_gov_version),
                )
                .await
            {
                ActualSearch::End(sn_limit) => {
                    return Ok((sn_limit, Some(new_owner.clone())));
                }
                ActualSearch::Continue { gov_version } => {
                    better_gov_version = gov_version;
                }
            }
        }

        // === FASE 1: Recolección de gov_versions candidatas ===
        let mut gov_versions_to_fetch: Vec<u64> = Vec::new();
        let mut old_owner_candidates: Vec<(
            PublicKey,
            OldOwnerData,
            Option<u64>,
            Option<u64>,
            bool,
        )> = Vec::new();

        for (creator, old_data) in data.old_owners.iter() {
            let mut user_gv = None;
            let mut schema_gv = None;
            let mut matched = false;

            if let Some(entry) = self.creator_witnesses.get(&(
                creator.to_owned(),
                namespace.clone(),
                schema_id.clone(),
            )) {
                if let Some((interval, actual_lo)) =
                    entry.intervals.get(&WitnessesType::User(node.clone()))
                {
                    let covered_old_owner = Self::covered_old_owner_intervals(
                        *actual_lo, interval, old_data,
                    );

                    if let Some(gov_version) =
                        covered_old_owner.iter().last().map(|range| range.hi)
                    {
                        user_gv = Some(gov_version);
                        gov_versions_to_fetch.push(gov_version);
                        matched = true;
                    }
                }

                if let Some((interval, actual_lo)) =
                    entry.intervals.get(&WitnessesType::Witnesses)
                {
                    let covered_old_owner = Self::covered_old_owner_intervals(
                        *actual_lo, interval, old_data,
                    );

                    if covered_old_owner.iter().next().is_some() {
                        let capped_old_owner = OldOwnerData {
                            sn: old_data.sn,
                            interval_gov_version: covered_old_owner,
                        };

                        if let Some(gov_version) = self.search_schemas_old(
                            node,
                            &schema_id,
                            &parse_namespace,
                            &capped_old_owner,
                            better_gov_version,
                        ) {
                            schema_gv = Some(gov_version);
                            gov_versions_to_fetch.push(gov_version);
                            matched = true;
                        }
                    }
                }
            }

            let is_direct = !matched && *creator == *node;
            old_owner_candidates.push((
                creator.clone(),
                old_data.clone(),
                user_gv,
                schema_gv,
                is_direct,
            ));
        }

        // Añadir better_gov_version para el cálculo final
        if let Some(gov_version) = better_gov_version {
            gov_versions_to_fetch.push(gov_version);
        }

        // === FASE 2: Batch fetch de SNs ===
        let sn_cache: HashMap<u64, SnLimit> = if gov_versions_to_fetch.is_empty()
        {
            HashMap::new()
        } else {
            let unique: std::collections::HashSet<u64> =
                gov_versions_to_fetch.into_iter().collect();
            let unique_vec: Vec<u64> = unique.into_iter().collect();
            let sns = self
                .get_sns(ctx, subject_id.clone(), unique_vec.clone())
                .await?;
            unique_vec.into_iter().zip(sns.into_iter()).collect()
        };

        // === FASE 3: Evaluación con cache ===
        for (creator, old_data, user_gv, schema_gv, is_direct) in
            old_owner_candidates
        {
            for gv in [user_gv, schema_gv].into_iter().flatten() {
                if let Some(sn_limit) = sn_cache.get(&gv) {
                    match sn_limit {
                        SnLimit::Sn(sn) => {
                            let candidate = *sn.min(&old_data.sn);
                            if better_sn.map_or(true, |bs| candidate > bs) {
                                better_sn = Some(candidate);
                                effective_owner = Some(creator.clone());
                            }
                        }
                        SnLimit::LastSn => {
                            if better_sn.map_or(true, |bs| old_data.sn > bs) {
                                better_sn = Some(old_data.sn);
                                effective_owner = Some(creator.clone());
                            }
                        }
                        SnLimit::NotSn => {}
                    }
                }
            }

            if is_direct {
                if better_sn.map_or(true, |bs| old_data.sn > bs) {
                    better_sn = Some(old_data.sn);
                    effective_owner = Some(creator.clone());
                }
            }
        }

        let sn_limit = if let Some(gov_version) = better_gov_version {
            match sn_cache.get(&gov_version).cloned().unwrap_or(SnLimit::NotSn) {
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

        Ok((sn_limit, effective_owner))
    }

    pub(crate) async fn search_witnesses(
        &self,
        ctx: &ActorContext<Self>,
        node: &PublicKey,
        data: &TransferData,
        namespace: String,
        schema_id: SchemaType,
        subject_id: DigestIdentifier,
        cached: &mut Option<(SnLimit, Option<PublicKey>)>,
    ) -> Result<SnLimit, ActorError> {
        match cached {
            Some((sn_limit, _)) => Ok(*sn_limit),
            None => {
                let (sn_limit, effective_owner) = self
                    .search_witnesses_with_owner(
                        ctx, node, data, namespace, schema_id, subject_id,
                    )
                    .await?;
                *cached = Some((sn_limit, effective_owner));
                Ok(sn_limit)
            }
        }
    }

}
