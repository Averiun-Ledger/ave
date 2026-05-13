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
    ActualSearch,
};

impl WitnessesRegister {
    pub(crate) async fn get_subjects_for_owner_schema(
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

    pub(crate) async fn list_current_witness_subjects(
        &self,
        ctx: &ActorContext<Self>,
        node: &PublicKey,
        governance_version: u64,
        after_subject_id: Option<DigestIdentifier>,
        limit: usize,
    ) -> Result<
        (Vec<CurrentWitnessSubject>, Option<DigestIdentifier>),
        ActorError,
    > {
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
                    ctx, creator, schema_id, namespace,
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
