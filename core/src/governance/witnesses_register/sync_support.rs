use std::collections::{BTreeMap, HashSet};

use crate::governance::subject_register::{
    SubjectRegister, SubjectRegisterMessage, SubjectRegisterResponse,
};
use ave_actors::{ActorContext, ActorError, ActorPath};
use ave_common::identity::{DigestIdentifier, PublicKey};
use ave_common::{Namespace, SchemaType};

use super::{CurrentWitnessSubject, WitnessesRegister};

impl WitnessesRegister {
    pub(crate) async fn get_subjects_for_owner_schema_batch(
        &self,
        ctx: &ActorContext<Self>,
        queries: Vec<(PublicKey, SchemaType, String)>,
    ) -> Result<Vec<Vec<DigestIdentifier>>, ActorError> {
        let path = ActorPath::from(format!(
            "/user/node/subject_manager/{}/subject_register",
            ctx.path().parent().key()
        ));
        let actor = ctx.system().get_actor::<SubjectRegister>(&path).await?;
        let response = actor
            .ask(SubjectRegisterMessage::GetSubjectsByOwnerSchemaBatch {
                queries,
            })
            .await?;

        match response {
            SubjectRegisterResponse::SubjectsBatch(results) => Ok(results),
            _ => Err(ActorError::UnexpectedResponse {
                path,
                expected: "SubjectRegisterResponse::SubjectsBatch".to_owned(),
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
        let mut relevant_creators: HashSet<(PublicKey, String, SchemaType)> =
            HashSet::new();

        // Witnesses explícitos: O(1) lookup via índice invertido.
        if let Some(explicit_creators) = self.node_creator_index.get(node) {
            relevant_creators.extend(explicit_creators.iter().cloned());
        }

        // Witnesses de schema: iterar solo sobre creators con Witnesses activo.
        for ((creator, namespace, schema_id), entry) in
            &self.creator_witnesses
        {
            let key =
                (creator.clone(), namespace.clone(), schema_id.clone());
            if relevant_creators.contains(&key) {
                continue;
            }
            if entry.intervals
                .get(&super::WitnessesType::Witnesses)
                .is_some_and(|(_, current_lo)| current_lo.is_some())
                && self.has_active_schema_witness(
                    node,
                    schema_id,
                    &Namespace::from(namespace.clone()),
                )
            {
                relevant_creators.insert(key);
            }
        }

        // Batch ask a SubjectRegister para todos los creators relevantes.
        let queries: Vec<(PublicKey, SchemaType, String)> = relevant_creators
            .into_iter()
            .map(|(creator, namespace, schema_id)| {
                (creator, schema_id, namespace)
            })
            .collect();

        let mut subjects = BTreeMap::new();

        if !queries.is_empty() {
            let batch_results = self
                .get_subjects_for_owner_schema_batch(ctx, queries)
                .await?;

            for subject_ids in batch_results {
                for subject_id in subject_ids {
                    if let Some(data) = self.subjects.get(&subject_id) {
                        subjects.insert(subject_id, data.sn);
                    }
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
            items.pop();
            items.last().map(|item| item.subject_id.clone())
        } else {
            None
        };

        Ok((items, next_cursor))
    }
}
