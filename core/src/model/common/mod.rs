use ave_common::SchemaType;
use borsh::{BorshDeserialize, BorshSerialize};
use rand::rng;
use rand::seq::IteratorRandom;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
use std::fmt::Debug;
use std::slice;
use tracing::error;

use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ActorRef, Handler,
    PersistentActor, Store, StoreCommand, StoreResponse,
};

use ave_common::identity::{DigestIdentifier, PublicKey};

use crate::governance::model::Quorum;
use crate::governance::role_register::{
    RoleDataRegister, RoleRegister, RoleRegisterMessage, RoleRegisterResponse,
    SearchRole,
};
use crate::governance::subject_register::{
    SubjectRegister, SubjectRegisterMessage,
};
use crate::governance::witnesses_register::{
    WitnessesRegister, WitnessesRegisterMessage, WitnessesRegisterResponse,
};
use crate::request::manager::{
    RebootType, RequestManager, RequestManagerMessage,
};
use crate::request::tracking::{RequestTracking, RequestTrackingMessage};
use std::ops::Bound::{Included, Unbounded};

pub mod contract;
pub mod node;
pub mod subject;

pub fn check_quorum_signers(
    signers: &HashSet<PublicKey>,
    quorum: &Quorum,
    workers: &HashSet<PublicKey>,
) -> bool {
    signers.is_subset(workers)
        && quorum.check_quorum(workers.len() as u32, signers.len() as u32)
}

pub async fn get_actual_roles_register<A>(
    ctx: &mut ActorContext<A>,
    governance_id: &DigestIdentifier,
    evaluation: SearchRole,
    approval: bool,
    version: u64,
) -> Result<(RoleDataRegister, Option<RoleDataRegister>), ActorError>
where
    A: Actor + Handler<A>,
{
    let path =
        ActorPath::from(format!("/user/node/{}/role_register", governance_id));
    let actor = ctx.system().get_actor::<RoleRegister>(&path).await?;

    let response = actor
        .ask(RoleRegisterMessage::SearchActualRoles {
            version,
            evaluation,
            approval,
        })
        .await?;

    match response {
        RoleRegisterResponse::ActualRoles {
            evaluation,
            approval,
        } => Ok((evaluation, approval)),
        _ => Err(ActorError::UnexpectedResponse {
            path,
            expected: "RolesRegisterResponse::ActualRoles".to_string(),
        }),
    }
}

pub async fn get_validation_roles_register<A>(
    ctx: &mut ActorContext<A>,
    governance_id: &DigestIdentifier,
    search: SearchRole,
    version: u64,
) -> Result<RoleDataRegister, ActorError>
where
    A: Actor + Handler<A>,
{
    let path =
        ActorPath::from(format!("/user/node/{}/role_register", governance_id));
    let actor = ctx.system().get_actor::<RoleRegister>(&path).await?;

    let response = actor
        .ask(RoleRegisterMessage::SearchValidators { search, version })
        .await?;

    match response {
        RoleRegisterResponse::Validation(validation) => Ok(validation),
        _ => Err(ActorError::UnexpectedResponse {
            path,
            expected: "RolesRegisterResponse::Validation".to_string(),
        }),
    }
}

pub async fn check_subject_creation<A>(
    ctx: &mut ActorContext<A>,
    governance_id: &DigestIdentifier,
    creator: PublicKey,
    gov_version: u64,
    namespace: String,
    schema_id: SchemaType,
) -> Result<(), ActorError>
where
    A: Actor + Handler<A>,
{
    let actor_path = ActorPath::from(format!(
        "/user/node/{}/subject_register",
        governance_id
    ));

    let actor: ActorRef<SubjectRegister> =
        ctx.system().get_actor(&actor_path).await.map_err(|_| {
            ActorError::Functional {
                description: "Governance has not been found".to_string(),
            }
        })?;

    let _response = actor
        .ask(SubjectRegisterMessage::Check {
            creator,
            gov_version,
            namespace,
            schema_id,
        })
        .await?;

    Ok(())
}

pub async fn check_witness_access<A>(
    ctx: &mut ActorContext<A>,
    governance_id: &DigestIdentifier,
    subject_id: &DigestIdentifier,
    node: PublicKey,
    namespace: String,
    schema_id: SchemaType,
) -> Result<Option<u64>, ActorError>
where
    A: Actor + Handler<A>,
{
    let actor_path = ActorPath::from(format!(
        "/user/node/{}/witnesses_register",
        governance_id
    ));

    let actor: ActorRef<WitnessesRegister> =
        ctx.system().get_actor(&actor_path).await?;

    let response = actor
        .ask(WitnessesRegisterMessage::Access {
            subject_id: subject_id.to_owned(),
            node,
            namespace,
            schema_id,
        })
        .await?;

    match response {
        WitnessesRegisterResponse::Access { sn } => Ok(sn),
        _ => Err(ActorError::UnexpectedResponse {
            path: actor_path,
            expected: "WitnessesRegisterResponse::Access { sn }".to_string(),
        }),
    }
}

#[derive(
    Clone,
    Copy,
    Debug,
    PartialEq,
    Eq,
    Serialize,
    Deserialize,
    BorshDeserialize,
    BorshSerialize,
)]
pub struct Interval {
    pub lo: u64,
    pub hi: u64, // inclusivo
}

impl Interval {
    pub const fn new(a: u64, b: u64) -> Self {
        if a <= b {
            Self { lo: a, hi: b }
        } else {
            Self { lo: b, hi: a }
        }
    }

    pub const fn contains(&self, value: u64) -> bool {
        value >= self.lo && value <= self.hi
    }
}

#[derive(
    Default,
    Debug,
    Clone,
    Serialize,
    Deserialize,
    BorshDeserialize,
    BorshSerialize,
)]
pub struct IntervalSet {
    // Invariante: ordenados por lo, disjuntos y ya "mergeados" (hi < siguiente.lo)
    intervals: Vec<Interval>,
}

impl IntervalSet {
    pub const fn new() -> Self {
        Self {
            intervals: Vec::new(),
        }
    }

    // Devuelve true si `x` está dentro de algún intervalo (extremos inclusivos).
    pub fn contains(&self, x: u64) -> bool {
        if self.intervals.is_empty() {
            return false;
        }

        match self.intervals.binary_search_by(|iv| iv.lo.cmp(&x)) {
            Ok(_) => true, // existe un intervalo con lo == x => contenido seguro
            Err(pos) => {
                if pos == 0 {
                    return false; // x es menor que el lo del primer intervalo
                }
                let iv = self.intervals[pos - 1];
                iv.hi >= x
            }
        }
    }

    // Inserta un intervalo inclusivo y fusiona solapes (incluye tocar por extremo: [1,4] + [4,7] => [1,7]).
    pub fn insert(&mut self, mut iv: Interval) {
        // Posición donde iv.lo podría insertarse manteniendo orden
        let mut i = match self.intervals.binary_search_by(|x| x.lo.cmp(&iv.lo))
        {
            Ok(pos) | Err(pos) => pos,
        };

        // Si puede fusionar con el anterior, retrocede uno
        if i > 0 && self.intervals[i - 1].hi >= iv.lo {
            i -= 1;
        }

        // Fusiona hacia delante todo lo que solape/toque (condición inclusiva: next.lo <= iv.hi)
        while i < self.intervals.len() && self.intervals[i].lo <= iv.hi {
            let cur = self.intervals[i];
            iv.lo = iv.lo.min(cur.lo);
            iv.hi = iv.hi.max(cur.hi);
            self.intervals.remove(i); // O(n) pero muy compacto en memoria
        }

        self.intervals.insert(i, iv);
    }

    // Consulta: devuelve el máximo valor cubierto dentro de [ql, qh], o None.
    pub fn max_covered_in(&self, ql: u64, qh: u64) -> Option<u64> {
        let (ql, qh) = if ql <= qh { (ql, qh) } else { (qh, ql) };
        if self.intervals.is_empty() {
            return None;
        }

        // Queremos el intervalo más a la derecha con lo <= qh
        let idx = match self.intervals.binary_search_by(|iv| iv.lo.cmp(&qh)) {
            Ok(pos) => pos, // lo == qh
            Err(pos) => {
                if pos == 0 {
                    return None;
                }
                pos - 1
            }
        };

        let iv = self.intervals[idx];
        // Hay intersección si iv.hi >= ql (ya sabemos iv.lo <= qh)
        if iv.hi >= ql {
            Some(iv.hi.min(qh))
        } else {
            None
        }
    }

    pub fn as_slice(&self) -> &[Interval] {
        &self.intervals
    }

    pub fn iter(&self) -> slice::Iter<'_, Interval> {
        self.intervals.iter()
    }

    pub fn iter_mut(&mut self) -> slice::IterMut<'_, Interval> {
        self.intervals.iter_mut()
    }
}

impl<'a> IntoIterator for &'a IntervalSet {
    type Item = &'a Interval;
    type IntoIter = slice::Iter<'a, Interval>;

    fn into_iter(self) -> Self::IntoIter {
        self.intervals.iter()
    }
}

impl<'a> IntoIterator for &'a mut IntervalSet {
    type Item = &'a mut Interval;
    type IntoIter = slice::IterMut<'a, Interval>;

    fn into_iter(self) -> Self::IntoIter {
        self.intervals.iter_mut()
    }
}

impl IntoIterator for IntervalSet {
    type Item = Interval;
    type IntoIter = std::vec::IntoIter<Interval>;

    fn into_iter(self) -> Self::IntoIter {
        self.intervals.into_iter()
    }
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
pub struct CeilingMap<T> {
    inner: BTreeMap<u64, T>,
}

impl<T> CeilingMap<T>
where
    T: Debug + Clone + Serialize,
{
    pub const fn new() -> Self {
        Self {
            inner: BTreeMap::new(),
        }
    }

    pub fn last(&self) -> Option<(&u64, &T)> {
        self.inner.last_key_value()
    }

    pub fn insert(&mut self, key: u64, value: T) {
        self.inner.insert(key, value);
    }

    pub fn range_with_predecessor(
        &self,
        lower: u64,
        upper: u64,
    ) -> Vec<(u64, T)> {
        let mut out: Vec<(u64, T)> = Vec::new();

        if let Some((key, value)) = self.inner.range(..lower).next_back() {
            out.push((*key, value.clone()));
        }

        for (key, value) in
            self.inner.range((Included(&lower), Included(&upper)))
        {
            out.push((*key, value.clone()));
        }

        out
    }

    pub fn get_prev_or_equal(&self, key: u64) -> Option<T> {
        self.inner
            .range((Unbounded, Included(&key)))
            .next_back()
            .map(|x| x.1.clone())
    }
}

pub async fn send_to_tracking<A>(
    ctx: &mut ActorContext<A>,
    message: RequestTrackingMessage,
) -> Result<(), ActorError>
where
    A: Actor + Handler<A>,
{
    let tracking_path = ActorPath::from("/user/request/tracking");
    let tracking_actor = ctx
        .system()
        .get_actor::<RequestTracking>(&tracking_path)
        .await?;
    tracking_actor.tell(message).await
}

pub async fn emit_fail<A>(
    ctx: &mut ActorContext<A>,
    error: ActorError,
) -> ActorError
where
    A: Actor + Handler<A>,
{
    error!("Falling, error: {}, actor: {}", error, ctx.path());
    if let Err(_e) = ctx.emit_fail(error.clone()).await {
        ctx.system().stop_system();
    };
    error
}

pub fn take_random_signers(
    signers: HashSet<PublicKey>,
    quantity: usize,
) -> (HashSet<PublicKey>, HashSet<PublicKey>) {
    if quantity == signers.len() {
        return (signers, HashSet::new());
    }

    let mut rng = rng();

    let random_signers: HashSet<PublicKey> = signers
        .iter()
        .sample(&mut rng, quantity)
        .into_iter()
        .cloned()
        .collect();

    let signers = signers
        .difference(&random_signers)
        .cloned()
        .collect::<HashSet<PublicKey>>();

    (random_signers, signers)
}

pub async fn send_reboot_to_req<A>(
    ctx: &mut ActorContext<A>,
    request_id: DigestIdentifier,
    governance_id: DigestIdentifier,
    reboot_type: RebootType,
) -> Result<(), ActorError>
where
    A: Actor + Handler<A>,
{
    let req_actor = ctx.get_parent::<RequestManager>().await?;
    req_actor
        .tell(RequestManagerMessage::Reboot {
            governance_id,
            reboot_type,
            request_id,
        })
        .await
}

pub async fn abort_req<A>(
    ctx: &mut ActorContext<A>,
    request_id: DigestIdentifier,
    who: PublicKey,
    reason: String,
    sn: u64,
) -> Result<(), ActorError>
where
    A: Actor + Handler<A>,
{
    let req_actor = ctx.get_parent::<RequestManager>().await?;
    req_actor
        .tell(RequestManagerMessage::Abort {
            request_id,
            who,
            reason,
            sn,
        })
        .await
}

pub async fn purge_storage<A>(
    ctx: &mut ActorContext<A>,
) -> Result<(), ActorError>
where
    A: PersistentActor,
    A::Event: BorshSerialize + BorshDeserialize,
{
    let store = ctx.get_child::<Store<A>>("store").await?;
    let response = store.ask(StoreCommand::Purge).await?;

    if let StoreResponse::Error(e) = response {
        return Err(ActorError::StoreOperation {
            operation: "purge".to_string(),
            reason: e.to_string(),
        });
    };

    Ok(())
}

pub async fn get_last_event<A>(
    ctx: &mut ActorContext<A>,
) -> Result<Option<A::Event>, ActorError>
where
    A: PersistentActor,
    A::Event: BorshSerialize + BorshDeserialize,
{
    let store = ctx.get_child::<Store<A>>("store").await?;
    let response = store.ask(StoreCommand::LastEvent).await?;

    match response {
        StoreResponse::LastEvent(event) => Ok(event),
        StoreResponse::Error(e) => Err(ActorError::FunctionalCritical {
            description: e.to_string(),
        }),
        _ => Err(ActorError::UnexpectedResponse {
            path: ActorPath::from(format!("{}/store", ctx.path())),
            expected: "StoreResponse::LastEvent".to_owned(),
        }),
    }
}

pub async fn get_n_events<A>(
    ctx: &mut ActorContext<A>,
    last_sn: u64,
    quantity: u64,
) -> Result<Vec<A::Event>, ActorError>
where
    A: PersistentActor,
    A::Event: BorshSerialize + BorshDeserialize,
{
    let store = ctx.get_child::<Store<A>>("store").await?;
    let response = store
        .ask(StoreCommand::GetEvents {
            from: last_sn,
            to: last_sn + quantity,
        })
        .await?;

    match response {
        StoreResponse::Events(events) => Ok(events),
        StoreResponse::Error(e) => Err(ActorError::FunctionalCritical {
            description: e.to_string(),
        }),
        _ => Err(ActorError::UnexpectedResponse {
            path: ActorPath::from(format!("{}/store", ctx.path())),
            expected: "StoreResponse::Events".to_owned(),
        }),
    }
}
