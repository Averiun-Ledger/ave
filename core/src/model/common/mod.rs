use borsh::{BorshDeserialize, BorshSerialize};
use rand::rng;
use rand::seq::IteratorRandom;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std:: fmt::Debug;

use ave_actors::{
    Actor, ActorContext, ActorError, ActorPath, ActorRef, Handler,
    PersistentActor, Store, StoreCommand, StoreResponse,
};

use ave_common::identity::{DigestIdentifier, PublicKey};

use crate::{
    node::nodekey::{NodeKey, NodeKeyMessage, NodeKeyResponse},
    request::manager::{RequestManager, RequestManagerMessage},
};
use std::ops::Bound::{Included, Unbounded};

pub mod contract;
pub mod node;
pub mod subject;


#[derive(Debug, Clone, Serialize, Deserialize, Default, BorshDeserialize, BorshSerialize,)]
pub struct CeilingMap<T> 
{
    inner: BTreeMap<u64, T>,
}

impl<T> CeilingMap<T> 
where T: Debug + Clone + Serialize + Default
{
    pub fn new() -> Self {
        CeilingMap { inner: BTreeMap::new() }
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
            out.push((key.clone(), value.clone()));
        }

        for (key, value) in self.inner.range((Included(&lower), Included(&upper))) {
            out.push((key.clone(), value.clone()));
        }

        out
    }

    pub fn get_prev_or_equal(&self, key: u64) -> Option<T> {
        self.inner
            .range((Unbounded, Included(&key)))
            .next_back().map(|x| x.1.clone())
    }
}

impl CeilingMap<HashSet<PublicKey>> {
    pub fn contains_from(&self, key: u64, target: &PublicKey) -> Option<u64> {
        for (k, v) in self.inner.range((Included(&key), Unbounded)) {
            if v.contains(&target) {
                return Some(k.clone());
            }
        }
        None
    }
}

impl CeilingMap<HashMap<PublicKey, BTreeSet<String>>> {
    pub fn contains_from(&self, key: u64, target: &PublicKey) -> Option<(u64, BTreeSet<String>)> {
        for (k, v) in self.inner.range((Included(&key), Unbounded)) {
            if let Some(povs) = v.get(&target) {
                return Some((k.clone(), povs.clone()));
            }
        }
        None
    }
}

pub async fn emit_fail<A>(
    ctx: &mut ActorContext<A>,
    error: ActorError,
) -> ActorError
where
    A: Actor + Handler<A>,
{
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
        .choose_multiple(&mut rng, quantity)
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
    request_id: &str,
    governance_id: DigestIdentifier,
) -> Result<(), ActorError>
where
    A: Actor + Handler<A>,
{
    let req_path = ActorPath::from(format!("/user/request/{}", request_id));
    let req_actor: Option<ActorRef<RequestManager>> =
        ctx.system().get_actor(&req_path).await;

    if let Some(req_actor) = req_actor {
        req_actor
            .tell(RequestManagerMessage::Reboot { governance_id })
            .await?
    } else {
        return Err(ActorError::NotFound(req_path));
    };

    Ok(())
}

pub async fn purge_storage<A>(
    ctx: &mut ActorContext<A>,
) -> Result<(), ActorError>
where
    A: PersistentActor,
    A::Event: BorshSerialize + BorshDeserialize,
{
    let store: Option<ActorRef<Store<A>>> = ctx.get_child("store").await;
    let response = if let Some(store) = store {
        store.ask(StoreCommand::Purge).await?
    } else {
        return Err(ActorError::NotFound(ActorPath::from(format!(
            "{}/store",
            ctx.path()
        ))));
    };

    if let StoreResponse::Error(e) = response {
        return Err(ActorError::Store(format!("Can not purge request: {}", e)));
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
    let path = ActorPath::from(&format!("{}/store", ctx.path()));
    let store: Option<ActorRef<Store<A>>> = ctx.get_child("store").await;
    let response = if let Some(store) = store {
        store.ask(StoreCommand::LastEvent).await?
    } else {
        return Err(ActorError::NotFound(path));
    };

    match response {
        StoreResponse::LastEvent(event) => Ok(event),
        StoreResponse::Error(e) => {
            Err(ActorError::FunctionalFail(e.to_string()))
        }
        _ => Err(ActorError::UnexpectedResponse(
            path,
            "StoreResponse::LastEvent".to_string(),
        )),
    }
}

pub async fn get_n_events<A>(
    ctx: &mut ActorContext<A>,    
    last_sn: u64,
    n: u64,
) -> Result<Vec<A::Event>, ActorError>
where
    A: PersistentActor,
    A::Event: BorshSerialize + BorshDeserialize,
{
    let store: Option<ActorRef<Store<A>>> = ctx.get_child("store").await;
    let response = if let Some(store) = store {
        store
            .ask(StoreCommand::GetEvents {
                from: last_sn,
                to: last_sn + n,
            })
            .await?
    } else {
        return Err(ActorError::NotFound(ActorPath::from(format!(
            "{}/store",
            ctx.path()
        ))));
    };

    match response {
        StoreResponse::Events(events) => Ok(events),
        _ => Err(ActorError::UnexpectedResponse(
            ActorPath::from(format!("{}/store", ctx.path())),
            "StoreResponse::Events".to_owned(),
        )),
    }
}

pub async fn get_node_key<A>(
    ctx: &mut ActorContext<A>,
) -> Result<PublicKey, ActorError>
where
    A: Actor + Handler<A>,
{
    // Node path.
    let node_key_path = ActorPath::from("/user/node/key");
    // Node actor.
    let node_key_actor: Option<ActorRef<NodeKey>> =
        ctx.system().get_actor(&node_key_path).await;

    // We obtain the actor node
    let response = if let Some(node_key_actor) = node_key_actor {
        node_key_actor.ask(NodeKeyMessage::GetPublicKey).await?
    } else {
        return Err(ActorError::NotFound(node_key_path));
    };

    // We handle the possible responses of node
    match response {
        NodeKeyResponse::PublicKey(key) => Ok(key),
    }
}
