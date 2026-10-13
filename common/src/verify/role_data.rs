//! Role-set data shared by the node and the off-chain
//! verification tool. Actor messages and role logic stay in core.

use std::collections::HashSet;

use crate::{governance::Quorum, identity::PublicKey};

use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};

#[derive(
    Debug, Clone, Serialize, Deserialize, BorshDeserialize, BorshSerialize,
)]
pub struct RoleDataRegister {
    pub workers: HashSet<PublicKey>,
    pub quorum: Quorum,
}
