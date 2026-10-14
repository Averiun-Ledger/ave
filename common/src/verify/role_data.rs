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

/// Role sets for one event: phase sets plus the outer validator
/// attestation set.
#[derive(Debug, Clone)]
pub struct RolesAtVersion {
    pub evaluation: RoleDataRegister,
    pub approval: Option<RoleDataRegister>,
    pub compilation: Option<RoleDataRegister>,
    pub validators: RoleDataRegister,
}

/// Single-owner attestation set (governance genesis shape): the
/// owner alone with Majority, never the register.
pub fn lone_owner_roles(owner: &PublicKey) -> RoleDataRegister {
    RoleDataRegister {
        workers: HashSet::from([owner.clone()]),
        quorum: Quorum::Majority,
    }
}
