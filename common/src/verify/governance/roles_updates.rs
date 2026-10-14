//! Governance role-update data shared by the node and the
//! off-chain verification tool. Actor messages stay in core.

use std::collections::{HashMap, HashSet};

use crate::{Namespace, SchemaType, identity::PublicKey};

pub struct RolesUpdateConfirm {
    pub new_approver: Option<PublicKey>,
    pub remove_approver: PublicKey,

    pub new_compiler: Option<PublicKey>,
    pub remove_compiler: PublicKey,

    pub new_evaluator: Option<PublicKey>,
    pub remove_evaluators: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,

    pub new_validator: Option<PublicKey>,
    pub remove_validators: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,

    pub remove_creator: HashSet<(SchemaType, String, PublicKey)>,
    pub remove_witnesses: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
}

pub struct RolesUpdateRemove {
    pub witnesses: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
    pub creator: HashSet<(SchemaType, String, PublicKey)>,
    pub approvers: Vec<PublicKey>,
    pub compilers: Vec<PublicKey>,
    pub evaluators: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
    pub validators: HashMap<(SchemaType, PublicKey), Vec<Namespace>>,
}
