//! Governance state shared by the node and the off-chain
//! verification tool. Actors, messages and registers stay in core.

pub mod data;
pub mod error;
pub mod model;
pub mod roles_updates;

pub use data::{GovernanceData, MemberName};
pub use error::GovernanceError;
pub use crate::governance::{
    CreatorQuantity, CreatorWitness, Member, ProtocolTypes, Quorum, Role,
    RoleCreator,
};
pub use model::{
    HashThisRole, PolicyGov, PolicySchema, RoleGovIssuer, RoleSchemaIssuer,
    RoleTypes, RolesGov, RolesSchema, RolesTrackerSchemas, Schema,
    WitnessesData,
};
pub use roles_updates::{RolesUpdateConfirm, RolesUpdateRemove};
