//! # Governance model.
//!
// Single source lives in ave-common (feature `verify`);
// this re-export keeps every core caller on identical behavior.
pub use ave_common::governance::{
    CreatorQuantity, CreatorWitness, Member, ProtocolTypes, Quorum, Role,
    RoleCreator,
};
pub use ave_common::verify::governance::model::{
    HashThisRole, PolicyGov, PolicySchema, RoleGovIssuer, RoleSchemaIssuer,
    RoleTypes, RolesGov, RolesSchema, RolesTrackerSchemas, Schema,
    WitnessesData,
};
