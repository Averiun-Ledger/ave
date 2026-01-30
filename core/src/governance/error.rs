use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum GovernanceError {
    // Schema errors
    #[error("schema '{schema_id}' does not exist")]
    SchemaDoesNotExist { schema_id: String },

    // Member errors
    #[error("creator must be a governance member")]
    CreatorNotMember,

    #[error("member '{name}' not found")]
    MemberNotFound { name: String },

    // Quorum errors
    #[error("no quorum found for role {role} and schema {schema_id}")]
    QuorumNotFound { role: String, schema_id: String },

    // Witnesses errors
    #[error("attempting to obtain witnesses for a schema that does not exist")]
    WitnessesForNonexistentSchema,

    // Conversion errors
    #[error("cannot convert value into GovernanceData: {details}")]
    ConversionFailed { details: String },

    // General error
    #[error("{0}")]
    Generic(String),
}

impl From<String> for GovernanceError {
    fn from(s: String) -> Self {
        GovernanceError::Generic(s)
    }
}

impl From<&str> for GovernanceError {
    fn from(s: &str) -> Self {
        GovernanceError::Generic(s.to_string())
    }
}
