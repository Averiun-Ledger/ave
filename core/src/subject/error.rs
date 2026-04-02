use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum SubjectError {
    // Subject state errors
    #[error("subject is no longer active")]
    SubjectInactive,

    #[error("subject schema id is invalid")]
    InvalidSchemaId,

    // Signature and verification errors
    #[error("signature verification failed: {context}")]
    SignatureVerificationFailed { context: String },

    #[error("incorrect signer: expected {expected}, got {actual}")]
    IncorrectSigner { expected: String, actual: String },

    #[error("validation request signature is invalid")]
    InvalidValidationRequestSignature,

    #[error("validator signature could not be verified")]
    InvalidValidatorSignature,

    // Event and ledger errors
    #[error(
        "event is not the next one to be applied: expected sn {expected}, got {actual}"
    )]
    InvalidSequenceNumber { expected: u64, actual: u64 },

    #[error("previous ledger event hash does not match")]
    PreviousHashMismatch,

    #[error("subject id mismatch: expected {expected}, got {actual}")]
    SubjectIdMismatch { expected: String, actual: String },

    #[error("ledger event hash mismatch: expected {expected}, got {actual}")]
    LedgerHashMismatch { expected: String, actual: String },

    #[error("event type does not match protocols")]
    EventProtocolMismatch,

    #[error("event should be {expected} but got {actual}")]
    UnexpectedEventType { expected: String, actual: String },

    // Protocol-specific errors
    #[error("fact event received but should be confirm or reject event")]
    UnexpectedFactEvent,

    #[error("transfer event received but should be confirm or reject event")]
    UnexpectedTransferEvent,

    #[error("EOL event received but should be confirm or reject event")]
    UnexpectedEOLEvent,

    #[error("confirm event received but new_owner is None")]
    ConfirmWithoutNewOwner,

    #[error("reject event received but new_owner is None")]
    RejectWithoutNewOwner,

    // Validation errors
    #[error("quorum is not valid")]
    InvalidQuorum,

    #[error("validation request hash does not match")]
    ValidationRequestHashMismatch,

    #[error("validators and quorum could not be obtained: {details}")]
    ValidatorsRetrievalFailed { details: String },

    // Metadata errors
    #[error("event metadata does not match subject metadata")]
    MetadataMismatch,

    #[error("validation metadata must be of type Metadata in creation event")]
    InvalidValidationMetadata,

    #[error(
        "validation metadata must be of type ModifiedMetadataHash in non-creation event"
    )]
    InvalidNonCreationValidationMetadata,

    #[error("in creation event, sequence number must be 0")]
    InvalidCreationSequenceNumber,

    #[error("previous ledger event hash must be empty in creation event")]
    NonEmptyPreviousHashInCreation,

    // Patch and state errors
    #[error("failed to apply patch: {details}")]
    PatchApplicationFailed { details: String },

    #[error("failed to convert ValueWrapper into Patch: {details}")]
    PatchConversionFailed { details: String },

    #[error("evaluation was satisfactory but there was no approval")]
    MissingApprovalAfterEvaluation,

    #[error("evaluation was not satisfactory but there is approval")]
    UnexpectedApprovalAfterFailedEvaluation,

    // Governance-specific errors
    #[error("failed to convert properties into GovernanceData: {details}")]
    GovernanceDataConversionFailed { details: String },

    #[error(
        "schema_id is Governance, but cannot convert properties: {details}"
    )]
    GovernancePropertiesConversionFailed { details: String },

    #[error("{what} '{who}' is not a member")]
    NotAMember { what: String, who: String },

    #[error("schema '{schema_id}' has no policies")]
    SchemaNoPolicies { schema_id: String },

    #[error("schema '{schema_id}' is not a schema")]
    InvalidSchema { schema_id: String },

    // Tracker-specific errors
    #[error("number of subjects that can be created has not been found")]
    MaxSubjectCreationNotFound,

    #[error("protocols data is for Governance but this is a Tracker")]
    GovernanceProtocolsInTracker,

    #[error("protocols data is for Tracker but this is a Governance")]
    TrackerProtocolsInGovernance,

    #[error("service subject cannot accept tracker opaque events")]
    ServiceCannotAcceptTrackerOpaque,

    #[error("governance fact event cannot contain viewpoints")]
    GovernanceFactViewpointsNotAllowed,

    // Hash errors
    #[error("failed to create hash: {details}")]
    HashCreationFailed { details: String },

    #[error("validation request hash could not be obtained: {details}")]
    ValidationRequestHashFailed { details: String },

    #[error("modified metadata hash could not be obtained: {details}")]
    ModifiedMetadataHashFailed { details: String },

    #[error(
        "modified metadata without properties hash mismatch: expected {expected}, got {actual}"
    )]
    ModifiedMetadataWithoutPropertiesHashMismatch {
        expected: String,
        actual: String,
    },

    #[error("properties hash mismatch: expected {expected}, got {actual}")]
    PropertiesHashMismatch { expected: String, actual: String },

    #[error("event request hash mismatch: expected {expected}, got {actual}")]
    EventRequestHashMismatch { expected: String, actual: String },

    #[error("viewpoints hash mismatch: expected {expected}, got {actual}")]
    ViewpointsHashMismatch { expected: String, actual: String },

    // Actor and system errors
    #[error("actor not found: {path}")]
    ActorNotFound { path: String },

    #[error("unexpected response from {path}: expected {expected}")]
    UnexpectedResponse { path: String, expected: String },

    #[error("helper not found: {helper}")]
    HelperNotFound { helper: String },

    #[error("cannot obtain {what}")]
    CannotObtain { what: String },

    // General errors
    #[error("{0}")]
    Generic(String),
}

impl From<String> for SubjectError {
    fn from(s: String) -> Self {
        Self::Generic(s)
    }
}

impl From<&str> for SubjectError {
    fn from(s: &str) -> Self {
        Self::Generic(s.to_string())
    }
}
