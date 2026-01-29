use thiserror::Error;

#[derive(Debug, Error, Clone)]
pub enum IntermediaryError {
    #[error("failed to serialize message: {details}")]
    SerializationFailed { details: String },

    #[error("failed to send message to network: {details}")]
    NetworkSendFailed { details: String },

    #[error("failed to convert sender bytes to public key: {details}")]
    InvalidPublicKey { details: String },

    #[error("failed to deserialize message: {details}")]
    DeserializationFailed { details: String },

    #[error("failed to get schema_id from validation request")]
    InvalidSchemaId,

    #[error("actor not found: {path}")]
    ActorNotFound { path: String },

    #[error("failed to send message to actor '{path}': {details}")]
    SendMessageFailed { path: String, details: String },

    #[error("invalid Ed25519 public key, cannot convert to PeerId: {details}")]
    PeerIdConversionFailed { details: String },
}
